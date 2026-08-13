//! LAN worker loop for durable repository-analysis tasks.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use futures::StreamExt as _;
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::{
    coordinator::{
        ArtifactRefV1, JobId, PermitDecision, ProviderKeyV1, ProviderOutcomeClassV1,
        RateLimitObservationV1, RepositoryScopeV1, Sha256Digest, TaskUsageV1,
    },
    coordinator_api::{
        AcquireProviderPermitRequestV1, AcquireProviderPermitResponseV1, CacheLookupRequestV1,
        CacheLookupResponseV1, CompleteTaskRequestV1, FailTaskRequestV1,
        FinishProviderPermitRequestV1, HeartbeatRequestV1, LeaseRequestV1, LeaseResponseV1,
    },
    github::{GitHubApiError, GitHubClient, RepositoryScope, preferred_token_from_environment},
    pki,
    repository_analyzer::{
        RepositoryAnalyzerBounds, analysis_reuse_fingerprint, analyze_repository_snapshot,
        exact_target_version, resolve_repository_snapshot, reuse_cached_evidence,
    },
    secure_cache::sha256_hex,
};

const RESPONSE_LIMIT: u64 = 16 * 1024 * 1024;
const ERROR_BODY_LIMIT: u64 = 16 * 1024;
const MAX_TASK_ATTEMPTS: u32 = 3;
const RETRY_DELAY_SECONDS: i64 = 30;
const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.crate-dependent-repos.evidence.v1+json";

#[derive(Clone, Debug)]
pub struct AgentRunConfig {
    pub coordinator: Url,
    pub ca_certificate: PathBuf,
    pub client_certificate: PathBuf,
    pub client_private_key: PathBuf,
    pub agent_id: String,
    pub job_id: JobId,
    pub lease_seconds: u64,
    pub idle_poll: Duration,
    pub once: bool,
    pub artifact_directory: PathBuf,
    pub max_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentLoopControl {
    Continue,
    Poll,
    Stop,
}

#[derive(Clone, Debug)]
struct ProviderFeedback {
    outcome: ProviderOutcomeClassV1,
    observation: RateLimitObservationV1,
}

impl ProviderFeedback {
    fn success() -> Self {
        Self {
            outcome: ProviderOutcomeClassV1::Success,
            observation: RateLimitObservationV1::default(),
        }
    }
}

/// Lease and execute tasks until the job terminates or `once` completes one
/// lease attempt. All HTTP traffic is mutually authenticated.
pub async fn run_agent(config: AgentRunConfig) -> Result<()> {
    validate_config(&config)?;
    let client = pki::authenticated_client(
        &config.ca_certificate,
        &config.client_certificate,
        &config.client_private_key,
    )?;
    let job: crate::coordinator::ScanJobV1 = get_json(
        &client,
        endpoint(&config.coordinator, &format!("v1/jobs/{}", config.job_id.0))?,
        &config.agent_id,
    )
    .await?;
    let target_version = exact_target_version(&job.spec.target.version_spec)?;
    let repository_scope = match job.spec.repository_scope {
        RepositoryScopeV1::PublicOnly => RepositoryScope::PublicOnly,
        RepositoryScopeV1::AllVisible => RepositoryScope::AllVisible,
    };
    let token = preferred_token_from_environment();
    if repository_scope == RepositoryScope::AllVisible && token.is_none() {
        bail!("all-visible worker tasks require GITHUB_APP_TOKEN, GITHUB_TOKEN, or GH_TOKEN");
    }
    let github = GitHubClient::new(token)?;
    let provider_key = ProviderKeyV1::github_repository_analysis(
        job.spec.repository_scope,
        job.spec.credential_profile_id.as_deref(),
    );
    loop {
        let admission: AcquireProviderPermitResponseV1 = post_json(
            &client,
            endpoint(&config.coordinator, "v1/providers/permits/acquire")?,
            &config.agent_id,
            &AcquireProviderPermitRequestV1 {
                key: provider_key.clone(),
                permit_id: None,
            },
        )
        .await?;
        let permit = match admission.decision {
            PermitDecision::Granted(permit) => permit,
            PermitDecision::WaitUntil(until) => {
                tokio::time::sleep(provider_wait_duration(until)).await;
                continue;
            }
            PermitDecision::CapacityExhausted | PermitDecision::HalfOpenProbeInFlight => {
                tokio::time::sleep(config.idle_poll).await;
                continue;
            }
        };

        let mut feedback = ProviderFeedback::success();
        let attempt: Result<AgentLoopControl> = async {
            let leased: LeaseResponseV1 = post_json(
                &client,
                endpoint(
                    &config.coordinator,
                    &format!("v1/jobs/{}/lease", config.job_id.0),
                )?,
                &config.agent_id,
                &LeaseRequestV1 {
                    lease_seconds: Some(config.lease_seconds),
                },
            )
            .await?;

            let Some(task) = leased.task else {
                let current: crate::coordinator::ScanJobV1 = get_json(
                    &client,
                    endpoint(&config.coordinator, &format!("v1/jobs/{}", config.job_id.0))?,
                    &config.agent_id,
                )
                .await?;
                return Ok(if current.state.is_terminal() || config.once {
                    AgentLoopControl::Stop
                } else {
                    AgentLoopControl::Poll
                });
            };
            let lease = task
                .lease
                .as_ref()
                .context("coordinator returned a leased task without lease metadata")?;
            let lease_id = lease.lease_id.clone();
            tracing::info!(
                task_id = %task.id.0,
                attempt = task.attempt,
                repository_scope = repository_scope.as_str(),
                "analyzing repository task"
            );

            let usage_before = github.usage();
            let analyzer_bounds = RepositoryAnalyzerBounds {
                file_bytes: config.max_file_bytes,
                concurrent_requests: 4,
                ..RepositoryAnalyzerBounds::default()
            };
            let analysis = async {
                let snapshot =
                    resolve_repository_snapshot(&github, &task.repository_id, repository_scope)
                        .await?;
                let fingerprint = analysis_reuse_fingerprint(
                    &snapshot,
                    &job.spec.target.crate_name,
                    &target_version,
                    analyzer_bounds,
                )?;
                let cached: CacheLookupResponseV1 = post_json(
                    &client,
                    endpoint(
                        &config.coordinator,
                        &format!("v1/tasks/{}/cache/lookup", task.id.0),
                    )?,
                    &config.agent_id,
                    &CacheLookupRequestV1 {
                        lease_id: lease_id.clone(),
                        fingerprint: fingerprint.clone(),
                    },
                )
                .await?;
                let (evidence, cache_reused) = match cached.evidence {
                    Some(evidence) => (
                        reuse_cached_evidence(
                            evidence,
                            &snapshot,
                            &job.spec.target.crate_name,
                            &target_version,
                        )?,
                        true,
                    ),
                    None => (
                        analyze_repository_snapshot(
                            &github,
                            &snapshot,
                            &job.spec.target.crate_name,
                            &target_version,
                            analyzer_bounds,
                        )
                        .await?,
                        false,
                    ),
                };
                Ok::<_, anyhow::Error>((evidence, fingerprint, cache_reused))
            };
            let heartbeat = heartbeat_until_failure(&client, &config, &task.id.0, &lease_id);
            let result = tokio::select! {
                result = analysis => {
                    if let Err(error) = &result {
                        feedback = classify_github_error(error);
                    }
                    result
                },
                error = heartbeat => Err(error),
            };
            let usage_after = github.usage();
            let usage = TaskUsageV1 {
                provider_requests: usage_after.requests.saturating_sub(usage_before.requests),
                downloaded_bytes: usage_after
                    .downloaded_bytes
                    .saturating_sub(usage_before.downloaded_bytes),
            };

            match result {
                Ok((evidence, fingerprint, cache_reused)) => {
                    let normalized = evidence.normalized();
                    tracing::info!(cache_reused, "repository evidence analysis completed");
                    let reuse_fingerprint = (normalized.limitations.is_empty()
                        && normalized.repositories.iter().all(|repository| {
                            repository.completeness
                                == crate::evidence::EvidenceCompletenessV1::Complete
                        }))
                    .then_some(fingerprint);
                    let bytes = serde_json::to_vec(&normalized).context("serializing evidence")?;
                    ensure!(
                        bytes.len() as u64 <= job.spec.bounds.artifact_byte_limit,
                        "evidence artifact exceeds job byte limit"
                    );
                    let digest = sha256_hex(&bytes);
                    persist_recoverable_artifact(
                        repository_scope,
                        &config.artifact_directory,
                        &digest,
                        &bytes,
                    )?;
                    post_no_content(
                        &client,
                        endpoint(
                            &config.coordinator,
                            &format!("v1/tasks/{}/complete", task.id.0),
                        )?,
                        &config.agent_id,
                        &CompleteTaskRequestV1 {
                            lease_id,
                            artifact: ArtifactRefV1 {
                                digest: Sha256Digest::parse(&digest)?,
                                media_type: EVIDENCE_MEDIA_TYPE.to_owned(),
                                stored_bytes: bytes.len() as u64,
                            },
                            evidence: normalized,
                            reuse_fingerprint,
                            usage,
                        },
                    )
                    .await?;
                }
                Err(error) => {
                    let retry_at = (task.attempt < MAX_TASK_ATTEMPTS)
                        .then(|| Utc::now() + TimeDelta::seconds(RETRY_DELAY_SECONDS));
                    post_no_content(
                        &client,
                        endpoint(&config.coordinator, &format!("v1/tasks/{}/fail", task.id.0))?,
                        &config.agent_id,
                        &FailTaskRequestV1 {
                            lease_id,
                            failure: format!("{error:#}"),
                            retry_at,
                            usage,
                        },
                    )
                    .await?;
                }
            }

            Ok(if config.once {
                AgentLoopControl::Stop
            } else {
                AgentLoopControl::Continue
            })
        }
        .await;

        let finish = post_no_content(
            &client,
            endpoint(&config.coordinator, "v1/providers/permits/finish")?,
            &config.agent_id,
            &FinishProviderPermitRequestV1 {
                permit_id: permit.id,
                outcome: feedback.outcome,
                observation: feedback.observation,
            },
        )
        .await;
        if let Err(error) = finish {
            return Err(if attempt.is_err() {
                error.context("finishing provider permit after a failed worker attempt")
            } else {
                error.context("finishing provider permit")
            });
        }

        match attempt? {
            AgentLoopControl::Continue => {}
            AgentLoopControl::Poll => tokio::time::sleep(config.idle_poll).await,
            AgentLoopControl::Stop => return Ok(()),
        }
    }
}

fn provider_wait_duration(until: DateTime<Utc>) -> Duration {
    until
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or(Duration::from_millis(50))
        .max(Duration::from_millis(50))
}

fn classify_github_error(error: &anyhow::Error) -> ProviderFeedback {
    for source in error.chain() {
        if let Some(error) = source.downcast_ref::<GitHubApiError>() {
            let status = error.status;
            let rate_limited = status.as_u16() == 429
                || (status.as_u16() == 403
                    && error.rate_limit.as_ref().is_some_and(|rate| {
                        rate.remaining == Some(0) || rate.retry_after.is_some()
                    }));
            let outcome = if rate_limited {
                ProviderOutcomeClassV1::RateLimited
            } else if status.as_u16() == 408 {
                ProviderOutcomeClassV1::Timeout
            } else if status.is_server_error() {
                ProviderOutcomeClassV1::ServerError
            } else if matches!(status.as_u16(), 401 | 403) {
                ProviderOutcomeClassV1::AuthorizationError
            } else if status.as_u16() == 404 {
                ProviderOutcomeClassV1::NotFound
            } else {
                ProviderOutcomeClassV1::OtherClientError
            };
            let observation = error
                .rate_limit
                .as_ref()
                .map(|rate| RateLimitObservationV1 {
                    remaining: rate.remaining,
                    reset_at: rate
                        .reset_epoch
                        .and_then(|epoch| i64::try_from(epoch).ok())
                        .and_then(|epoch| DateTime::<Utc>::from_timestamp(epoch, 0)),
                    retry_after_seconds: rate
                        .retry_after
                        .as_deref()
                        .and_then(|value| value.parse().ok()),
                })
                .unwrap_or_default();
            return ProviderFeedback {
                outcome,
                observation,
            };
        }
        if let Some(error) = source.downcast_ref::<reqwest::Error>() {
            return ProviderFeedback {
                outcome: if error.is_timeout() {
                    ProviderOutcomeClassV1::Timeout
                } else {
                    ProviderOutcomeClassV1::TransportFailure
                },
                observation: RateLimitObservationV1::default(),
            };
        }
    }
    ProviderFeedback::success()
}

async fn heartbeat_until_failure(
    client: &reqwest::Client,
    config: &AgentRunConfig,
    task_id: &str,
    lease_id: &str,
) -> anyhow::Error {
    let interval = Duration::from_secs((config.lease_seconds / 3).max(1));
    loop {
        tokio::time::sleep(interval).await;
        let result = post_no_content(
            client,
            match endpoint(
                &config.coordinator,
                &format!("v1/tasks/{task_id}/heartbeat"),
            ) {
                Ok(endpoint) => endpoint,
                Err(error) => return error,
            },
            &config.agent_id,
            &HeartbeatRequestV1 {
                lease_id: lease_id.to_owned(),
                lease_seconds: Some(config.lease_seconds),
            },
        )
        .await;
        if let Err(error) = result {
            return error.context("worker heartbeat failed");
        }
    }
}

fn validate_config(config: &AgentRunConfig) -> Result<()> {
    ensure!(
        config.coordinator.scheme() == "https",
        "coordinator URL must use https"
    );
    ensure!(!config.agent_id.trim().is_empty(), "agent ID is empty");
    ensure!(
        (1..=600).contains(&config.lease_seconds),
        "lease seconds must be 1..=600"
    );
    ensure!(
        !config.idle_poll.is_zero(),
        "idle poll interval must be positive"
    );
    ensure!(
        config.max_file_bytes > 0,
        "maximum file bytes must be positive"
    );
    Ok(())
}

fn endpoint(base: &Url, path: &str) -> Result<Url> {
    base.join(path)
        .with_context(|| format!("joining coordinator URL path {path}"))
}

async fn get_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: Url,
    agent_id: &str,
) -> Result<T> {
    let response = client
        .get(url)
        .header("x-agent-id", agent_id)
        .send()
        .await
        .context("sending coordinator request")?;
    decode_json_response(response).await
}

async fn post_json<Request: Serialize, Response: DeserializeOwned>(
    client: &reqwest::Client,
    url: Url,
    agent_id: &str,
    body: &Request,
) -> Result<Response> {
    let response = client
        .post(url)
        .header("x-agent-id", agent_id)
        .json(body)
        .send()
        .await
        .context("sending coordinator request")?;
    decode_json_response(response).await
}

async fn post_no_content<Request: Serialize>(
    client: &reqwest::Client,
    url: Url,
    agent_id: &str,
    body: &Request,
) -> Result<()> {
    let response = client
        .post(url)
        .header("x-agent-id", agent_id)
        .json(body)
        .send()
        .await
        .context("sending coordinator request")?;
    if response.status().is_success() {
        return Ok(());
    }
    Err(response_error(response).await)
}

async fn decode_json_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    let bytes = read_limited(response, RESPONSE_LIMIT).await?;
    serde_json::from_slice(&bytes).context("decoding coordinator response")
}

async fn response_error(response: reqwest::Response) -> anyhow::Error {
    let status = response.status();
    match read_limited(response, ERROR_BODY_LIMIT).await {
        Ok(bytes) => anyhow::anyhow!(
            "coordinator returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        ),
        Err(error) => anyhow::anyhow!("coordinator returned {status}: {error:#}"),
    }
}

async fn read_limited(response: reqwest::Response, limit: u64) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        bail!("coordinator response exceeds {limit} bytes");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading coordinator response")?;
        ensure!(
            (body.len() as u64).saturating_add(chunk.len() as u64) <= limit,
            "coordinator response exceeds {limit} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn persist_local_artifact(directory: &Path, digest: &str, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(directory)
        .with_context(|| format!("creating artifact directory {}", directory.display()))?;
    let path = directory.join(format!("{digest}.evidence.json"));
    if path.exists() {
        ensure!(
            fs::read(&path)? == bytes,
            "existing local artifact {} differs from its digest",
            path.display()
        );
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    match temporary.persist_noclobber(&path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(fs::read(&path)? == bytes, "concurrent artifact differs");
            Ok(())
        }
        Err(error) => Err(error.error.into()),
    }
}

/// Private evidence is uploaded over mTLS into the coordinator's encrypted,
/// tenant-scoped cache and is never copied to the worker's plaintext recovery
/// directory. Public evidence retains the existing recoverable-copy behavior.
fn persist_recoverable_artifact(
    repository_scope: RepositoryScope,
    directory: &Path,
    digest: &str,
    bytes: &[u8],
) -> Result<()> {
    if repository_scope == RepositoryScope::PublicOnly {
        persist_local_artifact(directory, digest, bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_configuration_rejects_plaintext_transport() {
        let configuration = AgentRunConfig {
            coordinator: Url::parse("http://coordinator.invalid/").unwrap(),
            ca_certificate: PathBuf::from("ca.pem"),
            client_certificate: PathBuf::from("agent.pem"),
            client_private_key: PathBuf::from("agent.key"),
            agent_id: "worker-1".to_owned(),
            job_id: JobId("job-1".to_owned()),
            lease_seconds: 120,
            idle_poll: Duration::from_secs(5),
            once: true,
            artifact_directory: PathBuf::from("artifacts"),
            max_file_bytes: 1024,
        };
        assert!(validate_config(&configuration).is_err());
    }

    #[test]
    fn local_artifacts_are_immutable_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"evidence";
        let digest = sha256_hex(bytes);
        persist_local_artifact(directory.path(), &digest, bytes).unwrap();
        persist_local_artifact(directory.path(), &digest, bytes).unwrap();
        assert_eq!(
            fs::read(directory.path().join(format!("{digest}.evidence.json"))).unwrap(),
            bytes
        );
    }

    #[test]
    fn all_visible_evidence_is_never_persisted_as_plaintext() {
        let directory = tempfile::tempdir().unwrap().path().join("artifacts");
        let bytes = br#"{"private_repository":"owner/repo"}"#;
        let digest = sha256_hex(bytes);
        persist_recoverable_artifact(RepositoryScope::AllVisible, &directory, &digest, bytes)
            .unwrap();
        assert!(!directory.exists());
    }

    #[test]
    fn public_evidence_keeps_a_recoverable_copy() {
        let directory = tempfile::tempdir().unwrap().path().join("artifacts");
        let bytes = b"public evidence";
        let digest = sha256_hex(bytes);
        persist_recoverable_artifact(RepositoryScope::PublicOnly, &directory, &digest, bytes)
            .unwrap();
        assert_eq!(
            fs::read(directory.join(format!("{digest}.evidence.json"))).unwrap(),
            bytes
        );
    }

    #[test]
    fn github_rate_limit_feedback_preserves_coordinator_observations() {
        let error = anyhow::Error::new(GitHubApiError {
            status: reqwest::StatusCode::FORBIDDEN,
            message: "rate limited".to_owned(),
            documentation_url: None,
            rate_limit: Some(crate::github::GitHubRateLimit {
                limit: Some(5_000),
                remaining: Some(0),
                used: Some(5_000),
                reset_epoch: Some(1_786_400_000),
                resource: Some("core".to_owned()),
                retry_after: Some("17".to_owned()),
            }),
        });

        let feedback = classify_github_error(&error);
        assert_eq!(feedback.outcome, ProviderOutcomeClassV1::RateLimited);
        assert_eq!(feedback.observation.remaining, Some(0));
        assert_eq!(feedback.observation.retry_after_seconds, Some(17));
        assert_eq!(
            feedback.observation.reset_at,
            DateTime::<Utc>::from_timestamp(1_786_400_000, 0)
        );
    }

    #[test]
    fn non_provider_analysis_errors_do_not_trip_the_provider_circuit() {
        let feedback = classify_github_error(&anyhow::anyhow!("manifest parse failed"));
        assert_eq!(feedback.outcome, ProviderOutcomeClassV1::Success);
        assert_eq!(feedback.observation, RateLimitObservationV1::default());
    }
}
