//! LAN worker loop for durable repository-analysis tasks.

use std::{
    fmt, fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use futures::{StreamExt as _, future::BoxFuture};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;
use uuid::Uuid;

use crate::{
    coordinator::{
        ArtifactRefV1, JobId, PermitDecision, PermitId, ProviderKeyV1, ProviderOutcomeClassV1,
        RateLimitObservationV1, RepositoryScopeV1, Sha256Digest, TaskUsageV1,
    },
    coordinator_api::{
        AcquireProviderPermitRequestV1, AcquireProviderPermitResponseV1, CacheLookupRequestV1,
        CacheLookupResponseV1, CompleteTaskRequestV1, DeferTaskRequestV1, FailTaskRequestV1,
        FinishProviderPermitRequestV1, HeartbeatRequestV1, LeaseRequestV1, LeaseResponseV1,
        TaskCredentialRequestV1, TaskCredentialResponseV1, TaskFailureClassV1,
    },
    github::{
        GitHubApiError, GitHubClient, GitHubRequestAttemptV1, GitHubRequestGate,
        GitHubRequestGateError, GitHubRequestOutcomeV1, GitHubRequestPermitV1,
        GitHubRequestTransportV1, RepositoryScope, preferred_token_from_environment,
    },
    pki,
    repository_analyzer::{
        RepositoryAnalyzerBounds, analysis_reuse_fingerprint, analyze_repository_snapshot,
        exact_target_version, resolve_repository_snapshot, reuse_cached_evidence,
    },
    secure_cache::sha256_hex,
};

const RESPONSE_LIMIT: u64 = 16 * 1024 * 1024;
const ERROR_BODY_LIMIT: u64 = 16 * 1024;
const MAX_FAILURE_BYTES: usize = 4_096;
const MAX_LEASE_REQUEST_ATTEMPTS: usize = 3;
const MAX_PROVIDER_CONTROL_REQUEST_ATTEMPTS: usize = 3;
const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.crate-dependent-repos.evidence.v1+json";

#[derive(Clone, Debug)]
pub struct AgentRunConfig {
    pub coordinator: Url,
    pub ca_certificate: PathBuf,
    pub client_certificate: PathBuf,
    pub client_private_key: PathBuf,
    pub agent_id: String,
    pub job_id: Option<JobId>,
    pub lease_seconds: u64,
    pub idle_poll: Duration,
    pub once: bool,
    pub artifact_directory: PathBuf,
    pub max_file_bytes: u64,
}

#[derive(Clone, Debug)]
struct ProviderFeedback {
    outcome: ProviderOutcomeClassV1,
    observation: RateLimitObservationV1,
}

#[derive(Clone)]
struct CoordinatorGitHubRequestGate {
    client: reqwest::Client,
    coordinator: Url,
    agent_id: Arc<str>,
    repository_scope: RepositoryScopeV1,
    credential_profile_id: Option<Arc<str>>,
    task_id: crate::coordinator::TaskId,
    lease_id: Arc<str>,
    capacity_delay: Duration,
    request_sequence: Arc<AtomicU64>,
}

impl CoordinatorGitHubRequestGate {
    fn new(
        client: reqwest::Client,
        config: &AgentRunConfig,
        repository_scope: RepositoryScopeV1,
        credential_profile_id: Option<&str>,
        task_id: crate::coordinator::TaskId,
        lease_id: &str,
    ) -> Self {
        Self {
            client,
            coordinator: config.coordinator.clone(),
            agent_id: Arc::from(config.agent_id.as_str()),
            repository_scope,
            credential_profile_id: credential_profile_id.map(Arc::from),
            task_id,
            lease_id: Arc::from(lease_id),
            capacity_delay: config.idle_poll,
            request_sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    fn deferred_for_capacity(&self) -> DateTime<Utc> {
        Utc::now()
            + TimeDelta::from_std(self.capacity_delay.max(Duration::from_millis(50)))
                .unwrap_or(TimeDelta::seconds(5))
    }

    fn permit_id(&self, request: GitHubRequestAttemptV1, sequence: u64) -> PermitId {
        let material = format!(
            "crate-dependent-repos/github-permit/v1\0{}\0{}\0{}\0{}\0{}",
            self.task_id.0,
            self.lease_id,
            request.resource.provider_resource(),
            request.attempt,
            sequence
        );
        PermitId(format!("ghp-{}", sha256_hex(material.as_bytes())))
    }
}

impl GitHubRequestGate for CoordinatorGitHubRequestGate {
    fn acquire<'a>(
        &'a self,
        request: GitHubRequestAttemptV1,
    ) -> BoxFuture<'a, Result<GitHubRequestPermitV1, GitHubRequestGateError>> {
        Box::pin(async move {
            let key = ProviderKeyV1::github_request(
                self.repository_scope,
                self.credential_profile_id.as_deref(),
                request.resource.provider_resource(),
            );
            let permit_id = self.permit_id(
                request,
                self.request_sequence.fetch_add(1, Ordering::Relaxed),
            );
            let admission: AcquireProviderPermitResponseV1 = post_json_with_ambiguous_retry(
                &self.client,
                endpoint(&self.coordinator, "v1/providers/permits/acquire")
                    .map_err(|_| GitHubRequestGateError::Protocol)?,
                &self.agent_id,
                &AcquireProviderPermitRequestV1 {
                    key,
                    permit_id: Some(permit_id),
                    task_id: Some(self.task_id.clone()),
                    lease_id: Some(self.lease_id.to_string()),
                },
            )
            .await
            .map_err(gate_error_from_coordinator)?;
            match admission.decision {
                PermitDecision::Granted(permit) => GitHubRequestPermitV1::new(permit.id.0),
                PermitDecision::WaitUntil(until) => {
                    Err(GitHubRequestGateError::DeferredUntil(until))
                }
                PermitDecision::CapacityExhausted | PermitDecision::HalfOpenProbeInFlight => Err(
                    GitHubRequestGateError::DeferredUntil(self.deferred_for_capacity()),
                ),
            }
        })
    }

    fn finish<'a>(
        &'a self,
        permit: GitHubRequestPermitV1,
        outcome: GitHubRequestOutcomeV1,
    ) -> BoxFuture<'a, Result<(), GitHubRequestGateError>> {
        Box::pin(async move {
            let retry_at = outcome.cooperative_retry_at(Utc::now());
            let feedback = provider_feedback_from_request(&outcome);
            post_no_content_with_ambiguous_retry(
                &self.client,
                endpoint(&self.coordinator, "v1/providers/permits/finish")
                    .map_err(|_| GitHubRequestGateError::Protocol)?,
                &self.agent_id,
                &FinishProviderPermitRequestV1 {
                    permit_id: PermitId(permit.as_str().to_owned()),
                    outcome: feedback.outcome,
                    observation: feedback.observation,
                },
            )
            .await
            .map_err(gate_error_from_coordinator)?;
            match retry_at {
                Some(until) => Err(GitHubRequestGateError::DeferredUntil(until)),
                None => Ok(()),
            }
        })
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
    loop {
        let lease_path = config.job_id.as_ref().map_or_else(
            || "v1/tasks/lease".to_owned(),
            |job_id| format!("v1/jobs/{}/lease", job_id.0),
        );
        let lease_request_id = Uuid::new_v4().to_string();
        let leased = lease_with_retry(
            &client,
            endpoint(&config.coordinator, &lease_path)?,
            &config.agent_id,
            &LeaseRequestV1 {
                lease_seconds: Some(config.lease_seconds),
                lease_id: Some(lease_request_id),
            },
        )
        .await?;
        let Some(task) = leased.task else {
            if let Some(job_id) = &config.job_id {
                let current: crate::coordinator::ScanJobV1 = get_json(
                    &client,
                    endpoint(&config.coordinator, &format!("v1/jobs/{}", job_id.0))?,
                    &config.agent_id,
                )
                .await?;
                if current.state.is_terminal() {
                    return Ok(());
                }
            }
            if config.once {
                return Ok(());
            }
            tokio::time::sleep(config.idle_poll).await;
            continue;
        };
        let lease = task
            .lease
            .as_ref()
            .context("coordinator returned a leased task without lease metadata")?;
        let lease_id = lease.lease_id.clone();
        if let Some(job_id) = &config.job_id {
            ensure!(
                task.job_id == *job_id,
                "pinned lease returned a task from another job"
            );
        }
        let job: crate::coordinator::ScanJobV1 = get_json(
            &client,
            endpoint(&config.coordinator, &format!("v1/jobs/{}", task.job_id.0))?,
            &config.agent_id,
        )
        .await?;
        ensure!(job.id == task.job_id, "task references a mismatched job");
        let target_version = exact_target_version(&job.spec.target.version_spec)?;
        let repository_scope = match job.spec.repository_scope {
            RepositoryScopeV1::PublicOnly => RepositoryScope::PublicOnly,
            RepositoryScopeV1::AllVisible => RepositoryScope::AllVisible,
        };

        let (token, credential_expires_at) = match job.spec.repository_scope {
            RepositoryScopeV1::PublicOnly => (preferred_token_from_environment(), None),
            RepositoryScopeV1::AllVisible => {
                let credential = post_json::<_, TaskCredentialResponseV1>(
                    &client,
                    endpoint(
                        &config.coordinator,
                        &format!("v1/tasks/{}/credential", task.id.0),
                    )?,
                    &config.agent_id,
                    &TaskCredentialRequestV1 {
                        lease_id: lease_id.clone(),
                    },
                )
                .await
                .and_then(|credential| {
                    ensure!(
                        credential.schema_version == 1
                            && !credential.access_token.trim().is_empty(),
                        "coordinator returned an invalid task credential"
                    );
                    Ok(credential)
                });
                match credential {
                    Ok(credential) => {
                        let (token, expires_at) = credential.into_token_and_expiry();
                        (Some(token), Some(expires_at))
                    }
                    Err(error) if credential_failure_is_transient(&error) => {
                        tracing::warn!(
                            task_id = %task.id.0,
                            "private task deferred because no brokered credential is available"
                        );
                        post_no_content(
                            &client,
                            endpoint(
                                &config.coordinator,
                                &format!("v1/tasks/{}/defer", task.id.0),
                            )?,
                            &config.agent_id,
                            &DeferTaskRequestV1 {
                                lease_id,
                                not_before: deferred_after(config.idle_poll),
                                reason_code: "credential_unavailable".to_owned(),
                            },
                        )
                        .await?;
                        if config.once {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(error) => {
                        post_no_content(
                            &client,
                            endpoint(&config.coordinator, &format!("v1/tasks/{}/fail", task.id.0))?,
                            &config.agent_id,
                            &FailTaskRequestV1 {
                                lease_id,
                                failure: bounded_failure(&error),
                                failure_class: credential_failure_class(&error),
                                usage: TaskUsageV1::default(),
                            },
                        )
                        .await?;
                        if config.once {
                            return Ok(());
                        }
                        continue;
                    }
                }
            }
        };
        let gate = Arc::new(CoordinatorGitHubRequestGate::new(
            client.clone(),
            &config,
            job.spec.repository_scope,
            job.spec.credential_profile_id.as_deref(),
            task.id.clone(),
            &lease_id,
        ));
        let github = match GitHubClient::new(token) {
            Ok(github) => github.with_gate(gate),
            Err(error) => {
                post_no_content(
                    &client,
                    endpoint(&config.coordinator, &format!("v1/tasks/{}/fail", task.id.0))?,
                    &config.agent_id,
                    &FailTaskRequestV1 {
                        lease_id,
                        failure: bounded_failure(&error),
                        failure_class: TaskFailureClassV1::AnalysisPermanent,
                        usage: TaskUsageV1::default(),
                    },
                )
                .await?;
                if config.once {
                    return Ok(());
                }
                continue;
            }
        };
        tracing::info!(
            task_id = %task.id.0,
            job_id = %task.job_id.0,
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
                resolve_repository_snapshot(&github, &task.repository_id, repository_scope).await?;
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
            result = analysis => result,
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
                        repository.completeness == crate::evidence::EvidenceCompletenessV1::Complete
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
                if let Some((not_before, reason_code)) = provider_defer(&error, config.idle_poll) {
                    post_no_content(
                        &client,
                        endpoint(
                            &config.coordinator,
                            &format!("v1/tasks/{}/defer", task.id.0),
                        )?,
                        &config.agent_id,
                        &DeferTaskRequestV1 {
                            lease_id,
                            not_before,
                            reason_code: reason_code.to_owned(),
                        },
                    )
                    .await?;
                } else {
                    post_no_content(
                        &client,
                        endpoint(&config.coordinator, &format!("v1/tasks/{}/fail", task.id.0))?,
                        &config.agent_id,
                        &FailTaskRequestV1 {
                            lease_id,
                            failure: bounded_failure(&error),
                            failure_class: classify_task_failure_with_credential_expiry(
                                &error,
                                credential_expires_at,
                            ),
                            usage,
                        },
                    )
                    .await?;
                }
            }
        }

        if config.once {
            return Ok(());
        }
    }
}

fn provider_feedback_from_request(outcome: &GitHubRequestOutcomeV1) -> ProviderFeedback {
    let observation = outcome
        .rate_limit
        .as_ref()
        .map(|rate| RateLimitObservationV1 {
            remaining: rate.remaining,
            reset_at: rate
                .reset_epoch
                .and_then(|epoch| i64::try_from(epoch).ok())
                .and_then(|epoch| DateTime::<Utc>::from_timestamp(epoch, 0)),
            retry_after_seconds: rate.retry_after_seconds.or_else(|| {
                rate.retry_after_at.and_then(|retry_at| {
                    u64::try_from(
                        retry_at
                            .signed_duration_since(Utc::now())
                            .num_seconds()
                            .max(0),
                    )
                    .ok()
                })
            }),
        })
        .unwrap_or_default();
    let outcome_class = match outcome.transport {
        GitHubRequestTransportV1::ConnectFailure | GitHubRequestTransportV1::TransportFailure => {
            ProviderOutcomeClassV1::TransportFailure
        }
        GitHubRequestTransportV1::Timeout => ProviderOutcomeClassV1::Timeout,
        GitHubRequestTransportV1::ResponseHeaders => {
            let status = outcome.status.unwrap_or_default();
            if status == 429
                || (status == 403
                    && (observation.remaining == Some(0)
                        || observation.retry_after_seconds.is_some()))
            {
                ProviderOutcomeClassV1::RateLimited
            } else if status == 408 {
                ProviderOutcomeClassV1::Timeout
            } else if (500..=599).contains(&status) {
                ProviderOutcomeClassV1::ServerError
            } else if matches!(status, 401 | 403) {
                ProviderOutcomeClassV1::AuthorizationError
            } else if status == 404 {
                ProviderOutcomeClassV1::NotFound
            } else if (400..=499).contains(&status) {
                ProviderOutcomeClassV1::OtherClientError
            } else {
                ProviderOutcomeClassV1::Success
            }
        }
    };
    ProviderFeedback {
        outcome: outcome_class,
        observation,
    }
}

fn provider_defer(
    error: &anyhow::Error,
    unavailable_delay: Duration,
) -> Option<(DateTime<Utc>, &'static str)> {
    error.chain().find_map(|source| {
        let error = source.downcast_ref::<GitHubRequestGateError>()?;
        match error {
            GitHubRequestGateError::DeferredUntil(until) => Some((
                (*until).max(Utc::now() + TimeDelta::milliseconds(50)),
                "github_provider_backpressure",
            )),
            GitHubRequestGateError::Unavailable => Some((
                deferred_after(unavailable_delay),
                "github_admission_unavailable",
            )),
            GitHubRequestGateError::Rejected | GitHubRequestGateError::Protocol => None,
        }
    })
}

fn deferred_after(delay: Duration) -> DateTime<Utc> {
    Utc::now()
        + TimeDelta::from_std(delay.max(Duration::from_millis(50))).unwrap_or(TimeDelta::seconds(5))
}

fn classify_task_failure(error: &anyhow::Error) -> TaskFailureClassV1 {
    for source in error.chain() {
        if let Some(error) = source.downcast_ref::<GitHubRequestGateError>() {
            return match error {
                GitHubRequestGateError::DeferredUntil(_) => TaskFailureClassV1::ProviderRateLimited,
                GitHubRequestGateError::Unavailable => TaskFailureClassV1::AnalysisTransient,
                GitHubRequestGateError::Rejected => TaskFailureClassV1::ProviderAuthorization,
                GitHubRequestGateError::Protocol => TaskFailureClassV1::AnalysisPermanent,
            };
        }
        if let Some(error) = source.downcast_ref::<GitHubApiError>() {
            let status = error.status;
            let rate_limited = status.as_u16() == 429
                || (status.as_u16() == 403
                    && error.rate_limit.as_ref().is_some_and(|rate| {
                        rate.remaining == Some(0) || rate.retry_after.is_some()
                    }));
            return if rate_limited {
                TaskFailureClassV1::ProviderRateLimited
            } else if status.as_u16() == 408 || status.is_server_error() {
                TaskFailureClassV1::ProviderTransient
            } else if matches!(status.as_u16(), 401 | 403) {
                TaskFailureClassV1::ProviderAuthorization
            } else if status.as_u16() == 404 {
                TaskFailureClassV1::RepositoryNotFound
            } else {
                TaskFailureClassV1::AnalysisPermanent
            };
        }
        if let Some(error) = source.downcast_ref::<reqwest::Error>() {
            return if error.is_timeout() || error.is_connect() {
                TaskFailureClassV1::ProviderTransient
            } else {
                TaskFailureClassV1::AnalysisTransient
            };
        }
        if let Some(error) = source.downcast_ref::<CoordinatorResponseError>() {
            return if error.status.is_server_error() || matches!(error.status.as_u16(), 408 | 429) {
                TaskFailureClassV1::AnalysisTransient
            } else {
                TaskFailureClassV1::AnalysisPermanent
            };
        }
    }
    TaskFailureClassV1::AnalysisTransient
}

fn classify_task_failure_with_credential_expiry(
    error: &anyhow::Error,
    credential_expires_at: Option<DateTime<Utc>>,
) -> TaskFailureClassV1 {
    let class = classify_task_failure(error);
    if class == TaskFailureClassV1::ProviderAuthorization
        && credential_expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now() + TimeDelta::seconds(5))
    {
        TaskFailureClassV1::ProviderTransient
    } else {
        class
    }
}

fn credential_failure_is_transient(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source.downcast_ref::<reqwest::Error>().is_some()
            || source
                .downcast_ref::<CoordinatorResponseError>()
                .is_some_and(|error| {
                    error.status.is_server_error() || matches!(error.status.as_u16(), 408 | 429)
                })
    })
}

fn credential_failure_class(error: &anyhow::Error) -> TaskFailureClassV1 {
    if error.chain().any(|source| {
        source
            .downcast_ref::<CoordinatorResponseError>()
            .is_some_and(|error| matches!(error.status.as_u16(), 401 | 403))
    }) {
        TaskFailureClassV1::ProviderAuthorization
    } else {
        TaskFailureClassV1::AnalysisPermanent
    }
}

fn bounded_failure(error: &anyhow::Error) -> String {
    let mut failure = format!("{error:#}");
    if failure.len() > MAX_FAILURE_BYTES {
        let mut end = MAX_FAILURE_BYTES;
        while !failure.is_char_boundary(end) {
            end -= 1;
        }
        failure.truncate(end);
    }
    failure
}

fn gate_error_from_coordinator(error: anyhow::Error) -> GitHubRequestGateError {
    for source in error.chain() {
        if let Some(error) = source.downcast_ref::<CoordinatorResponseError>() {
            return if matches!(error.status.as_u16(), 401 | 403) {
                GitHubRequestGateError::Rejected
            } else if error.status.is_server_error() || matches!(error.status.as_u16(), 408 | 429) {
                GitHubRequestGateError::Unavailable
            } else {
                GitHubRequestGateError::Protocol
            };
        }
        if source.downcast_ref::<reqwest::Error>().is_some() {
            return GitHubRequestGateError::Unavailable;
        }
    }
    GitHubRequestGateError::Protocol
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

async fn post_json_with_ambiguous_retry<Request: Serialize, Response: DeserializeOwned>(
    client: &reqwest::Client,
    url: Url,
    agent_id: &str,
    body: &Request,
) -> Result<Response> {
    for attempt in 0..MAX_PROVIDER_CONTROL_REQUEST_ATTEMPTS {
        match post_json(client, url.clone(), agent_id, body).await {
            Ok(response) => return Ok(response),
            Err(error)
                if attempt + 1 < MAX_PROVIDER_CONTROL_REQUEST_ATTEMPTS
                    && coordinator_response_is_ambiguous(&error) =>
            {
                tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded provider-control retry loop always returns")
}

async fn lease_with_retry(
    client: &reqwest::Client,
    url: Url,
    agent_id: &str,
    request: &LeaseRequestV1,
) -> Result<LeaseResponseV1> {
    for attempt in 0..MAX_LEASE_REQUEST_ATTEMPTS {
        match post_json(client, url.clone(), agent_id, request).await {
            Ok(response) => return Ok(response),
            Err(error)
                if attempt + 1 < MAX_LEASE_REQUEST_ATTEMPTS
                    && coordinator_response_is_ambiguous(&error) =>
            {
                tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded lease retry loop always returns")
}

fn coordinator_response_is_ambiguous(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source.downcast_ref::<reqwest::Error>().is_some()
            || source.downcast_ref::<serde_json::Error>().is_some()
            || source
                .downcast_ref::<CoordinatorResponseError>()
                .is_some_and(|error| {
                    error.status.is_server_error() || matches!(error.status.as_u16(), 408 | 429)
                })
    })
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

async fn post_no_content_with_ambiguous_retry<Request: Serialize>(
    client: &reqwest::Client,
    url: Url,
    agent_id: &str,
    body: &Request,
) -> Result<()> {
    for attempt in 0..MAX_PROVIDER_CONTROL_REQUEST_ATTEMPTS {
        match post_no_content(client, url.clone(), agent_id, body).await {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt + 1 < MAX_PROVIDER_CONTROL_REQUEST_ATTEMPTS
                    && coordinator_response_is_ambiguous(&error) =>
            {
                tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("bounded provider-control retry loop always returns")
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
    let message = match read_limited(response, ERROR_BODY_LIMIT).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => format!("failed to read bounded error response: {error:#}"),
    };
    anyhow::Error::new(CoordinatorResponseError { status, message })
}

#[derive(Debug)]
struct CoordinatorResponseError {
    status: reqwest::StatusCode,
    message: String,
}

impl fmt::Display for CoordinatorResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "coordinator returned {}: {}",
            self.status, self.message
        )
    }
}

impl std::error::Error for CoordinatorResponseError {}

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
            job_id: Some(JobId("job-1".to_owned())),
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
        let feedback = provider_feedback_from_request(&GitHubRequestOutcomeV1 {
            request: GitHubRequestAttemptV1 {
                provider: crate::github::OutboundProviderV1::GitHub,
                resource: crate::github::GitHubRequestResourceV1::Core,
                attempt: 1,
                max_attempts: 3,
            },
            transport: GitHubRequestTransportV1::ResponseHeaders,
            status: Some(403),
            rate_limit: Some(crate::github::GitHubRequestRateLimitV1 {
                limit: Some(5_000),
                remaining: Some(0),
                used: Some(5_000),
                reset_epoch: Some(1_786_400_000),
                resource: Some(crate::github::GitHubRateResourceV1::Core),
                retry_after_seconds: Some(17),
                retry_after_at: None,
            }),
        });
        assert_eq!(feedback.outcome, ProviderOutcomeClassV1::RateLimited);
        assert_eq!(feedback.observation.remaining, Some(0));
        assert_eq!(feedback.observation.retry_after_seconds, Some(17));
        assert_eq!(
            feedback.observation.reset_at,
            DateTime::<Utc>::from_timestamp(1_786_400_000, 0)
        );
    }

    #[test]
    fn provider_permit_ids_are_stable_unique_and_identity_blind() {
        let configuration = AgentRunConfig {
            coordinator: Url::parse("https://coordinator.invalid/").unwrap(),
            ca_certificate: PathBuf::from("ca.pem"),
            client_certificate: PathBuf::from("agent.pem"),
            client_private_key: PathBuf::from("agent.key"),
            agent_id: "worker-1".to_owned(),
            job_id: None,
            lease_seconds: 120,
            idle_poll: Duration::from_secs(5),
            once: true,
            artifact_directory: PathBuf::from("artifacts"),
            max_file_bytes: 1024,
        };
        let gate = CoordinatorGitHubRequestGate::new(
            reqwest::Client::new(),
            &configuration,
            RepositoryScopeV1::PublicOnly,
            None,
            crate::coordinator::TaskId("task-private-name".to_owned()),
            "lease-secret",
        );
        let request = GitHubRequestAttemptV1 {
            provider: crate::github::OutboundProviderV1::GitHub,
            resource: crate::github::GitHubRequestResourceV1::Core,
            attempt: 1,
            max_attempts: 3,
        };
        let first = gate.permit_id(request, 7);
        assert_eq!(first, gate.permit_id(request, 7));
        assert_ne!(first, gate.permit_id(request, 8));
        assert!(!first.0.contains("private"));
        assert!(!first.0.contains("secret"));
    }

    #[test]
    fn non_provider_analysis_errors_do_not_trip_the_provider_circuit() {
        assert_eq!(
            classify_task_failure(&anyhow::anyhow!("manifest parse failed")),
            TaskFailureClassV1::AnalysisTransient
        );
    }

    #[test]
    fn ambiguous_lease_responses_are_retried_with_the_same_request_id() {
        let unavailable = anyhow::Error::new(CoordinatorResponseError {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            message: "temporarily unavailable".to_owned(),
        });
        let rejected = anyhow::Error::new(CoordinatorResponseError {
            status: reqwest::StatusCode::BAD_REQUEST,
            message: "invalid request".to_owned(),
        });
        assert!(coordinator_response_is_ambiguous(&unavailable));
        assert!(!coordinator_response_is_ambiguous(&rejected));
    }

    #[test]
    fn persisted_failure_text_is_bounded_on_utf8_boundaries() {
        let error = anyhow::anyhow!("{}", "ä".repeat(MAX_FAILURE_BYTES));
        let failure = bounded_failure(&error);
        assert!(failure.len() <= MAX_FAILURE_BYTES);
        assert!(failure.ends_with('ä'));
    }
}
