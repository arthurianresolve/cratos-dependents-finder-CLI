//! Mutual-TLS coordinator protocol for LAN operators and workers.

use std::{collections::BTreeSet, io, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result, ensure};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::AddExtension,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use chrono::{DateTime, TimeDelta, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tokio_rustls::server::TlsStream;
use tower::Layer as _;
use uuid::Uuid;

use crate::{
    coordinator::{
        AgentRecordV1, ArtifactRecordV1, ArtifactRefV1, CacheContentKindV1, CacheKeyV1,
        CacheMetadataV1, CacheNamespaceV1, CacheProtectionV1, DurableCommandV1, DurableOutcomeV1,
        EvidenceCompletenessV1 as CacheCompletenessV1, JobEventV1, JobId, NewRepositoryTaskV1,
        PermitDecision, PermitId, ProviderKeyV1, ProviderOutcomeClassV1, ProviderPolicyV1,
        RateLimitObservationV1, RepositoryScopeV1, RepositoryTaskStateV1, RepositoryTaskV1,
        RetentionPolicyV1, ReuseFingerprintV1, SCHEMA_VERSION_V1, ScanJobV1, ScanSpecV1,
        SubmitJobV1, SubmitOutcome, TaskId, TaskUsageV1, TursoCoordinatorStore,
    },
    evidence::{EvidenceBundleV1, EvidenceCompletenessV1, RepositoryVisibilityV1},
    pki,
    repository_analyzer::{
        REPOSITORY_ANALYZER_VERSION, analysis_evidence_profile_hash, analysis_target_hash,
    },
    secure_cache::{EnvelopeKey, SecureBlobCache, SecureCacheNamespace, sha256_hex},
    telemetry::CoordinatorMetrics,
};

const MAX_REPOSITORIES_PER_JOB: usize = 10_000;
const DEFAULT_LEASE_SECONDS: u64 = 120;
const MAX_LEASE_SECONDS: u64 = 600;
const LEASE_RECLAIM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const RETENTION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const RETENTION_SWEEP_BATCH: usize = 256;
const MAX_EVIDENCE_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_PAGE_SIZE: usize = 250;
const MAX_PAGE_SIZE: usize = 1_000;
const MAX_COMPLETE_REQUEST_BYTES: usize = MAX_EVIDENCE_ARTIFACT_BYTES + 512 * 1024;
const CACHE_CONTENT_KIND_EVIDENCE: &str = "evidence";
pub const EVIDENCE_MEDIA_TYPE_V1: &str = "application/vnd.crate-dependent-repos.evidence.v1+json";

#[derive(Clone, Debug)]
pub struct CoordinatorServerConfig {
    pub listen: SocketAddr,
    pub ca_certificate: PathBuf,
    pub server_certificate: PathBuf,
    pub server_private_key: PathBuf,
    pub artifact_cache_directory: PathBuf,
    pub envelope_key: PathBuf,
    pub envelope_key_id: String,
    pub retention_policy: RetentionPolicyV1,
}

#[derive(Clone)]
struct ApiState {
    store: TursoCoordinatorStore,
    metrics: CoordinatorMetrics,
    artifacts: SecureBlobCache,
    envelope_key: Arc<EnvelopeKey>,
    retention_policy: RetentionPolicyV1,
    artifact_retention: Arc<RwLock<()>>,
}

#[derive(Clone, Debug)]
struct TlsPeerIdentity {
    certificate_sha256: String,
}

#[derive(Clone, Debug)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
}

impl PeerIdentityAcceptor {
    fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, TlsPeerIdentity>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let certificate = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .ok_or_else(|| io::Error::other("mTLS peer certificate missing"))?;
            let identity = TlsPeerIdentity {
                certificate_sha256: sha256_hex(certificate.as_ref()),
            };
            Ok((stream, Extension(identity).layer(service)))
        })
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitScanRequestV1 {
    pub idempotency_key: String,
    pub job_id: Option<JobId>,
    pub spec: ScanSpecV1,
    pub repositories: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitScanResponseV1 {
    pub job_id: JobId,
    pub created: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LeaseRequestV1 {
    pub lease_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeartbeatRequestV1 {
    pub lease_id: String,
    pub lease_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompleteTaskRequestV1 {
    pub lease_id: String,
    pub artifact: ArtifactRefV1,
    pub evidence: EvidenceBundleV1,
    /// Immutable analysis identity used only for complete derived-evidence
    /// reuse. Older workers may omit it; their artifacts remain exportable but
    /// are never selected by the incremental cache.
    #[serde(default)]
    pub reuse_fingerprint: Option<ReuseFingerprintV1>,
    #[serde(default)]
    pub usage: TaskUsageV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheLookupRequestV1 {
    pub lease_id: String,
    pub fingerprint: ReuseFingerprintV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheLookupResponseV1 {
    pub evidence: Option<EvidenceBundleV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigureProviderRequestV1 {
    pub key: ProviderKeyV1,
    pub policy: ProviderPolicyV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcquireProviderPermitRequestV1 {
    pub key: ProviderKeyV1,
    pub permit_id: Option<PermitId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcquireProviderPermitResponseV1 {
    pub decision: PermitDecision,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinishProviderPermitRequestV1 {
    pub permit_id: PermitId,
    pub outcome: ProviderOutcomeClassV1,
    pub observation: RateLimitObservationV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetentionCollectionResponseV1 {
    pub candidates: usize,
    pub metadata_removed: usize,
    pub blobs_removed: usize,
    pub remaining_candidates: usize,
    pub events_pruned: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailTaskRequestV1 {
    pub lease_id: String,
    pub failure: String,
    pub retry_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub usage: TaskUsageV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LeaseResponseV1 {
    pub task: Option<RepositoryTaskV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryTaskPageV1 {
    pub items: Vec<RepositoryTaskV1>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobEventPageV1 {
    pub items: Vec<JobEventV1>,
    pub next_cursor: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct TaskPageQueryV1 {
    after: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct EventPageQueryV1 {
    after: Option<u64>,
    limit: Option<usize>,
}

pub async fn serve(
    config: CoordinatorServerConfig,
    store: TursoCoordinatorStore,
    metrics: CoordinatorMetrics,
) -> Result<()> {
    ensure!(
        !config.envelope_key_id.trim().is_empty(),
        "envelope key ID is empty"
    );
    let tls = pki::server_config(
        &config.ca_certificate,
        &config.server_certificate,
        &config.server_private_key,
    )?;
    let acceptor = PeerIdentityAcceptor::new(RustlsAcceptor::new(RustlsConfig::from_config(
        Arc::new(tls),
    )));
    let envelope_key = Arc::new(EnvelopeKey::load(
        &config.envelope_key,
        config.envelope_key_id,
    )?);
    let state = ApiState {
        store,
        metrics,
        artifacts: SecureBlobCache::new(config.artifact_cache_directory),
        envelope_key,
        retention_policy: config.retention_policy,
        artifact_retention: Arc::new(RwLock::new(())),
    };
    spawn_lease_reclaimer(state.store.clone());
    spawn_retention_collector(state.clone());
    let application = Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(render_metrics))
        .route("/v1/jobs", post(submit_job))
        .route("/v1/jobs/{job_id}", get(job_status))
        .route("/v1/jobs/{job_id}/events", get(job_events))
        .route("/v1/jobs/{job_id}/tasks", get(job_tasks))
        .route("/v1/jobs/{job_id}/resume", post(resume_job))
        .route("/v1/jobs/{job_id}/cancel", post(cancel_job))
        .route("/v1/jobs/{job_id}/lease", post(lease_task))
        .route("/v1/tasks/{task_id}/heartbeat", post(heartbeat_task))
        .route("/v1/tasks/{task_id}/cache/lookup", post(cache_lookup))
        .route("/v1/tasks/{task_id}/complete", post(complete_task))
        .route("/v1/tasks/{task_id}/artifact", get(task_artifact))
        .route("/v1/artifacts/retention/run", post(run_retention))
        .route("/v1/tasks/{task_id}/fail", post(fail_task))
        .route("/v1/providers/configure", post(configure_provider))
        .route(
            "/v1/providers/permits/acquire",
            post(acquire_provider_permit),
        )
        .route("/v1/providers/permits/finish", post(finish_provider_permit))
        .layer(DefaultBodyLimit::max(MAX_COMPLETE_REQUEST_BYTES))
        .with_state(state);

    tracing::info!(listen = %config.listen, "coordinator listening with mutual TLS");
    axum_server::bind(config.listen)
        .acceptor(acceptor)
        .serve(application.into_make_service())
        .await
        .context("serving coordinator API")
}

async fn authenticate(
    state: &ApiState,
    headers: &HeaderMap,
    peer: &TlsPeerIdentity,
) -> Result<AgentRecordV1, ApiError> {
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError {
            status: StatusCode::UNAUTHORIZED,
            code: "agent_id_required",
            message: "x-agent-id is required".to_owned(),
        })?;
    let record = state
        .store
        .agent(agent_id)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError {
            status: StatusCode::FORBIDDEN,
            code: "agent_not_enrolled",
            message: "client identity is not enrolled".to_owned(),
        })?;
    if record.revoked_at.is_some()
        || !record
            .certificate_sha256
            .eq_ignore_ascii_case(&peer.certificate_sha256)
    {
        state.metrics.authentication_failures.inc();
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "agent_identity_rejected",
            message: "client certificate is revoked or does not match enrollment".to_owned(),
        });
    }
    state.metrics.api_requests.inc();
    Ok(record)
}

async fn health(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<&'static str, ApiError> {
    authenticate(&state, &headers, &peer).await?;
    Ok("ok")
}

async fn render_metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<Response, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    if agent.agent_id != "operator" {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "operator_required",
            message: "operator identity is required".to_owned(),
        });
    }
    let body = state
        .metrics
        .render()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0",
        )],
        body,
    )
        .into_response())
}

async fn submit_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<SubmitScanRequestV1>,
) -> Result<Json<SubmitScanResponseV1>, ApiError> {
    require_operator(&state, &headers, &peer).await?;
    request
        .spec
        .validate()
        .map_err(|error| ApiError::bad_request("invalid_scan_spec", error.to_string()))?;
    if request.repositories.len() > MAX_REPOSITORIES_PER_JOB
        || request.repositories.len() as u64 > request.spec.bounds.repository_limit
    {
        return Err(ApiError::bad_request(
            "repository_limit_exceeded",
            format!("a job may contain at most {MAX_REPOSITORIES_PER_JOB} repositories"),
        ));
    }
    let repositories = request
        .repositories
        .iter()
        .map(|repository| repository.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if repositories.len() != request.repositories.len()
        || repositories.iter().any(|repository| {
            repository.is_empty()
                || repository.split_once('/').is_none()
                || repository.contains(char::is_whitespace)
        })
    {
        return Err(ApiError::bad_request(
            "invalid_repository_list",
            "repositories must be unique owner/name identifiers",
        ));
    }
    let job_id = request
        .job_id
        .unwrap_or_else(|| JobId(Uuid::new_v4().to_string()));
    if repositories.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_repository_list",
            "at least one repository is required",
        ));
    }
    let submitted_at = Utc::now();
    let provider_key = ProviderKeyV1::github_repository_analysis(
        request.spec.repository_scope,
        request.spec.credential_profile_id.as_deref(),
    );
    apply_unit(
        &state,
        DurableCommandV1::ConfigureProvider {
            key: provider_key,
            policy: ProviderPolicyV1::github_repository_analysis(),
        },
    )
    .await?;
    let tasks = repositories
        .into_iter()
        .map(|repository| NewRepositoryTaskV1 {
            task_id: TaskId(Uuid::new_v4().to_string()),
            job_id: job_id.clone(),
            repository_id: repository,
            not_before: submitted_at,
            created_at: submitted_at,
        })
        .collect();
    let outcome = state
        .store
        .apply(DurableCommandV1::SubmitJobWithTasks {
            request: SubmitJobV1 {
                job_id: job_id.clone(),
                idempotency_key: request.idempotency_key,
                spec: request.spec,
                submitted_at,
            },
            tasks,
            now: submitted_at,
        })
        .await
        .map_err(|error| ApiError::bad_request("job_submission_failed", error.to_string()))?;
    let (job_id, created) = match outcome {
        DurableOutcomeV1::Submitted(SubmitOutcome::Created(job_id)) => (job_id, true),
        DurableOutcomeV1::Submitted(SubmitOutcome::Existing(job_id)) => (job_id, false),
        _ => return Err(ApiError::internal("unexpected submission outcome")),
    };
    if created {
        state.metrics.jobs_submitted.inc();
    }
    Ok(Json(SubmitScanResponseV1 { job_id, created }))
}

async fn job_status(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<Json<ScanJobV1>, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let job = state
        .store
        .job(JobId(job_id))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "job_not_found",
            message: "job was not found".to_owned(),
        })?;
    authorize_job(&agent, &job)?;
    Ok(Json(job))
}

async fn job_events(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
    Query(query): Query<EventPageQueryV1>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<Json<JobEventPageV1>, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let job_id = JobId(job_id);
    let job = state
        .store
        .job(job_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "job_not_found",
            message: "job was not found".to_owned(),
        })?;
    authorize_job(&agent, &job)?;
    let limit = page_size(query.limit)?;
    let mut events = state
        .store
        .events_for_job(job_id, query.after, limit + 1)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let next_cursor = (events.len() > limit).then(|| events[limit - 1].sequence);
    events.truncate(limit);
    Ok(Json(JobEventPageV1 {
        items: events,
        next_cursor,
    }))
}

async fn job_tasks(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
    Query(query): Query<TaskPageQueryV1>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<Json<RepositoryTaskPageV1>, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let job_id = JobId(job_id);
    let job = state
        .store
        .job(job_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "job_not_found",
            message: "job was not found".to_owned(),
        })?;
    authorize_job(&agent, &job)?;
    let limit = page_size(query.limit)?;
    let mut tasks = state
        .store
        .tasks_for_job(job_id, query.after, limit + 1)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let next_cursor = (tasks.len() > limit).then(|| tasks[limit - 1].repository_id.clone());
    tasks.truncate(limit);
    Ok(Json(RepositoryTaskPageV1 {
        items: tasks,
        next_cursor,
    }))
}

fn page_size(requested: Option<usize>) -> Result<usize, ApiError> {
    let limit = requested.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(ApiError::bad_request(
            "invalid_page_size",
            format!("page size must be between 1 and {MAX_PAGE_SIZE}"),
        ));
    }
    Ok(limit)
}

async fn resume_job(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<StatusCode, ApiError> {
    require_operator(&state, &headers, &peer).await?;
    apply_unit(
        &state,
        DurableCommandV1::ResumeJob {
            job_id: JobId(job_id),
            now: Utc::now(),
        },
    )
    .await
}

async fn cancel_job(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<StatusCode, ApiError> {
    require_operator(&state, &headers, &peer).await?;
    apply_unit(
        &state,
        DurableCommandV1::CancelJob {
            job_id: JobId(job_id),
            now: Utc::now(),
        },
    )
    .await
}

async fn lease_task(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<LeaseRequestV1>,
) -> Result<Json<LeaseResponseV1>, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let job_id = JobId(job_id);
    let job = state
        .store
        .job(job_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "job_not_found",
            message: "job was not found".to_owned(),
        })?;
    authorize_job(&agent, &job)?;
    let lease_seconds = request.lease_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(ApiError::bad_request(
            "invalid_lease_duration",
            format!("lease duration must be 1..={MAX_LEASE_SECONDS} seconds"),
        ));
    }
    let outcome = state
        .store
        .apply(DurableCommandV1::LeaseNextTask {
            job_id,
            agent_id: agent.agent_id,
            lease_id: Uuid::new_v4().to_string(),
            lease_seconds,
            now: Utc::now(),
        })
        .await
        .map_err(|error| ApiError::bad_request("lease_failed", error.to_string()))?;
    let DurableOutcomeV1::Task(task) = outcome else {
        return Err(ApiError::internal("unexpected lease outcome"));
    };
    if task.is_some() {
        state.metrics.tasks_leased.inc();
    }
    Ok(Json(LeaseResponseV1 { task }))
}

async fn heartbeat_task(
    State(state): State<ApiState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<HeartbeatRequestV1>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let lease_seconds = request.lease_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(ApiError::bad_request(
            "invalid_lease_duration",
            format!("lease duration must be 1..={MAX_LEASE_SECONDS} seconds"),
        ));
    }
    let task_id = TaskId(task_id);
    authorize_task(&state, &agent, &task_id).await?;
    apply_unit(
        &state,
        DurableCommandV1::HeartbeatTask {
            task_id,
            agent_id: agent.agent_id,
            lease_id: request.lease_id,
            lease_seconds,
            now: Utc::now(),
        },
    )
    .await
}

fn spawn_lease_reclaimer(store: TursoCoordinatorStore) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(LEASE_RECLAIM_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match store
                .apply(DurableCommandV1::ReclaimExpiredLeases { now: Utc::now() })
                .await
            {
                Ok(DurableOutcomeV1::Tasks(tasks)) if !tasks.is_empty() => {
                    tracing::warn!(
                        reclaimed_tasks = tasks.len(),
                        "reclaimed expired task leases"
                    );
                }
                Ok(DurableOutcomeV1::Tasks(_)) => {}
                Ok(_) => tracing::error!("lease reclaimer received an unexpected outcome"),
                Err(error) => tracing::error!(error = %error, "lease reclaimer failed"),
            }
        }
    });
}

fn spawn_retention_collector(state: ApiState) {
    tokio::spawn(async move {
        run_automatic_retention(&state).await;
        let mut interval = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            run_automatic_retention(&state).await;
        }
    });
}

async fn run_automatic_retention(state: &ApiState) {
    match collect_retention(state, Utc::now()).await {
        Ok(response) => tracing::info!(
            candidates = response.candidates,
            metadata_removed = response.metadata_removed,
            blobs_removed = response.blobs_removed,
            remaining_candidates = response.remaining_candidates,
            events_pruned = response.events_pruned,
            "automatic retention sweep completed"
        ),
        Err(error) => tracing::error!(
            code = error.code,
            error = %error.message,
            "automatic artifact retention sweep failed"
        ),
    }
}

async fn cache_lookup(
    State(state): State<ApiState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<CacheLookupRequestV1>,
) -> Result<Json<CacheLookupResponseV1>, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let task_id = TaskId(task_id);
    let task = state
        .store
        .task(task_id)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "task_not_found",
            message: "task was not found".to_owned(),
        })?;
    let job = state
        .store
        .job(task.job_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::internal("task references a missing job"))?;
    authorize_job(&agent, &job)?;
    validate_task_lease(&task, &agent.agent_id, &request.lease_id)?;
    validate_reuse_fingerprint_for_job(&request.fingerprint, &job)?;

    // Keep metadata and object retention under one read-side lifecycle guard.
    // The collector takes the write side before removing either.
    let _retention_guard = state.artifact_retention.read().await;
    let namespace = cache_namespace(&job)?;
    let Some(artifact) = state
        .store
        .reusable_artifact(namespace, request.fingerprint.clone(), Utc::now())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
    else {
        return Ok(Json(CacheLookupResponseV1 { evidence: None }));
    };
    let secure_namespace =
        SecureNamespaceOwned::from_cache_namespace(&artifact.metadata.key.namespace);
    let digest = artifact.metadata.key.digest.as_str().to_owned();
    let _object_guard = state
        .artifacts
        .lock_object(
            &secure_namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &digest,
        )
        .await
        .map_err(|error| ApiError::internal(format!("locking cached evidence: {error:#}")))?;
    let cache = state.artifacts.clone();
    let key = state.envelope_key.clone();
    let read_namespace = secure_namespace.clone();
    let read_digest = digest.clone();
    let plaintext = tokio::task::spawn_blocking(move || {
        cache.get(
            &read_namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &read_digest,
            &key,
        )
    })
    .await
    .map_err(|error| ApiError::internal(format!("cache read task failed: {error}")))?;
    let plaintext = match plaintext {
        Ok(plaintext) => plaintext,
        Err(error) => {
            tracing::warn!(%error, "invalid encrypted cache object; invalidating metadata");
            invalidate_cached_object(&state, &artifact.metadata.key, &secure_namespace, &digest)
                .await?;
            return Ok(Json(CacheLookupResponseV1 { evidence: None }));
        }
    };
    let evidence = match serde_json::from_slice::<EvidenceBundleV1>(&plaintext) {
        Ok(evidence) if evidence.schema_is_supported() => evidence,
        Ok(_) | Err(_) => {
            tracing::warn!("unsupported cached evidence payload; invalidating metadata");
            invalidate_cached_object(&state, &artifact.metadata.key, &secure_namespace, &digest)
                .await?;
            return Ok(Json(CacheLookupResponseV1 { evidence: None }));
        }
    };
    if validate_reuse_fingerprint(&request.fingerprint, &evidence, &job).is_err() {
        tracing::warn!("cached evidence does not match its reuse metadata; invalidating entry");
        invalidate_cached_object(&state, &artifact.metadata.key, &secure_namespace, &digest)
            .await?;
        return Ok(Json(CacheLookupResponseV1 { evidence: None }));
    }
    let evidence = match validate_evidence(&task, &job, evidence) {
        Ok(evidence) => evidence,
        Err(_) => return Ok(Json(CacheLookupResponseV1 { evidence: None })),
    };
    match state
        .store
        .apply(DurableCommandV1::TouchCacheKey {
            key: artifact.metadata.key,
            accessed_at: Utc::now(),
        })
        .await
        .map_err(|error| ApiError::internal(format!("touching cache metadata: {error}")))?
    {
        DurableOutcomeV1::Applied => {}
        _ => return Err(ApiError::internal("unexpected cache touch outcome")),
    }
    Ok(Json(CacheLookupResponseV1 {
        evidence: Some(evidence),
    }))
}

async fn complete_task(
    State(state): State<ApiState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<CompleteTaskRequestV1>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let task_id = TaskId(task_id);
    let task = state
        .store
        .task(task_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "task_not_found",
            message: "task was not found".to_owned(),
        })?;
    let job = state
        .store
        .job(task.job_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::internal("task references a missing job"))?;
    authorize_job(&agent, &job)?;
    let agent_id = agent.agent_id;
    validate_task_lease(&task, &agent_id, &request.lease_id)?;
    let evidence = validate_evidence(&task, &job, request.evidence)?;
    let reuse_fingerprint = request.reuse_fingerprint;
    if let Some(fingerprint) = &reuse_fingerprint {
        validate_reuse_fingerprint(fingerprint, &evidence, &job)?;
    }
    let canonical = serde_json::to_vec(&evidence)
        .map_err(|error| ApiError::internal(format!("serializing evidence: {error}")))?;
    validate_artifact_reference(&request.artifact, &canonical, &job)?;

    let cache_namespace = cache_namespace(&job)?;
    let secure_namespace = secure_namespace(&job)?;
    let cache_key = CacheKeyV1 {
        namespace: cache_namespace,
        digest: request.artifact.digest.clone(),
    };
    let _retention_guard = state.artifact_retention.read().await;
    let _object_guard = state
        .artifacts
        .lock_object(
            &secure_namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            request.artifact.digest.as_str(),
        )
        .await
        .map_err(|error| ApiError::internal(format!("locking evidence object: {error:#}")))?;
    let cache = state.artifacts.clone();
    let key = state.envelope_key.clone();
    let plaintext = canonical.clone();
    let storage_namespace = secure_namespace.clone();
    let stored = tokio::task::spawn_blocking(move || {
        cache.put(
            storage_namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &plaintext,
            &key,
        )
    })
    .await
    .map_err(|error| ApiError::internal(format!("artifact storage task failed: {error}")))?
    .map_err(|error| ApiError::internal(format!("storing encrypted evidence: {error:#}")))?;
    if stored.sha256 != request.artifact.digest.as_str()
        || stored.bytes != request.artifact.stored_bytes
    {
        return Err(ApiError::internal(
            "encrypted cache returned inconsistent artifact metadata",
        ));
    }
    let now = Utc::now();
    let metadata = CacheMetadataV1 {
        schema_version: SCHEMA_VERSION_V1,
        key: cache_key,
        content_kind: CacheContentKindV1::DerivedEvidence,
        content_length: request.artifact.stored_bytes,
        github_blob_sha: None,
        protection: CacheProtectionV1::EnvelopeEncrypted {
            algorithm: "AES-256-GCM".to_owned(),
            wrapping_key_id: stored.key_id.clone(),
        },
        completeness: cache_completeness(&evidence),
        reuse_fingerprint,
        created_at: now,
        last_accessed_at: now,
        retain_until: state
            .retention_policy
            .deadline(CacheContentKindV1::DerivedEvidence, now),
        reference_count: 0,
    };
    let completion = state
        .store
        .apply(DurableCommandV1::CompleteTaskWithArtifact {
            task_id: task_id.clone(),
            agent_id,
            lease_id: request.lease_id,
            result: request.artifact,
            artifact: Box::new(ArtifactRecordV1 {
                job_id: task.job_id,
                task_id,
                metadata,
            }),
            usage: request.usage,
            now: Utc::now(),
        })
        .await;
    match completion {
        Ok(DurableOutcomeV1::Applied) => {}
        Ok(DurableOutcomeV1::QuotaExceeded(resource)) => {
            remove_uncommitted_artifact(&state, &secure_namespace, &stored).await;
            return Err(ApiError {
                status: StatusCode::INSUFFICIENT_STORAGE,
                code: "quota_exhausted",
                message: format!("job quota is exhausted for {resource:?}"),
            });
        }
        Ok(_) => {
            remove_uncommitted_artifact(&state, &secure_namespace, &stored).await;
            return Err(ApiError::internal("unexpected completion outcome"));
        }
        Err(error) => {
            remove_uncommitted_artifact(&state, &secure_namespace, &stored).await;
            return Err(ApiError::bad_request(
                "state_transition_rejected",
                error.to_string(),
            ));
        }
    }
    state.metrics.tasks_completed.inc();
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_uncommitted_artifact(
    state: &ApiState,
    namespace: &SecureNamespaceOwned,
    stored: &crate::secure_cache::StoredObject,
) {
    if !stored.created {
        return;
    }
    let cache = state.artifacts.clone();
    let namespace = namespace.clone();
    let digest = stored.sha256.clone();
    let removed = tokio::task::spawn_blocking(move || {
        cache.remove(
            &namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &digest,
        )
    })
    .await;
    match removed {
        Err(error) => tracing::warn!(%error, "failed to schedule uncommitted artifact cleanup"),
        Ok(Err(error)) => tracing::warn!(%error, "failed to remove uncommitted artifact"),
        Ok(Ok(_)) => {}
    }
}

async fn invalidate_cached_object(
    state: &ApiState,
    cache_key: &CacheKeyV1,
    namespace: &SecureNamespaceOwned,
    digest: &str,
) -> Result<(), ApiError> {
    match state
        .store
        .apply(DurableCommandV1::InvalidateCacheKey {
            key: cache_key.clone(),
            now: Utc::now(),
        })
        .await
        .map_err(|error| ApiError::internal(format!("invalidating cache metadata: {error}")))?
    {
        DurableOutcomeV1::Applied => {}
        _ => return Err(ApiError::internal("unexpected cache invalidation outcome")),
    }
    let cache = state.artifacts.clone();
    let namespace = namespace.clone();
    let digest = digest.to_owned();
    tokio::task::spawn_blocking(move || {
        cache.remove(
            &namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &digest,
        )
    })
    .await
    .map_err(|error| ApiError::internal(format!("cache invalidation task failed: {error}")))?
    .map_err(|error| ApiError::internal(format!("removing invalid cache object: {error:#}")))?;
    Ok(())
}

async fn task_artifact(
    State(state): State<ApiState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<Response, ApiError> {
    require_operator(&state, &headers, &peer).await?;
    let _retention_guard = state.artifact_retention.read().await;
    let artifact = state
        .store
        .artifact(TaskId(task_id))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "artifact_not_found",
            message: "task artifact was not found".to_owned(),
        })?;
    let namespace = SecureNamespaceOwned::from_cache_namespace(&artifact.metadata.key.namespace);
    let digest = artifact.metadata.key.digest.as_str().to_owned();
    let cache = state.artifacts.clone();
    let key = state.envelope_key.clone();
    let body = tokio::task::spawn_blocking(move || {
        cache.get(
            &namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &digest,
            &key,
        )
    })
    .await
    .map_err(|error| ApiError::internal(format!("artifact read task failed: {error}")))?
    .map_err(|error| ApiError::internal(format!("reading encrypted evidence: {error:#}")))?;
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(EVIDENCE_MEDIA_TYPE_V1),
    );
    Ok(response)
}

async fn run_retention(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
) -> Result<Json<RetentionCollectionResponseV1>, ApiError> {
    require_operator(&state, &headers, &peer).await?;
    collect_retention(&state, Utc::now()).await.map(Json)
}

async fn collect_retention(
    state: &ApiState,
    now: DateTime<Utc>,
) -> Result<RetentionCollectionResponseV1, ApiError> {
    state.metrics.retention_runs.inc();
    state
        .metrics
        .retention_last_run_timestamp_seconds
        .set(now.timestamp());
    let result = collect_retention_batch(state, now).await;
    match &result {
        Ok(response) => {
            state.metrics.retention_last_run_succeeded.set(1);
            state
                .metrics
                .retention_metadata_removed
                .inc_by(response.metadata_removed as u64);
            state
                .metrics
                .retention_blobs_removed
                .inc_by(response.blobs_removed as u64);
            state
                .metrics
                .retention_pending_candidates
                .set(response.remaining_candidates as i64);
        }
        Err(_) => {
            state.metrics.retention_failures.inc();
            state.metrics.retention_last_run_succeeded.set(0);
        }
    }
    result
}

async fn collect_retention_batch(
    state: &ApiState,
    now: DateTime<Utc>,
) -> Result<RetentionCollectionResponseV1, ApiError> {
    let _retention_guard = state.artifact_retention.write().await;
    let artifacts = state
        .store
        .artifacts()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let mut candidates = Vec::with_capacity(RETENTION_SWEEP_BATCH);
    let mut candidate_count = 0_usize;
    let mut live_keys = BTreeSet::new();
    for artifact in artifacts {
        if artifact.metadata.content_kind != CacheContentKindV1::DerivedEvidence {
            live_keys.insert(artifact.metadata.key);
        } else if artifact.metadata.is_retention_candidate(now) {
            candidate_count += 1;
            if candidates.len() < RETENTION_SWEEP_BATCH {
                candidates.push(artifact);
            }
        } else {
            live_keys.insert(artifact.metadata.key);
        }
    }
    let mut processed_blobs = BTreeSet::new();
    let mut blobs_removed = 0_usize;
    let mut metadata_removed = 0_usize;

    for artifact in &candidates {
        let key = &artifact.metadata.key;
        if !live_keys.contains(key) && processed_blobs.insert(key.clone()) {
            let namespace = SecureNamespaceOwned::from_cache_namespace(&key.namespace);
            let digest = key.digest.as_str().to_owned();
            let cache = state.artifacts.clone();
            let _object_guard = cache
                .lock_object(
                    &namespace.as_borrowed(),
                    CACHE_CONTENT_KIND_EVIDENCE,
                    &digest,
                )
                .await
                .map_err(|error| {
                    ApiError::internal(format!("locking expired artifact: {error:#}"))
                })?;
            let removed = tokio::task::spawn_blocking(move || {
                cache.remove(
                    &namespace.as_borrowed(),
                    CACHE_CONTENT_KIND_EVIDENCE,
                    &digest,
                )
            })
            .await
            .map_err(|error| ApiError::internal(format!("retention task failed: {error}")))?
            .map_err(|error| ApiError::internal(format!("removing expired artifact: {error:#}")))?;
            blobs_removed += usize::from(removed);
        }
        apply_unit(
            state,
            DurableCommandV1::RemoveExpiredArtifact {
                task_id: artifact.task_id.clone(),
                now,
            },
        )
        .await?;
        metadata_removed += 1;
    }

    let event_retention_days = i64::from(state.retention_policy.derived_evidence_days);
    let event_cutoff = now
        .checked_sub_signed(TimeDelta::days(event_retention_days))
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    let events_pruned = match state
        .store
        .apply(DurableCommandV1::PruneEventsBefore {
            cutoff: event_cutoff,
        })
        .await
        .map_err(|error| ApiError::internal(format!("pruning retained events: {error}")))?
    {
        DurableOutcomeV1::EventsPruned(count) => count,
        _ => return Err(ApiError::internal("unexpected event pruning outcome")),
    };

    Ok(RetentionCollectionResponseV1 {
        candidates: candidate_count,
        metadata_removed,
        blobs_removed,
        remaining_candidates: candidate_count.saturating_sub(metadata_removed),
        events_pruned,
    })
}

#[derive(Clone, Debug)]
enum SecureNamespaceOwned {
    Public,
    Private(String),
}

impl SecureNamespaceOwned {
    fn as_borrowed(&self) -> SecureCacheNamespace<'_> {
        match self {
            Self::Public => SecureCacheNamespace::Public,
            Self::Private(tenant_id) => SecureCacheNamespace::Private { tenant_id },
        }
    }

    fn from_cache_namespace(namespace: &CacheNamespaceV1) -> Self {
        match namespace {
            CacheNamespaceV1::Public => Self::Public,
            CacheNamespaceV1::Private { principal_id } => Self::Private(principal_id.clone()),
        }
    }
}

fn validate_task_lease(
    task: &RepositoryTaskV1,
    agent_id: &str,
    lease_id: &str,
) -> Result<(), ApiError> {
    if task.state == RepositoryTaskStateV1::Succeeded {
        return Ok(());
    }
    let lease = task
        .lease
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("lease_required", "task has no active lease"))?;
    if task.state != RepositoryTaskStateV1::Leased
        || lease.agent_id != agent_id
        || lease.lease_id != lease_id
        || lease.expires_at <= Utc::now()
    {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            code: "lease_rejected",
            message: "task lease is expired or belongs to another agent".to_owned(),
        });
    }
    Ok(())
}

fn validate_evidence(
    task: &RepositoryTaskV1,
    job: &ScanJobV1,
    evidence: EvidenceBundleV1,
) -> Result<EvidenceBundleV1, ApiError> {
    if !evidence.schema_is_supported() {
        return Err(ApiError::bad_request(
            "unsupported_evidence_schema",
            format!(
                "evidence schema {} is not supported",
                evidence.schema_version
            ),
        ));
    }
    let evidence = evidence.normalized();
    if evidence.repositories.len() != 1
        || !evidence.repositories[0]
            .repository
            .eq_ignore_ascii_case(&task.repository_id)
    {
        return Err(ApiError::bad_request(
            "evidence_repository_mismatch",
            "evidence must contain exactly the leased repository",
        ));
    }
    if !evidence
        .target
        .name
        .eq_ignore_ascii_case(&job.spec.target.crate_name)
    {
        return Err(ApiError::bad_request(
            "evidence_target_mismatch",
            "evidence crate does not match the scan target",
        ));
    }
    if job.spec.repository_scope == RepositoryScopeV1::PublicOnly
        && evidence.repositories[0].visibility != RepositoryVisibilityV1::Public
    {
        return Err(ApiError::bad_request(
            "evidence_visibility_mismatch",
            "public-only jobs accept evidence only for confirmed public repositories",
        ));
    }
    let version_requirement =
        semver::VersionReq::parse(&job.spec.target.version_spec).map_err(|error| {
            ApiError::internal(format!("stored version requirement is invalid: {error}"))
        })?;
    if !version_requirement.matches(&evidence.target.version) {
        return Err(ApiError::bad_request(
            "evidence_version_mismatch",
            "evidence target version is outside the scan requirement",
        ));
    }
    Ok(evidence)
}

fn validate_reuse_fingerprint_for_job(
    fingerprint: &ReuseFingerprintV1,
    job: &ScanJobV1,
) -> Result<(), ApiError> {
    if fingerprint.repository_id.trim().is_empty() || fingerprint.tree_sha.trim().is_empty() {
        return Err(ApiError::bad_request(
            "invalid_reuse_fingerprint",
            "reuse fingerprint repository and tree identities are required",
        ));
    }
    if fingerprint.analyzer_version != REPOSITORY_ANALYZER_VERSION
        || fingerprint.evidence_profile_hash != analysis_evidence_profile_hash()
    {
        return Err(ApiError::bad_request(
            "incompatible_reuse_fingerprint",
            "reuse fingerprint analyzer or evidence profile is incompatible",
        ));
    }
    let version = semver::Version::parse(
        job.spec
            .target
            .version_spec
            .strip_prefix('=')
            .ok_or_else(|| ApiError::internal("stored scan target is not exact"))?,
    )
    .map_err(|error| ApiError::internal(format!("stored scan target is invalid: {error}")))?;
    let expected_target = analysis_target_hash(&job.spec.target.crate_name, &version)
        .map_err(|error| ApiError::internal(format!("hashing scan target: {error}")))?;
    if fingerprint.target_hash != expected_target {
        return Err(ApiError::bad_request(
            "reuse_target_mismatch",
            "reuse fingerprint target does not match the job",
        ));
    }
    Ok(())
}

fn validate_reuse_fingerprint(
    fingerprint: &ReuseFingerprintV1,
    evidence: &EvidenceBundleV1,
    job: &ScanJobV1,
) -> Result<(), ApiError> {
    validate_reuse_fingerprint_for_job(fingerprint, job)?;
    let Some(repository) = evidence
        .repositories
        .first()
        .filter(|_| evidence.repositories.len() == 1)
    else {
        return Err(ApiError::bad_request(
            "reuse_evidence_mismatch",
            "reusable evidence must contain exactly one repository",
        ));
    };
    let immutable_tree_matches = repository.explanation.steps.iter().any(|step| {
        step.kind == crate::evidence::ExplanationStepKindV1::ImmutableRevision
            && step.reference.as_ref().is_some_and(|reference| {
                reference.tree_sha.as_deref() == Some(fingerprint.tree_sha.as_str())
            })
    });
    if repository.repository_id.as_deref() != Some(fingerprint.repository_id.as_str())
        || repository.completeness != EvidenceCompletenessV1::Complete
        || repository.explanation.completeness != EvidenceCompletenessV1::Complete
        || !evidence.limitations.is_empty()
        || !immutable_tree_matches
    {
        return Err(ApiError::bad_request(
            "reuse_evidence_mismatch",
            "evidence is incomplete or does not match the immutable reuse fingerprint",
        ));
    }
    Ok(())
}

fn validate_artifact_reference(
    artifact: &ArtifactRefV1,
    canonical: &[u8],
    job: &ScanJobV1,
) -> Result<(), ApiError> {
    if artifact.media_type != EVIDENCE_MEDIA_TYPE_V1 {
        return Err(ApiError::bad_request(
            "unsupported_artifact_media_type",
            format!("artifact media type must be {EVIDENCE_MEDIA_TYPE_V1}"),
        ));
    }
    if canonical.is_empty() || canonical.len() > MAX_EVIDENCE_ARTIFACT_BYTES {
        return Err(ApiError {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "artifact_too_large",
            message: format!("canonical evidence must be 1..={MAX_EVIDENCE_ARTIFACT_BYTES} bytes"),
        });
    }
    let canonical_bytes = canonical.len() as u64;
    if artifact.stored_bytes != canonical_bytes
        || canonical_bytes > job.spec.bounds.artifact_byte_limit
    {
        return Err(ApiError::bad_request(
            "artifact_length_mismatch",
            "artifact length does not match canonical evidence or job bounds",
        ));
    }
    if artifact.digest.as_str() != sha256_hex(canonical) {
        return Err(ApiError::bad_request(
            "artifact_digest_mismatch",
            "artifact SHA-256 does not match canonical evidence",
        ));
    }
    Ok(())
}

fn cache_namespace(job: &ScanJobV1) -> Result<CacheNamespaceV1, ApiError> {
    match job.spec.repository_scope {
        RepositoryScopeV1::PublicOnly => Ok(CacheNamespaceV1::Public),
        RepositoryScopeV1::AllVisible => Ok(CacheNamespaceV1::Private {
            principal_id: job
                .spec
                .credential_profile_id
                .clone()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| ApiError::internal("private job lacks a credential profile"))?,
        }),
    }
}

fn secure_namespace(job: &ScanJobV1) -> Result<SecureNamespaceOwned, ApiError> {
    Ok(SecureNamespaceOwned::from_cache_namespace(
        &cache_namespace(job)?,
    ))
}

fn cache_completeness(evidence: &EvidenceBundleV1) -> CacheCompletenessV1 {
    if evidence
        .repositories
        .iter()
        .all(|repository| repository.completeness == EvidenceCompletenessV1::Complete)
    {
        CacheCompletenessV1::Complete
    } else if evidence
        .repositories
        .iter()
        .all(|repository| repository.completeness == EvidenceCompletenessV1::Unavailable)
    {
        CacheCompletenessV1::Failed
    } else {
        CacheCompletenessV1::Partial
    }
}

async fn fail_task(
    State(state): State<ApiState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<FailTaskRequestV1>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    if request.failure.len() > 4_096 {
        return Err(ApiError::bad_request(
            "failure_too_long",
            "failure text exceeds 4096 bytes",
        ));
    }
    let task_id = TaskId(task_id);
    authorize_task(&state, &agent, &task_id).await?;
    let outcome = state
        .store
        .apply(DurableCommandV1::FailTask {
            task_id,
            agent_id: agent.agent_id,
            lease_id: request.lease_id,
            failure: request.failure,
            retry_at: request.retry_at,
            usage: request.usage,
            now: Utc::now(),
        })
        .await
        .map_err(|error| ApiError::bad_request("state_transition_rejected", error.to_string()))?;
    match outcome {
        DurableOutcomeV1::Applied => {}
        DurableOutcomeV1::QuotaExceeded(resource) => {
            return Err(ApiError {
                status: StatusCode::INSUFFICIENT_STORAGE,
                code: "quota_exhausted",
                message: format!("job quota is exhausted for {resource:?}"),
            });
        }
        _ => return Err(ApiError::internal("unexpected task failure outcome")),
    }
    state.metrics.tasks_failed.inc();
    Ok(StatusCode::NO_CONTENT)
}

async fn configure_provider(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<ConfigureProviderRequestV1>,
) -> Result<StatusCode, ApiError> {
    require_operator(&state, &headers, &peer).await?;
    apply_unit(
        &state,
        DurableCommandV1::ConfigureProvider {
            key: request.key,
            policy: request.policy,
        },
    )
    .await
}

async fn acquire_provider_permit(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<AcquireProviderPermitRequestV1>,
) -> Result<Json<AcquireProviderPermitResponseV1>, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    authorize_provider_key(&agent, &request.key)?;
    let outcome = state
        .store
        .apply(DurableCommandV1::AcquireProviderPermit {
            key: request.key,
            permit_id: request
                .permit_id
                .unwrap_or_else(|| PermitId(Uuid::new_v4().to_string())),
            agent_id: agent.agent_id,
            now: Utc::now(),
        })
        .await
        .map_err(|error| ApiError::bad_request("provider_permit_rejected", error.to_string()))?;
    let DurableOutcomeV1::Permit(decision) = outcome else {
        return Err(ApiError::internal("unexpected provider permit outcome"));
    };
    Ok(Json(AcquireProviderPermitResponseV1 { decision }))
}

async fn finish_provider_permit(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<FinishProviderPermitRequestV1>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    apply_unit(
        &state,
        DurableCommandV1::FinishProviderRequest {
            permit_id: request.permit_id,
            agent_id: agent.agent_id,
            outcome: request.outcome,
            observation: request.observation,
            now: Utc::now(),
        },
    )
    .await
}

async fn require_operator(
    state: &ApiState,
    headers: &HeaderMap,
    peer: &TlsPeerIdentity,
) -> Result<(), ApiError> {
    if authenticate(state, headers, peer).await?.agent_id != "operator" {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            code: "operator_required",
            message: "operator identity is required".to_owned(),
        });
    }
    Ok(())
}

fn authorize_job(agent: &AgentRecordV1, job: &ScanJobV1) -> Result<(), ApiError> {
    if agent.agent_id == "operator" || agent.authorization.allows(&job.spec) {
        return Ok(());
    }
    Err(ApiError {
        status: StatusCode::FORBIDDEN,
        code: "job_scope_forbidden",
        message: "worker is not authorized for this job scope".to_owned(),
    })
}

async fn authorize_task(
    state: &ApiState,
    agent: &AgentRecordV1,
    task_id: &TaskId,
) -> Result<(), ApiError> {
    let task = state
        .store
        .task(task_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "task_not_found",
            message: "task was not found".to_owned(),
        })?;
    let job = state
        .store
        .job(task.job_id)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::internal("task references a missing job"))?;
    authorize_job(agent, &job)
}

fn authorize_provider_key(agent: &AgentRecordV1, key: &ProviderKeyV1) -> Result<(), ApiError> {
    if agent.agent_id == "operator"
        || (key.provider == "github"
            && key.resource == "repository_analysis:public_only"
            && key.principal_id == "public")
        || (key.provider == "github"
            && key.resource == "repository_analysis:all_visible"
            && agent
                .authorization
                .private_credential_profiles
                .contains(&key.principal_id))
    {
        return Ok(());
    }
    Err(ApiError {
        status: StatusCode::FORBIDDEN,
        code: "provider_scope_forbidden",
        message: "worker is not authorized for this provider credential scope".to_owned(),
    })
}

async fn apply_unit(state: &ApiState, command: DurableCommandV1) -> Result<StatusCode, ApiError> {
    match state.store.apply(command).await {
        Ok(DurableOutcomeV1::Applied) => Ok(StatusCode::NO_CONTENT),
        Ok(_) => Err(ApiError::internal("unexpected state outcome")),
        Err(error) => Err(ApiError::bad_request(
            "state_transition_rejected",
            error.to_string(),
        )),
    }
}

pub fn validate_submit_request(request: &SubmitScanRequestV1) -> Result<()> {
    request.spec.validate()?;
    ensure!(
        !request.repositories.is_empty()
            && request.repositories.len() <= MAX_REPOSITORIES_PER_JOB
            && request.repositories.len() as u64 <= request.spec.bounds.repository_limit,
        "repository limit exceeded"
    );
    let repositories = request
        .repositories
        .iter()
        .map(|repository| repository.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    ensure!(
        repositories.len() == request.repositories.len()
            && repositories.iter().all(|repository| {
                repository
                    .split_once('/')
                    .is_some_and(|(owner, name)| !owner.is_empty() && !name.is_empty())
                    && !repository.contains(char::is_whitespace)
            }),
        "repositories must be unique owner/name identifiers"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::coordinator::{
        AgentAuthorizationV1, RepositoryScopeV1, SCHEMA_VERSION_V1, ScanBoundsV1, ScanTargetV1,
    };

    #[test]
    fn validates_commercial_repository_capacity() {
        let mut request = SubmitScanRequestV1 {
            idempotency_key: "one".to_owned(),
            job_id: None,
            spec: ScanSpecV1 {
                schema_version: SCHEMA_VERSION_V1,
                target: ScanTargetV1 {
                    crate_name: "fs2".to_owned(),
                    version_spec: "=0.4.3".to_owned(),
                },
                repository_scope: RepositoryScopeV1::PublicOnly,
                credential_profile_id: None,
                bounds: ScanBoundsV1::default(),
                analyzer_versions: BTreeMap::new(),
            },
            repositories: vec!["example/app".to_owned()],
        };
        assert!(validate_submit_request(&request).is_ok());
        request.spec.target.version_spec = "^0.4".to_owned();
        assert!(validate_submit_request(&request).is_err());
        request.spec.target.version_spec = "=0.4.3".to_owned();
        request.repositories.clear();
        assert!(validate_submit_request(&request).is_err());
    }

    fn test_job(scope: RepositoryScopeV1, profile: Option<&str>) -> ScanJobV1 {
        ScanJobV1 {
            schema_version: SCHEMA_VERSION_V1,
            id: JobId("job-1".to_owned()),
            idempotency_key: "key-1".to_owned(),
            spec: ScanSpecV1 {
                schema_version: SCHEMA_VERSION_V1,
                target: ScanTargetV1 {
                    crate_name: "fs2".to_owned(),
                    version_spec: "=0.4.3".to_owned(),
                },
                repository_scope: scope,
                credential_profile_id: profile.map(str::to_owned),
                bounds: ScanBoundsV1::default(),
                analyzer_versions: BTreeMap::new(),
            },
            state: crate::coordinator::ScanJobStateV1::Running,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            progress: Default::default(),
            quota_usage: Default::default(),
            partial_reasons: BTreeSet::new(),
            failure: None,
        }
    }

    fn test_agent(id: &str, profiles: &[&str]) -> AgentRecordV1 {
        AgentRecordV1 {
            agent_id: id.to_owned(),
            certificate_sha256: "ab".repeat(32),
            enrolled_at: Utc::now(),
            revoked_at: None,
            authorization: AgentAuthorizationV1 {
                private_credential_profiles: profiles
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
            },
        }
    }

    #[test]
    fn private_job_and_provider_authorization_is_profile_bound() {
        let public_only = test_agent("worker", &[]);
        let production = test_agent("worker", &["production"]);
        let private = test_job(RepositoryScopeV1::AllVisible, Some("production"));
        let public = test_job(RepositoryScopeV1::PublicOnly, None);

        assert!(authorize_job(&public_only, &public).is_ok());
        assert_eq!(
            authorize_job(&public_only, &private).unwrap_err().code,
            "job_scope_forbidden"
        );
        assert!(authorize_job(&production, &private).is_ok());

        let key = ProviderKeyV1::github_repository_analysis(
            RepositoryScopeV1::AllVisible,
            Some("production"),
        );
        assert_eq!(
            authorize_provider_key(&public_only, &key).unwrap_err().code,
            "provider_scope_forbidden"
        );
        assert!(authorize_provider_key(&production, &key).is_ok());
    }

    #[test]
    fn operator_is_unrestricted() {
        let operator = test_agent("operator", &[]);
        let private = test_job(RepositoryScopeV1::AllVisible, Some("production"));
        let key = ProviderKeyV1::github_repository_analysis(
            RepositoryScopeV1::AllVisible,
            Some("production"),
        );

        assert!(authorize_job(&operator, &private).is_ok());
        assert!(authorize_provider_key(&operator, &key).is_ok());
    }
}
