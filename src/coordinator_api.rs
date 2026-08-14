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
use tokio::sync::{Mutex, RwLock};
use tokio_rustls::server::TlsStream;
use tower::Layer as _;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::{
    catalog::{
        InventoryNamespaceV1, InventoryObservationEnvelopeV1, InventoryProjectionInputV1,
        InventoryProjectionStore, RepositoryAttemptInputV1, RepositoryRevisionV1,
    },
    coordinator::{
        AgentRecordV1, ArtifactProjectionOutcomeV1, ArtifactRecordV1, ArtifactRefV1,
        CacheContentKindV1, CacheKeyV1, CacheMetadataV1, CacheNamespaceV1, CacheProtectionV1,
        ControlActionV1, ControlCommandV1, ControlResultV1, CredentialBroker, CredentialRequestV1,
        DurableCommandV1, DurableOutcomeV1, EvidenceCompletenessV1 as CacheCompletenessV1,
        FailedAttemptProjectionKeyV1, FailedAttemptProjectionOutcomeV1,
        FailedAttemptProjectionRecordV1, HttpCredentialBroker, InventoryProjectionStateV1,
        JobEventV1, JobId, NewRepositoryTaskV1, PermitDecision, PermitId, ProviderKeyV1,
        ProviderOutcomeClassV1, ProviderPolicyV1, RateLimitObservationV1, RepositoryScopeV1,
        RepositoryTaskStateV1, RepositoryTaskV1, RetentionPolicyV1, ReuseFingerprintV1,
        SCHEMA_VERSION_V1, ScanJobV1, ScanSpecV1, SubmitJobV1, SubmitOutcome, TaskId, TaskUsageV1,
        TursoCoordinatorStore,
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
const MAX_TASK_ATTEMPTS: u32 = 3;
const INITIAL_TASK_RETRY_SECONDS: i64 = 30;
const LEASE_RECLAIM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const RETENTION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const INVENTORY_RECONCILIATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
const RETENTION_SWEEP_BATCH: usize = 256;
const INVENTORY_RECONCILIATION_BATCH: usize = 64;
const OPERATIONAL_RETENTION_DAYS: i64 = 365;
const MAX_EVIDENCE_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_PAGE_SIZE: usize = 250;
const MAX_PAGE_SIZE: usize = 1_000;
const MAX_COMPLETE_REQUEST_BYTES: usize = MAX_EVIDENCE_ARTIFACT_BYTES + 512 * 1024;
const CACHE_CONTENT_KIND_EVIDENCE: &str = "evidence";
pub const DEFAULT_PRIVATE_INVENTORY_ENABLED: bool = false;
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
    /// HTTPS endpoint of the external short-lived credential broker. The
    /// coordinator stores only the endpoint and credential-profile metadata.
    pub credential_broker_endpoint: Option<Url>,
    /// Explicitly allow normalized private repository metadata in the searchable catalog.
    /// Deployments must leave this false unless their storage controls permit it.
    pub private_inventory_enabled: bool,
}

#[derive(Clone)]
struct ApiState {
    store: TursoCoordinatorStore,
    inventory: Arc<dyn InventoryProjectionStore>,
    metrics: CoordinatorMetrics,
    artifacts: SecureBlobCache,
    envelope_key: Arc<EnvelopeKey>,
    retention_policy: RetentionPolicyV1,
    private_inventory_enabled: bool,
    credential_broker: Option<Arc<dyn CredentialBroker>>,
    artifact_retention: Arc<RwLock<()>>,
    inventory_reconciliation_cursor: Arc<Mutex<Option<TaskId>>>,
    failed_attempt_reconciliation_cursor: Arc<Mutex<Option<FailedAttemptProjectionKeyV1>>>,
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

    fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
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
    /// Client retry key for ambiguous lease responses. When supplied, retries
    /// by the same enrolled agent return the same active task.
    #[serde(default)]
    pub lease_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeartbeatRequestV1 {
    pub lease_id: String,
    pub lease_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeferTaskRequestV1 {
    pub lease_id: String,
    pub not_before: DateTime<Utc>,
    pub reason_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TaskCredentialRequestV1 {
    pub lease_id: String,
}

/// Short-lived secret returned only on the authenticated worker listener.
/// Deliberately does not implement `Debug` so routine request tracing cannot
/// print the token.
#[derive(Deserialize, Serialize)]
pub struct TaskCredentialResponseV1 {
    pub schema_version: u16,
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
}

impl TaskCredentialResponseV1 {
    pub fn into_token_and_expiry(mut self) -> (String, DateTime<Utc>) {
        (std::mem::take(&mut self.access_token), self.expires_at)
    }
}

impl Drop for TaskCredentialResponseV1 {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
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
    /// Individual-request permits are bound to the worker's current task
    /// lease. Omitted only by the legacy repository-attempt admission path.
    #[serde(default)]
    pub task_id: Option<TaskId>,
    #[serde(default)]
    pub lease_id: Option<String>,
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
    pub inventory_attempts_pruned: usize,
    pub jobs_pruned: usize,
    pub tasks_pruned: usize,
    pub quotas_pruned: usize,
    pub reservations_pruned: usize,
    pub idempotency_keys_pruned: usize,
    pub failed_attempt_projections_pruned: usize,
    pub schedules_pruned: usize,
    pub schedule_revisions_pruned: usize,
    pub schedule_occurrences_pruned: usize,
    pub schedule_materializations_pruned: usize,
    pub repository_sets_pruned: usize,
    pub credential_profiles_pruned: usize,
    pub service_tokens_pruned: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailTaskRequestV1 {
    pub lease_id: String,
    pub failure: String,
    #[serde(default)]
    pub failure_class: TaskFailureClassV1,
    #[serde(default)]
    pub usage: TaskUsageV1,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailureClassV1 {
    ProviderTransient,
    ProviderRateLimited,
    ProviderAuthorization,
    RepositoryNotFound,
    #[default]
    AnalysisTransient,
    AnalysisPermanent,
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
    inventory: Arc<dyn InventoryProjectionStore>,
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
    let credential_broker = config
        .credential_broker_endpoint
        .map(|endpoint| {
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("building credential-broker HTTP client")?;
            let broker = HttpCredentialBroker::new(client, endpoint)
                .context("configuring credential broker")?;
            Ok::<Arc<dyn CredentialBroker>, anyhow::Error>(Arc::new(broker))
        })
        .transpose()?;
    let state = ApiState {
        store,
        inventory,
        metrics,
        artifacts: SecureBlobCache::new(config.artifact_cache_directory),
        envelope_key,
        retention_policy: config.retention_policy,
        private_inventory_enabled: config.private_inventory_enabled,
        credential_broker,
        artifact_retention: Arc::new(RwLock::new(())),
        inventory_reconciliation_cursor: Arc::new(Mutex::new(None)),
        failed_attempt_reconciliation_cursor: Arc::new(Mutex::new(None)),
    };
    spawn_lease_reclaimer(state.store.clone());
    spawn_retention_collector(state.clone());
    spawn_inventory_reconciler(state.clone());
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
        .route("/v1/tasks/lease", post(lease_authorized_task))
        .route("/v1/tasks/{task_id}/heartbeat", post(heartbeat_task))
        .route("/v1/tasks/{task_id}/defer", post(defer_task))
        .route(
            "/v1/tasks/{task_id}/credential",
            post(issue_task_credential),
        )
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
    for resource in ["core", "search"] {
        apply_unit(
            &state,
            DurableCommandV1::ConfigureProvider {
                key: ProviderKeyV1::github_request(
                    request.spec.repository_scope,
                    request.spec.credential_profile_id.as_deref(),
                    resource,
                ),
                policy: ProviderPolicyV1::github_requests(),
            },
        )
        .await?;
    }
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
    let lease_id = request
        .lease_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_lease_request_id(&lease_id)?;
    let leased_at = Utc::now();
    let outcome = state
        .store
        .apply(DurableCommandV1::LeaseNextTask {
            job_id,
            agent_id: agent.agent_id,
            lease_id,
            lease_seconds,
            now: leased_at,
        })
        .await
        .map_err(|error| ApiError::bad_request("lease_failed", error.to_string()))?;
    let DurableOutcomeV1::Task(task) = outcome else {
        return Err(ApiError::internal("unexpected lease outcome"));
    };
    if task.as_ref().is_some_and(|task| {
        task.lease
            .as_ref()
            .is_some_and(|lease| lease.acquired_at == leased_at)
    }) {
        state.metrics.tasks_leased.inc();
    }
    Ok(Json(LeaseResponseV1 { task }))
}

/// Lease the next ready task across every running job the enrolled worker may
/// access. Authorization is applied during selection so private job existence
/// is never disclosed by an empty or successful response.
async fn lease_authorized_task(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<LeaseRequestV1>,
) -> Result<Json<LeaseResponseV1>, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let lease_seconds = request.lease_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(ApiError::bad_request(
            "invalid_lease_duration",
            format!("lease duration must be 1..={MAX_LEASE_SECONDS} seconds"),
        ));
    }
    let lease_id = request
        .lease_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_lease_request_id(&lease_id)?;
    let leased_at = Utc::now();
    let outcome = state
        .store
        .apply(DurableCommandV1::LeaseNextAuthorizedTask {
            authorization: agent.authorization,
            agent_id: agent.agent_id,
            lease_id,
            lease_seconds,
            now: leased_at,
        })
        .await
        .map_err(|error| ApiError::bad_request("lease_failed", error.to_string()))?;
    let DurableOutcomeV1::Task(task) = outcome else {
        return Err(ApiError::internal("unexpected global lease outcome"));
    };
    if task.as_ref().is_some_and(|task| {
        task.lease
            .as_ref()
            .is_some_and(|lease| lease.acquired_at == leased_at)
    }) {
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

async fn defer_task(
    State(state): State<ApiState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<DeferTaskRequestV1>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate(&state, &headers, &peer).await?;
    let task_id = TaskId(task_id);
    authorize_task(&state, &agent, &task_id).await?;
    let provider_deferred = request.reason_code.starts_with("github_");
    let result = apply_unit(
        &state,
        DurableCommandV1::DeferTask {
            task_id,
            agent_id: agent.agent_id,
            lease_id: request.lease_id,
            not_before: request.not_before,
            reason_code: request.reason_code,
            now: Utc::now(),
        },
    )
    .await;
    if result.is_ok() && provider_deferred {
        state.metrics.provider_deferrals.inc();
    }
    result
}

async fn issue_task_credential(
    State(state): State<ApiState>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    Extension(peer): Extension<TlsPeerIdentity>,
    Json(request): Json<TaskCredentialRequestV1>,
) -> Result<Json<TaskCredentialResponseV1>, ApiError> {
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
    if job.spec.repository_scope != RepositoryScopeV1::AllVisible {
        return Err(ApiError::bad_request(
            "credential_not_required",
            "public-only tasks do not receive brokered credentials",
        ));
    }
    let profile_id = job
        .spec
        .credential_profile_id
        .as_deref()
        .ok_or_else(|| ApiError::internal("private job lacks a credential profile"))?;
    let now = Utc::now();
    let profile = state
        .store
        .credential_profile(profile_id)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| {
            state.metrics.credential_broker_failures.inc();
            ApiError::unavailable(
                "credential_profile_unavailable",
                "the task credential profile is not configured",
            )
        })?;
    if !profile.enabled || profile.provider != "github" || profile.provider_host != "api.github.com"
    {
        state.metrics.credential_broker_failures.inc();
        return Err(ApiError::unavailable(
            "credential_profile_unavailable",
            "the task credential profile is disabled or incompatible",
        ));
    }
    profile.validate(now).map_err(|_| {
        state.metrics.credential_broker_failures.inc();
        ApiError::unavailable(
            "credential_profile_unavailable",
            "the task credential profile is invalid or expired",
        )
    })?;
    let broker = state.credential_broker.as_ref().ok_or_else(|| {
        state.metrics.credential_broker_failures.inc();
        ApiError::unavailable(
            "credential_broker_unavailable",
            "private tasks require a configured credential broker",
        )
    })?;
    let not_after = task
        .lease
        .as_ref()
        .expect("the active lease was validated")
        .expires_at;
    let credential = broker
        .issue(
            CredentialRequestV1::for_profile(&profile, agent.agent_id.clone(), not_after),
            now,
        )
        .await
        .map_err(|_| {
            state.metrics.credential_broker_failures.inc();
            ApiError::unavailable(
                "credential_broker_unavailable",
                "the credential broker could not issue a task credential",
            )
        })?;
    let current_task = state
        .store
        .task(task.id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::internal("credential task disappeared"))?;
    validate_task_lease(&current_task, &agent.agent_id, &request.lease_id)?;
    if credential.expires_at <= Utc::now() {
        state.metrics.credential_broker_failures.inc();
        return Err(ApiError::unavailable(
            "credential_broker_unavailable",
            "the credential broker returned an expired task credential",
        ));
    }
    Ok(Json(TaskCredentialResponseV1 {
        schema_version: 1,
        access_token: credential.expose_token().to_owned(),
        expires_at: credential.expires_at,
    }))
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

fn spawn_inventory_reconciler(state: ApiState) {
    tokio::spawn(async move {
        run_inventory_reconciliation(&state).await;
        let mut interval = tokio::time::interval(INVENTORY_RECONCILIATION_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            run_inventory_reconciliation(&state).await;
        }
    });
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct InventoryReconciliationSummary {
    candidates: usize,
    projected: usize,
    private_skipped: usize,
    unresolved_aliases: usize,
    expired_skipped: usize,
    failed: usize,
}

async fn run_inventory_reconciliation(state: &ApiState) {
    match reconcile_inventory_batch(state).await {
        Ok(summary) if summary.projected > 0 || summary.failed > 0 => tracing::info!(
            candidates = summary.candidates,
            projected = summary.projected,
            private_skipped = summary.private_skipped,
            unresolved_aliases = summary.unresolved_aliases,
            expired_skipped = summary.expired_skipped,
            failed = summary.failed,
            "inventory projection reconciliation batch completed"
        ),
        Ok(summary) if summary.private_skipped > 0 => tracing::debug!(
            diagnostic_code = "private_inventory_reconciliation_skipped",
            private_skipped = summary.private_skipped,
            "private evidence remains outside the searchable inventory by policy"
        ),
        Ok(summary) if summary.unresolved_aliases > 0 => tracing::debug!(
            unresolved_aliases = summary.unresolved_aliases,
            "failed attempts remain pending until their stable repository aliases are observed"
        ),
        Ok(_) => {}
        Err(error) => tracing::error!(
            diagnostic_code = "inventory_projection_reconciliation_unavailable",
            error = %error,
            "inventory projection reconciliation could not enumerate artifacts"
        ),
    }
}

async fn reconcile_inventory_batch(state: &ApiState) -> Result<InventoryReconciliationSummary> {
    let cursor = state.inventory_reconciliation_cursor.lock().await.clone();
    let artifacts = state
        .store
        .pending_artifacts_page(cursor, INVENTORY_RECONCILIATION_BATCH)
        .await
        .context("enumerating pending artifacts for inventory reconciliation")?;
    *state.inventory_reconciliation_cursor.lock().await =
        artifacts.last().map(|artifact| artifact.task_id.clone());

    let mut summary = InventoryReconciliationSummary {
        candidates: artifacts.len(),
        ..InventoryReconciliationSummary::default()
    };
    for artifact in artifacts {
        let task_id = artifact.task_id.clone();
        let artifact_digest = artifact.metadata.key.digest.clone();
        match reconcile_inventory_artifact(state, artifact).await {
            Ok(InventoryReconciliationOutcome::Projected) => summary.projected += 1,
            Ok(InventoryReconciliationOutcome::PrivateDisabled) => {
                summary.private_skipped += 1;
            }
            Ok(InventoryReconciliationOutcome::RepositoryUnknown) => {
                summary.failed += 1;
                tracing::warn!(
                    diagnostic_code = "inventory_projection_repository_identity_missing",
                    task_id = %task_id.0,
                    artifact_digest = %artifact_digest.as_str(),
                    "completed evidence remains pending because its repository identity could not be resolved"
                );
            }
            Ok(InventoryReconciliationOutcome::Expired) => summary.expired_skipped += 1,
            Err(error) => {
                summary.failed += 1;
                tracing::warn!(
                    diagnostic_code = "inventory_projection_reconciliation_failed",
                    task_id = %task_id.0,
                    artifact_digest = %artifact_digest.as_str(),
                    error = %error,
                    "completed evidence remains pending inventory projection"
                );
            }
        }
    }
    let failure_cursor = state
        .failed_attempt_reconciliation_cursor
        .lock()
        .await
        .clone();
    let failed_attempts = state
        .store
        .pending_failed_attempt_projections_page(failure_cursor, INVENTORY_RECONCILIATION_BATCH)
        .await
        .context("enumerating pending failed attempts for inventory reconciliation")?;
    *state.failed_attempt_reconciliation_cursor.lock().await =
        failed_attempts.last().map(|record| record.key.clone());
    summary.candidates += failed_attempts.len();
    for record in failed_attempts {
        let key = record.key.clone();
        match reconcile_failed_attempt(state, record).await {
            Ok(InventoryReconciliationOutcome::Projected) => summary.projected += 1,
            Ok(InventoryReconciliationOutcome::PrivateDisabled) => {
                summary.private_skipped += 1;
            }
            Ok(InventoryReconciliationOutcome::RepositoryUnknown) => {
                summary.unresolved_aliases += 1;
            }
            Ok(InventoryReconciliationOutcome::Expired) => summary.expired_skipped += 1,
            Err(error) => {
                summary.failed += 1;
                tracing::warn!(
                    diagnostic_code = "failed_attempt_inventory_reconciliation_failed",
                    task_id = %key.task_id.0,
                    task_attempt = key.task_attempt,
                    error = %error,
                    "failed attempt remains pending inventory projection"
                );
            }
        }
    }
    if summary.failed > 0 {
        state
            .metrics
            .inventory_projection_failures
            .inc_by(summary.failed as u64);
    }
    if let Ok(watermark) = state.inventory.watermark().await {
        state
            .metrics
            .inventory_watermark
            .set(i64::try_from(watermark).unwrap_or(i64::MAX));
    }
    Ok(summary)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryReconciliationOutcome {
    Projected,
    PrivateDisabled,
    RepositoryUnknown,
    Expired,
}

async fn reconcile_inventory_artifact(
    state: &ApiState,
    artifact: ArtifactRecordV1,
) -> Result<InventoryReconciliationOutcome> {
    let Some(artifact) = state
        .store
        .artifact(artifact.task_id.clone())
        .await
        .context("refreshing inventory artifact metadata")?
    else {
        return Ok(InventoryReconciliationOutcome::Projected);
    };
    if matches!(
        artifact.inventory_projection,
        InventoryProjectionStateV1::Projected { .. }
    ) {
        return Ok(InventoryReconciliationOutcome::Projected);
    }
    if artifact.metadata.is_retention_candidate(Utc::now()) {
        return Ok(InventoryReconciliationOutcome::Expired);
    }
    if !inventory_projection_enabled(
        state.private_inventory_enabled,
        &artifact.metadata.key.namespace,
    ) {
        return Ok(InventoryReconciliationOutcome::PrivateDisabled);
    }
    let task = state
        .store
        .task(artifact.task_id.clone())
        .await
        .context("loading inventory task")?
        .context("inventory artifact references a missing task")?;
    let job = state
        .store
        .job(artifact.job_id.clone())
        .await
        .context("loading inventory job")?
        .context("inventory artifact references a missing job")?;
    let artifact_ref = task
        .result
        .clone()
        .context("inventory artifact task has no durable result")?;
    ensure!(
        artifact_ref.digest == artifact.metadata.key.digest
            && artifact_ref.stored_bytes == artifact.metadata.content_length,
        "inventory artifact result no longer matches its metadata"
    );

    let namespace = SecureNamespaceOwned::from_cache_namespace(&artifact.metadata.key.namespace);
    let digest = artifact.metadata.key.digest.as_str().to_owned();
    let cache = state.artifacts.clone();
    let key = state.envelope_key.clone();
    let plaintext = {
        let _retention_guard = state.artifact_retention.read().await;
        tokio::task::spawn_blocking(move || {
            cache.get(
                &namespace.as_borrowed(),
                CACHE_CONTENT_KIND_EVIDENCE,
                &digest,
                &key,
            )
        })
        .await
        .context("inventory artifact read task failed")?
        .context("reading encrypted inventory evidence")?
    };
    let evidence = serde_json::from_slice::<EvidenceBundleV1>(&plaintext)
        .context("deserializing inventory evidence")?;
    let evidence = validate_evidence(&task, &job, evidence)
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
    let canonical = serde_json::to_vec(&evidence).context("serializing reconciled evidence")?;
    validate_artifact_reference(&artifact_ref, &canonical, &job)
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
    let projection = inventory_projection(
        &task,
        &job,
        artifact_ref,
        evidence,
        artifact.metadata.reuse_fingerprint.as_ref(),
        artifact.metadata.created_at,
    )
    .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
    project_and_mark_inventory(state, &artifact, projection).await?;
    Ok(InventoryReconciliationOutcome::Projected)
}

async fn reconcile_failed_attempt(
    state: &ApiState,
    record: FailedAttemptProjectionRecordV1,
) -> Result<InventoryReconciliationOutcome> {
    if !inventory_projection_enabled(state.private_inventory_enabled, &record.namespace) {
        return Ok(InventoryReconciliationOutcome::PrivateDisabled);
    }
    let namespace = match &record.namespace {
        CacheNamespaceV1::Public => InventoryNamespaceV1::Public,
        CacheNamespaceV1::Private { principal_id } => InventoryNamespaceV1::Private {
            credential_profile_id: principal_id.clone(),
        },
    };
    let Some(repository) = state
        .inventory
        .repository_for_alias(&namespace, &record.normalized_repository_alias)
        .await
        .map_err(|error| anyhow::anyhow!("resolving failed-attempt repository alias: {error}"))?
    else {
        return Ok(InventoryReconciliationOutcome::RepositoryUnknown);
    };
    ensure!(
        repository.key.namespace == namespace,
        "repository alias escaped its inventory namespace"
    );
    let projection = InventoryProjectionInputV1::FailedAttempt(RepositoryAttemptInputV1 {
        schema_version: crate::catalog::CATALOG_SCHEMA_VERSION_V1,
        namespace,
        job_id: record.job_id.clone(),
        task_id: record.key.task_id.clone(),
        task_attempt: record.key.task_attempt,
        repository_id: repository.key.repository_id,
        repository_full_name: repository.full_name,
        visibility: repository.visibility,
        revision: None,
        completed_at: record.completed_at,
        failure_code: record.failure_code.clone(),
        failure_message: record.failure_message.clone(),
    });
    state
        .inventory
        .project(projection)
        .await
        .map_err(|error| anyhow::anyhow!("projecting failed inventory attempt: {error}"))?;
    match state
        .store
        .apply(DurableCommandV1::MarkFailedAttemptProjected {
            key: record.key,
            projection_digest: record.projection_digest,
            now: Utc::now(),
        })
        .await
        .context("marking failed-attempt inventory projection")?
    {
        DurableOutcomeV1::FailedAttemptProjection(
            FailedAttemptProjectionOutcomeV1::Marked
            | FailedAttemptProjectionOutcomeV1::AlreadyProjected,
        ) => Ok(InventoryReconciliationOutcome::Projected),
        _ => Err(anyhow::anyhow!(
            "unexpected failed-attempt projection marker outcome"
        )),
    }
}

fn inventory_projection_enabled(
    private_inventory_enabled: bool,
    namespace: &CacheNamespaceV1,
) -> bool {
    matches!(namespace, CacheNamespaceV1::Public) || private_inventory_enabled
}

async fn project_and_mark_inventory(
    state: &ApiState,
    artifact: &ArtifactRecordV1,
    projection: InventoryProjectionInputV1,
) -> Result<()> {
    state
        .inventory
        .project(projection)
        .await
        .map_err(|error| anyhow::anyhow!("projecting inventory evidence: {error}"))?;
    match state
        .store
        .apply(DurableCommandV1::MarkArtifactProjected {
            task_id: artifact.task_id.clone(),
            artifact_digest: artifact.metadata.key.digest.clone(),
            now: Utc::now(),
        })
        .await
        .context("marking inventory artifact projected")?
    {
        DurableOutcomeV1::ArtifactProjection(
            ArtifactProjectionOutcomeV1::Marked | ArtifactProjectionOutcomeV1::AlreadyProjected,
        ) => Ok(()),
        _ => Err(anyhow::anyhow!(
            "unexpected inventory projection marker outcome"
        )),
    }
}

async fn run_automatic_retention(state: &ApiState) {
    match collect_retention(state, Utc::now()).await {
        Ok(response) => tracing::info!(
            candidates = response.candidates,
            metadata_removed = response.metadata_removed,
            blobs_removed = response.blobs_removed,
            remaining_candidates = response.remaining_candidates,
            events_pruned = response.events_pruned,
            inventory_attempts_pruned = response.inventory_attempts_pruned,
            jobs_pruned = response.jobs_pruned,
            tasks_pruned = response.tasks_pruned,
            failed_attempt_projections_pruned = response.failed_attempt_projections_pruned,
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
        reuse_fingerprint: reuse_fingerprint.clone(),
        created_at: now,
        last_accessed_at: now,
        retain_until: state
            .retention_policy
            .deadline(CacheContentKindV1::DerivedEvidence, now),
        reference_count: 0,
    };
    let artifact_ref = request.artifact.clone();
    let artifact_record = ArtifactRecordV1 {
        job_id: task.job_id.clone(),
        task_id: task_id.clone(),
        metadata,
        inventory_projection: InventoryProjectionStateV1::Pending,
    };
    let completion = state
        .store
        .apply(DurableCommandV1::CompleteTaskWithArtifact {
            task_id: task_id.clone(),
            agent_id,
            lease_id: request.lease_id,
            result: request.artifact,
            artifact: Box::new(artifact_record.clone()),
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
    drop(_object_guard);
    drop(_retention_guard);
    if !inventory_projection_enabled(
        state.private_inventory_enabled,
        &artifact_record.metadata.key.namespace,
    ) {
        tracing::info!(
            diagnostic_code = "private_inventory_projection_disabled",
            task_id = %task_id.0,
            artifact_digest = %artifact_ref.digest.as_str(),
            "private evidence completed durably and remains outside the searchable inventory"
        );
    } else {
        let projection = inventory_projection(
            &task,
            &job,
            artifact_ref,
            evidence,
            reuse_fingerprint.as_ref(),
            now,
        )
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message));
        let projected = match projection {
            Ok(projection) => {
                project_and_mark_inventory(&state, &artifact_record, projection).await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = projected {
            tracing::warn!(
                diagnostic_code = "inventory_projection_deferred",
                task_id = %task_id.0,
                artifact_digest = %artifact_record.metadata.key.digest.as_str(),
                error = %error,
                "task completed durably; inventory projection remains pending"
            );
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
    let event_retention_days = i64::from(state.retention_policy.derived_evidence_days);
    let event_cutoff = now
        .checked_sub_signed(TimeDelta::days(event_retention_days))
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    // Searchable private metadata must disappear before its encrypted source
    // or authorization metadata can be removed. This operation is durable and
    // idempotent, so a later blob failure remains safe to retry.
    let inventory_attempts_pruned = state
        .inventory
        .retain_since(event_cutoff)
        .await
        .map_err(|error| ApiError::internal(format!("pruning inventory projection: {error}")))?;
    let failed_attempt_projections_pruned = match state
        .store
        .apply(DurableCommandV1::PruneFailedAttemptProjectionsBefore {
            cutoff: event_cutoff,
        })
        .await
        .map_err(|error| {
            ApiError::internal(format!(
                "pruning failed-attempt projection records: {error}"
            ))
        })? {
        DurableOutcomeV1::FailedAttemptProjectionsPruned(count) => count,
        _ => {
            return Err(ApiError::internal(
                "unexpected failed-attempt projection retention outcome",
            ));
        }
    };
    let page = state
        .store
        .expired_artifacts_page(now, RETENTION_SWEEP_BATCH)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let candidate_count = page.total_candidates;
    let mut processed_blobs = BTreeSet::new();
    let mut blobs_removed = 0_usize;
    let mut metadata_removed = 0_usize;

    for artifact in &page.candidates {
        let key = &artifact.metadata.key;
        state
            .inventory
            .remove_artifact_projection(&artifact.task_id, &key.digest)
            .await
            .map_err(|error| {
                ApiError::internal(format!(
                    "removing artifact inventory projection before retention: {error}"
                ))
            })?;
        if page.removable_blob_keys.contains(key) && processed_blobs.insert(key.clone()) {
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
    let operational_cutoff = now
        .checked_sub_signed(TimeDelta::days(OPERATIONAL_RETENTION_DAYS))
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    let control_pruned = state
        .store
        .apply_control(ControlCommandV1 {
            schema_version: SCHEMA_VERSION_V1,
            command_id: format!(
                "retention-control-{}",
                operational_cutoff.timestamp_micros()
            ),
            expected_generation: None,
            issued_at: now,
            action: ControlActionV1::PruneBefore {
                cutoff: operational_cutoff,
            },
        })
        .await
        .map_err(|error| ApiError::internal(format!("pruning control history: {error}")))?;
    let ControlResultV1::ControlHistoryPruned {
        summary: control_pruned,
    } = control_pruned.result
    else {
        return Err(ApiError::internal(
            "unexpected control-history pruning outcome",
        ));
    };
    let runs_pruned = match state
        .store
        .apply(DurableCommandV1::PruneTerminalRunsBefore {
            cutoff: operational_cutoff,
        })
        .await
        .map_err(|error| ApiError::internal(format!("pruning terminal runs: {error}")))?
    {
        DurableOutcomeV1::RunsPruned(summary) => summary,
        _ => return Err(ApiError::internal("unexpected run pruning outcome")),
    };

    Ok(RetentionCollectionResponseV1 {
        candidates: candidate_count,
        metadata_removed,
        blobs_removed,
        remaining_candidates: candidate_count.saturating_sub(metadata_removed),
        events_pruned: events_pruned.saturating_add(runs_pruned.events),
        inventory_attempts_pruned,
        jobs_pruned: runs_pruned.jobs,
        tasks_pruned: runs_pruned.tasks,
        quotas_pruned: runs_pruned.quotas,
        reservations_pruned: runs_pruned.reservations,
        idempotency_keys_pruned: runs_pruned.idempotency_keys,
        failed_attempt_projections_pruned,
        schedules_pruned: control_pruned.schedules,
        schedule_revisions_pruned: control_pruned.revisions,
        schedule_occurrences_pruned: control_pruned.occurrences,
        schedule_materializations_pruned: control_pruned.materializations,
        repository_sets_pruned: control_pruned.repository_sets,
        credential_profiles_pruned: control_pruned.credential_profiles,
        service_tokens_pruned: control_pruned.service_tokens,
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

fn inventory_projection(
    task: &RepositoryTaskV1,
    job: &ScanJobV1,
    artifact: ArtifactRefV1,
    evidence: EvidenceBundleV1,
    reuse_fingerprint: Option<&ReuseFingerprintV1>,
    completed_at: DateTime<Utc>,
) -> Result<InventoryProjectionInputV1, ApiError> {
    let repository = evidence
        .repositories
        .first()
        .ok_or_else(|| ApiError::internal("validated evidence has no repository"))?;
    let immutable = repository
        .explanation
        .steps
        .iter()
        .filter_map(|step| step.reference.as_ref())
        .find(|reference| reference.commit_sha.is_some() && reference.tree_sha.is_some())
        .ok_or_else(|| {
            ApiError::bad_request(
                "immutable_revision_required",
                "inventory evidence must identify its immutable commit and tree",
            )
        })?;
    let repository_id = repository
        .repository_id
        .as_deref()
        .or_else(|| reuse_fingerprint.map(|fingerprint| fingerprint.repository_id.as_str()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::bad_request(
                "repository_id_required",
                "inventory evidence must contain the stable repository ID",
            )
        })?
        .to_owned();
    let namespace = inventory_namespace(job)?;
    let analyzer_profile = serde_json::to_vec(&(
        "inventory-analyzer-profile-v1",
        &job.spec.analyzer_versions,
        reuse_fingerprint,
    ))
    .map_err(|error| ApiError::internal(format!("serializing analyzer profile: {error}")))?;
    Ok(InventoryProjectionInputV1::Observation(
        InventoryObservationEnvelopeV1 {
            schema_version: crate::catalog::CATALOG_SCHEMA_VERSION_V1,
            namespace,
            job_id: task.job_id.clone(),
            task_id: task.id.clone(),
            task_attempt: task.attempt,
            artifact,
            repository_id,
            revision: RepositoryRevisionV1 {
                commit_sha: immutable
                    .commit_sha
                    .clone()
                    .expect("immutable reference commit was checked"),
                tree_sha: immutable
                    .tree_sha
                    .clone()
                    .expect("immutable reference tree was checked"),
                analyzer_profile_digest: sha256_hex(&analyzer_profile),
            },
            target_selector: job.spec.target.version_spec.clone(),
            completed_at,
            evidence,
        },
    ))
}

fn inventory_namespace(job: &ScanJobV1) -> Result<InventoryNamespaceV1, ApiError> {
    match job.spec.repository_scope {
        RepositoryScopeV1::PublicOnly => Ok(InventoryNamespaceV1::Public),
        RepositoryScopeV1::AllVisible => Ok(InventoryNamespaceV1::Private {
            credential_profile_id: job.spec.credential_profile_id.clone().ok_or_else(|| {
                ApiError::internal("private job is missing its credential profile")
            })?,
        }),
    }
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
    let task = state
        .store
        .task(task_id.clone())
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::internal("authorized task disappeared"))?;
    let now = Utc::now();
    let retry_at = task_retry_at(request.failure_class, task.attempt, now);
    let outcome = state
        .store
        .apply(DurableCommandV1::FailTask {
            task_id,
            agent_id: agent.agent_id,
            lease_id: request.lease_id,
            failure: request.failure,
            retry_at,
            usage: request.usage,
            now,
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

fn task_retry_at(
    failure_class: TaskFailureClassV1,
    attempt: u32,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if attempt >= MAX_TASK_ATTEMPTS
        || matches!(
            failure_class,
            TaskFailureClassV1::ProviderAuthorization
                | TaskFailureClassV1::RepositoryNotFound
                | TaskFailureClassV1::AnalysisPermanent
        )
    {
        return None;
    }
    let exponent = attempt.saturating_sub(1).min(3);
    let delay = INITIAL_TASK_RETRY_SECONDS.saturating_mul(1_i64 << exponent);
    now.checked_add_signed(TimeDelta::seconds(delay))
        .or(Some(DateTime::<Utc>::MAX_UTC))
}

fn validate_lease_request_id(lease_id: &str) -> Result<(), ApiError> {
    if lease_id.is_empty()
        || lease_id.len() > 256
        || !lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ApiError::bad_request(
            "invalid_lease_id",
            "lease_id contains unsupported characters",
        ));
    }
    Ok(())
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
    match (&request.task_id, &request.lease_id) {
        (Some(task_id), Some(lease_id)) => {
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
            validate_task_lease(&task, &agent.agent_id, lease_id)?;
            let expected = ProviderKeyV1::github_request(
                job.spec.repository_scope,
                job.spec.credential_profile_id.as_deref(),
                request.key.resource.rsplit(':').next().unwrap_or("other"),
            );
            if request.key != expected {
                return Err(ApiError::bad_request(
                    "provider_scope_mismatch",
                    "provider request scope does not match the leased task",
                ));
            }
        }
        (None, None) if !request.key.resource.starts_with("request:") => {}
        (None, None) => {
            return Err(ApiError::bad_request(
                "permit_lease_required",
                "individual provider requests require a live task lease",
            ));
        }
        _ => {
            return Err(ApiError::bad_request(
                "invalid_permit_lease",
                "task_id and lease_id must be supplied together",
            ));
        }
    }
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
            && (key.resource == "repository_analysis:public_only"
                || key.resource.starts_with("request:public_only:"))
            && key.principal_id == "public")
        || (key.provider == "github"
            && (key.resource == "repository_analysis:all_visible"
                || key.resource.starts_with("request:all_visible:"))
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
    use std::{collections::BTreeMap, sync::Arc};

    use semver::Version;

    use super::*;
    use crate::{
        cargo_evidence::{PackageIdentityV1, RecordedRelation},
        catalog::{
            InMemoryInventoryStore, InventoryAccessV1, InventoryFreshnessV1,
            InventoryPageRequestV1, InventoryQueryV1,
        },
        coordinator::{
            AgentAuthorizationV1, ArtifactRefV1, CacheMetadataV1, CacheNamespaceV1,
            CacheProtectionV1, EvidenceCompletenessV1 as CacheCompletenessV1, NewRepositoryTaskV1,
            RepositoryScopeV1, SCHEMA_VERSION_V1, ScanBoundsV1, ScanTargetV1, Sha256Digest,
            SubmitJobV1, TaskUsageV1,
        },
        evidence::{
            EvidenceBundleV1, EvidenceCompletenessV1, EvidenceReferenceV1, EvidenceStrengthV1,
            ExplanationStepKindV1, ExplanationStepV1, RepositoryEvidenceV1,
            RepositoryExplanationV1, RepositoryVisibilityV1,
        },
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

    #[test]
    fn coordinator_owns_bounded_typed_retry_policy() {
        let now = Utc::now();
        assert_eq!(
            task_retry_at(TaskFailureClassV1::ProviderTransient, 1, now),
            Some(now + TimeDelta::seconds(30))
        );
        assert_eq!(
            task_retry_at(TaskFailureClassV1::AnalysisTransient, 2, now),
            Some(now + TimeDelta::seconds(60))
        );
        assert_eq!(
            task_retry_at(TaskFailureClassV1::ProviderAuthorization, 1, now),
            None
        );
        assert_eq!(
            task_retry_at(TaskFailureClassV1::ProviderTransient, 3, now),
            None
        );
    }

    #[test]
    fn client_lease_retry_ids_are_bounded_and_header_safe() {
        assert!(validate_lease_request_id("worker:018f0f9b-lease_1").is_ok());
        assert!(validate_lease_request_id("").is_err());
        assert!(validate_lease_request_id("contains/slash").is_err());
        assert!(validate_lease_request_id(&"x".repeat(257)).is_err());
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

    #[test]
    fn private_inventory_requires_explicit_opt_in() {
        let private = CacheNamespaceV1::Private {
            principal_id: "profile".to_owned(),
        };
        assert!(inventory_projection_enabled(
            DEFAULT_PRIVATE_INVENTORY_ENABLED,
            &CacheNamespaceV1::Public
        ));
        assert!(!inventory_projection_enabled(
            DEFAULT_PRIVATE_INVENTORY_ENABLED,
            &private
        ));
        assert!(inventory_projection_enabled(true, &private));
    }

    fn inventory_evidence(now: DateTime<Utc>) -> EvidenceBundleV1 {
        let repository = "example/app";
        EvidenceBundleV1 {
            schema_version: EvidenceBundleV1::SCHEMA_VERSION,
            generated_at: now,
            target: PackageIdentityV1 {
                name: "fs2".to_owned(),
                version: Version::new(0, 4, 3),
                source: None,
            },
            globally_exhaustive: false,
            repositories: vec![RepositoryEvidenceV1 {
                repository: repository.to_owned(),
                repository_id: Some("42".to_owned()),
                visibility: RepositoryVisibilityV1::Public,
                head_committed_at: Some(now),
                completeness: EvidenceCompletenessV1::Complete,
                requirements: Vec::new(),
                exact_resolution_count: 0,
                recorded_relation: RecordedRelation::NotRecorded,
                direct_witness: None,
                transitive_witness: None,
                msrv: None,
                package_inventory_complete: false,
                packages: Vec::new(),
                vulnerabilities: Vec::new(),
                explanation: RepositoryExplanationV1 {
                    repository: repository.to_owned(),
                    observed_at: now,
                    strength: EvidenceStrengthV1::DiscoveryOnly,
                    completeness: EvidenceCompletenessV1::Complete,
                    steps: vec![ExplanationStepV1 {
                        kind: ExplanationStepKindV1::ImmutableRevision,
                        statement: "immutable test revision".to_owned(),
                        reference: Some(EvidenceReferenceV1 {
                            commit_sha: Some("commit-1".to_owned()),
                            tree_sha: Some("tree-1".to_owned()),
                            path: None,
                            blob_sha: None,
                        }),
                    }],
                    limitations: Vec::new(),
                    direct_witness: None,
                    transitive_witness: None,
                },
            }],
            advisory_snapshots: Vec::new(),
            limitations: Vec::new(),
        }
        .normalized()
    }

    async fn submit_and_fail_repository_task(
        store: &TursoCoordinatorStore,
        job_id: &str,
        task_id: &str,
        scope: RepositoryScopeV1,
        profile: Option<&str>,
        now: DateTime<Utc>,
    ) {
        let job_id = JobId(job_id.to_owned());
        let task_id = TaskId(task_id.to_owned());
        store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: format!("failure-{}", job_id.0),
                    spec: test_job(scope, profile).spec,
                    submitted_at: now,
                },
                tasks: vec![NewRepositoryTaskV1 {
                    task_id: task_id.clone(),
                    job_id: job_id.clone(),
                    repository_id: "example/app".to_owned(),
                    not_before: now,
                    created_at: now,
                }],
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::LeaseNextTask {
                job_id,
                agent_id: "worker".to_owned(),
                lease_id: format!("lease-{}", task_id.0),
                lease_seconds: 120,
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::FailTask {
                task_id: task_id.clone(),
                agent_id: "worker".to_owned(),
                lease_id: format!("lease-{}", task_id.0),
                failure: "secret provider response that must not enter the catalog".to_owned(),
                retry_at: None,
                usage: TaskUsageV1::default(),
                now: now + TimeDelta::seconds(1),
            })
            .await
            .unwrap();
    }

    async fn seed_prior_inventory_observation(
        inventory: &InMemoryInventoryStore,
        observed_at: DateTime<Utc>,
    ) {
        inventory
            .project(InventoryProjectionInputV1::Observation(
                InventoryObservationEnvelopeV1 {
                    schema_version: crate::catalog::CATALOG_SCHEMA_VERSION_V1,
                    namespace: InventoryNamespaceV1::Public,
                    job_id: JobId("prior-job".to_owned()),
                    task_id: TaskId("prior-task".to_owned()),
                    task_attempt: 1,
                    artifact: ArtifactRefV1 {
                        digest: Sha256Digest::parse("1".repeat(64)).unwrap(),
                        media_type: EVIDENCE_MEDIA_TYPE_V1.to_owned(),
                        stored_bytes: 1,
                    },
                    repository_id: "42".to_owned(),
                    revision: RepositoryRevisionV1 {
                        commit_sha: "commit-1".to_owned(),
                        tree_sha: "tree-1".to_owned(),
                        analyzer_profile_digest: "profile-1".to_owned(),
                    },
                    target_selector: "=0.4.3".to_owned(),
                    completed_at: observed_at,
                    evidence: inventory_evidence(observed_at),
                },
            ))
            .await
            .unwrap();
    }

    fn reconciliation_state(
        directory: &tempfile::TempDir,
        store: TursoCoordinatorStore,
        inventory: Arc<InMemoryInventoryStore>,
        envelope_key: Arc<EnvelopeKey>,
        private_inventory_enabled: bool,
    ) -> ApiState {
        ApiState {
            store,
            inventory,
            metrics: CoordinatorMetrics::new(),
            artifacts: SecureBlobCache::new(directory.path().join("artifacts")),
            envelope_key,
            retention_policy: RetentionPolicyV1::default(),
            private_inventory_enabled,
            credential_broker: None,
            artifact_retention: Arc::new(RwLock::new(())),
            inventory_reconciliation_cursor: Arc::new(Mutex::new(None)),
            failed_attempt_reconciliation_cursor: Arc::new(Mutex::new(None)),
        }
    }

    #[tokio::test]
    async fn failed_attempt_waits_for_stable_alias_then_marks_refresh_failed() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("envelope.key");
        EnvelopeKey::generate("test-key")
            .persist_new(&key_path)
            .unwrap();
        let envelope_key = Arc::new(EnvelopeKey::load(&key_path, "test-key").unwrap());
        let store = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let now = Utc::now();
        submit_and_fail_repository_task(
            &store,
            "failed-job",
            "failed-task",
            RepositoryScopeV1::PublicOnly,
            None,
            now,
        )
        .await;
        let pending = store
            .pending_failed_attempt_projections_page(None, 10)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].failure_code, "scan_attempt_failed");
        assert!(!pending[0].failure_message.contains("secret"));

        let inventory = Arc::new(InMemoryInventoryStore::new([8; 32]));
        let state = reconciliation_state(
            &directory,
            store.clone(),
            inventory.clone(),
            envelope_key,
            false,
        );
        let unresolved = reconcile_inventory_batch(&state).await.unwrap();
        assert_eq!(unresolved.unresolved_aliases, 1);
        assert_eq!(inventory.watermark().await.unwrap(), 0);

        seed_prior_inventory_observation(&inventory, now).await;
        let projected = reconcile_inventory_batch(&state).await.unwrap();
        assert_eq!(projected.projected, 1);
        assert!(
            store
                .pending_failed_attempt_projections_page(None, 10)
                .await
                .unwrap()
                .is_empty()
        );

        let page = inventory
            .search(
                &InventoryAccessV1 {
                    principal_id: "test".to_owned(),
                    private_credential_profiles: BTreeSet::new(),
                },
                &InventoryQueryV1::new(),
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].freshness, InventoryFreshnessV1::RefreshFailed);
        assert!(page.items[0].observation.is_none());
    }

    #[tokio::test]
    async fn private_failed_attempt_remains_outside_inventory_without_opt_in() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("envelope.key");
        EnvelopeKey::generate("test-key")
            .persist_new(&key_path)
            .unwrap();
        let envelope_key = Arc::new(EnvelopeKey::load(&key_path, "test-key").unwrap());
        let store = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        submit_and_fail_repository_task(
            &store,
            "private-failed-job",
            "private-failed-task",
            RepositoryScopeV1::AllVisible,
            Some("production"),
            Utc::now(),
        )
        .await;
        let inventory = Arc::new(InMemoryInventoryStore::new([9; 32]));
        let state = reconciliation_state(
            &directory,
            store.clone(),
            inventory.clone(),
            envelope_key,
            false,
        );

        let summary = reconcile_inventory_batch(&state).await.unwrap();
        assert_eq!(summary.private_skipped, 1);
        assert_eq!(inventory.watermark().await.unwrap(), 0);
        assert_eq!(
            store
                .pending_failed_attempt_projections_page(None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn reconciliation_projects_and_marks_a_durable_pending_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("envelope.key");
        EnvelopeKey::generate("test-key")
            .persist_new(&key_path)
            .unwrap();
        let store = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let now = Utc::now();
        let job_id = JobId("job-reconcile".to_owned());
        let task_id = TaskId("task-reconcile".to_owned());
        store
            .apply(DurableCommandV1::SubmitJob {
                request: SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: "reconcile".to_owned(),
                    spec: test_job(RepositoryScopeV1::PublicOnly, None).spec,
                    submitted_at: now,
                },
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::EnqueueTask {
                task: NewRepositoryTaskV1 {
                    task_id: task_id.clone(),
                    job_id: job_id.clone(),
                    repository_id: "example/app".to_owned(),
                    not_before: now,
                    created_at: now,
                },
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::StartJob {
                job_id: job_id.clone(),
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::LeaseNextTask {
                job_id: job_id.clone(),
                agent_id: "worker".to_owned(),
                lease_id: "lease".to_owned(),
                lease_seconds: 120,
                now,
            })
            .await
            .unwrap();

        let evidence = inventory_evidence(now);
        let canonical = serde_json::to_vec(&evidence).unwrap();
        let digest = Sha256Digest::parse(sha256_hex(&canonical)).unwrap();
        let artifact_ref = ArtifactRefV1 {
            digest: digest.clone(),
            media_type: EVIDENCE_MEDIA_TYPE_V1.to_owned(),
            stored_bytes: canonical.len() as u64,
        };
        let artifacts = SecureBlobCache::new(directory.path().join("artifacts"));
        let envelope_key = Arc::new(EnvelopeKey::load(&key_path, "test-key").unwrap());
        artifacts
            .put(
                SecureCacheNamespace::Public,
                CACHE_CONTENT_KIND_EVIDENCE,
                &canonical,
                &envelope_key,
            )
            .unwrap();
        let record = ArtifactRecordV1 {
            job_id: job_id.clone(),
            task_id: task_id.clone(),
            metadata: CacheMetadataV1 {
                schema_version: SCHEMA_VERSION_V1,
                key: CacheKeyV1 {
                    namespace: CacheNamespaceV1::Public,
                    digest,
                },
                content_kind: CacheContentKindV1::DerivedEvidence,
                content_length: canonical.len() as u64,
                github_blob_sha: None,
                protection: CacheProtectionV1::EnvelopeEncrypted {
                    algorithm: "AES-256-GCM".to_owned(),
                    wrapping_key_id: "test-key".to_owned(),
                },
                completeness: CacheCompletenessV1::Complete,
                reuse_fingerprint: None,
                created_at: now,
                last_accessed_at: now,
                retain_until: now + TimeDelta::days(1),
                reference_count: 0,
            },
            inventory_projection: InventoryProjectionStateV1::Pending,
        };
        store
            .apply(DurableCommandV1::CompleteTaskWithArtifact {
                task_id: task_id.clone(),
                agent_id: "worker".to_owned(),
                lease_id: "lease".to_owned(),
                result: artifact_ref,
                artifact: Box::new(record),
                usage: TaskUsageV1::default(),
                now,
            })
            .await
            .unwrap();

        let inventory = Arc::new(InMemoryInventoryStore::new([7; 32]));
        let state = ApiState {
            store: store.clone(),
            inventory: inventory.clone(),
            metrics: CoordinatorMetrics::new(),
            artifacts,
            envelope_key,
            retention_policy: RetentionPolicyV1::default(),
            private_inventory_enabled: false,
            credential_broker: None,
            artifact_retention: Arc::new(RwLock::new(())),
            inventory_reconciliation_cursor: Arc::new(Mutex::new(None)),
            failed_attempt_reconciliation_cursor: Arc::new(Mutex::new(None)),
        };

        assert_eq!(
            reconcile_inventory_batch(&state).await.unwrap(),
            InventoryReconciliationSummary {
                candidates: 1,
                projected: 1,
                private_skipped: 0,
                unresolved_aliases: 0,
                failed: 0,
                expired_skipped: 0,
            }
        );
        assert!(matches!(
            store
                .artifact(task_id)
                .await
                .unwrap()
                .unwrap()
                .inventory_projection,
            InventoryProjectionStateV1::Projected { .. }
        ));
        assert_eq!(inventory.watermark().await.unwrap(), 1);
        assert_eq!(
            reconcile_inventory_batch(&state).await.unwrap(),
            InventoryReconciliationSummary::default()
        );
    }
}
