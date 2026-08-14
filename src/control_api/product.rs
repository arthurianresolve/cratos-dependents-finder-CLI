use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post, put},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    catalog::{CatalogError, InventoryNamespaceV1},
    control_auth::{
        ControlPrincipalV1, ControlScopeV1, CredentialProfileIdV1, InventoryScopeRequestV1,
        authorize_inventory_scope,
    },
    coordinator::{
        ControlActionV1, ControlCommandV1, CreateScheduleV1, CredentialProfileV1, JobId,
        JobPriorityV1, RepositorySetContentV1, RepositorySourceRefV1, SCHEMA_VERSION_V1,
        SavedInventoryQueryRefV1, ScanJobStateV1, ScanJobV1, ScanSpecV1, ScheduleDefinitionV1,
        ScheduleId, ScheduleStateV1, SubmitJobV1, UtcCronV1,
    },
};

use super::{
    ControlApiState, ControlApiStateError, TrustedProxyAuthenticationV1, authenticate, failure,
    inventory_access_matches, json_problem, request_id, state_problem, success,
};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 200;
const DEFAULT_JOB_LIST_LIMIT: usize = 100;
const MAX_JOB_LIST_LIMIT: usize = 1_000;

pub(super) fn standard_routes<StateT: ControlApiState>() -> Router<StateT> {
    Router::new()
        .route("/api/v1/schedules", get(list_schedules::<StateT>))
        .route(
            "/api/v1/schedules/{schedule_id}",
            get(read_schedule::<StateT>).delete(delete_schedule::<StateT>),
        )
        .route(
            "/api/v1/schedules/{schedule_id}/enable",
            post(enable_schedule::<StateT>),
        )
        .route(
            "/api/v1/schedules/{schedule_id}/disable",
            post(disable_schedule::<StateT>),
        )
        .route(
            "/api/v1/schedules/{schedule_id}/trigger",
            post(trigger_schedule::<StateT>),
        )
        .route("/api/v1/jobs", get(list_jobs::<StateT>))
        .route("/api/v1/jobs/{job_id}", get(read_job::<StateT>))
        .route("/api/v1/jobs/{job_id}/cancel", post(cancel_job::<StateT>))
        .route("/api/v1/jobs/{job_id}/resume", post(resume_job::<StateT>))
        .route(
            "/api/v1/credential-profiles",
            get(list_credential_profiles::<StateT>),
        )
        .route(
            "/api/v1/credential-profiles/{profile_id}",
            put(upsert_credential_profile::<StateT>).delete(revoke_credential_profile::<StateT>),
        )
}

pub(super) fn explicit_repository_routes<StateT: ControlApiState>() -> Router<StateT> {
    Router::new()
        .route("/api/v1/schedules", post(create_schedule::<StateT>))
        .route(
            "/api/v1/schedules/{schedule_id}",
            put(revise_schedule::<StateT>),
        )
        .route("/api/v1/jobs", post(submit_job::<StateT>))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScheduleRepositorySourceRequestV1 {
    Explicit { repositories: Vec<String> },
    SavedQuery { query: SavedInventoryQueryRefV1 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleDefinitionRequestV1 {
    pub schema_version: u16,
    pub cron: UtcCronV1,
    pub scan_spec: ScanSpecV1,
    pub repository_source: ScheduleRepositorySourceRequestV1,
    pub priority: JobPriorityV1,
    pub max_run_age_seconds: u64,
}

impl ScheduleDefinitionRequestV1 {
    fn into_core(
        self,
    ) -> Result<(ScheduleDefinitionV1, Option<RepositorySetContentV1>), ControlApiStateError> {
        if self.schema_version != SCHEMA_VERSION_V1 || self.priority != JobPriorityV1::Normal {
            return Err(ControlApiStateError::ValidationFailed);
        }
        let (repository_source, content) = match self.repository_source {
            ScheduleRepositorySourceRequestV1::Explicit { repositories } => {
                let content = RepositorySetContentV1::from_repositories(repositories)
                    .map_err(|_| ControlApiStateError::ValidationFailed)?;
                if content.repository_set.repository_count == 0
                    || content.repository_set.repository_count
                        > self.scan_spec.bounds.repository_limit
                {
                    return Err(ControlApiStateError::ValidationFailed);
                }
                (
                    RepositorySourceRefV1::Explicit {
                        repository_set: content.repository_set.clone(),
                    },
                    Some(content),
                )
            }
            ScheduleRepositorySourceRequestV1::SavedQuery { query } => {
                (RepositorySourceRefV1::SavedQuery { query }, None)
            }
        };
        Ok((
            ScheduleDefinitionV1 {
                schema_version: SCHEMA_VERSION_V1,
                cron: self.cron,
                scan_spec: self.scan_spec,
                repository_source,
                priority: self.priority,
                max_run_age_seconds: self.max_run_age_seconds,
            },
            content,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateScheduleRequestV1 {
    pub schema_version: u16,
    pub schedule_id: ScheduleId,
    pub enabled: bool,
    pub definition: ScheduleDefinitionRequestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviseScheduleRequestV1 {
    pub schema_version: u16,
    pub expected_revision: u64,
    pub definition: ScheduleDefinitionRequestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleStateChangeRequestV1 {
    pub schema_version: u16,
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScheduleResponseV1 {
    pub schema_version: u16,
    pub schedule: ScheduleStateV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScheduleListResponseV1 {
    pub schema_version: u16,
    pub schedules: Vec<ScheduleStateV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitJobRequestV1 {
    pub schema_version: u16,
    pub job_id: Option<JobId>,
    pub spec: ScanSpecV1,
    pub repositories: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubmitJobResponseV1 {
    pub schema_version: u16,
    pub job_id: JobId,
    pub created: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct JobListParametersV1 {
    state: Option<ScanJobStateV1>,
    limit: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobListResponseV1 {
    pub schema_version: u16,
    pub jobs: Vec<ScanJobV1>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialProfileListResponseV1 {
    pub schema_version: u16,
    pub profiles: Vec<CredentialProfileV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialProfileResponseV1 {
    pub schema_version: u16,
    pub profile: CredentialProfileV1,
}

async fn list_schedules<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::SchedulesRead).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    match state.scheduler_snapshot().await {
        Ok(snapshot) => match state
            .authorized_schedules(&principal, snapshot.schedules)
            .await
        {
            Ok(schedules) => success(
                StatusCode::OK,
                request_id,
                ScheduleListResponseV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    schedules,
                },
            ),
            Err(error) => failure(state_problem(error, request_id)),
        },
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn read_schedule<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::SchedulesRead).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    match authorized_schedule_state(&state, &principal, &ScheduleId(schedule_id)).await {
        Ok(schedule) => success(
            StatusCode::OK,
            request_id,
            ScheduleResponseV1 {
                schema_version: SCHEMA_VERSION_V1,
                schedule,
            },
        ),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn create_schedule<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<CreateScheduleRequestV1>, JsonRejection>,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::SchedulesWrite).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    let request = match payload {
        Ok(Json(request)) if request.schema_version == SCHEMA_VERSION_V1 => request,
        Ok(_) => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
        Err(error) => return failure(json_problem(error, request_id)),
    };
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    let (definition, content) = match request.definition.into_core() {
        Ok(parts) => parts,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    if let Err(error) = validate_definition_access(&state, &principal, &definition).await {
        return failure(state_problem(error, request_id));
    }
    let now = Utc::now();
    if let Err(error) = apply_action(
        &state,
        format!("api-create-schedule-{key}"),
        ControlActionV1::CreateSchedule {
            request: CreateScheduleV1 {
                schema_version: SCHEMA_VERSION_V1,
                schedule_id: request.schedule_id.clone(),
                enabled: request.enabled,
                definition,
                created_at: now,
            },
            repository_set_content: content,
        },
        now,
    )
    .await
    {
        return failure(state_problem(error, request_id));
    }
    schedule_mutation_response(
        &state,
        &principal,
        request.schedule_id,
        StatusCode::CREATED,
        request_id,
    )
    .await
}

async fn revise_schedule<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<ReviseScheduleRequestV1>, JsonRejection>,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::SchedulesWrite).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    let request = match payload {
        Ok(Json(request))
            if request.schema_version == SCHEMA_VERSION_V1 && request.expected_revision > 0 =>
        {
            request
        }
        Ok(_) => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
        Err(error) => return failure(json_problem(error, request_id)),
    };
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    let schedule_id = ScheduleId(schedule_id);
    if let Err(error) = authorized_schedule_state(&state, &principal, &schedule_id).await {
        return failure(state_problem(error, request_id));
    }
    let (definition, content) = match request.definition.into_core() {
        Ok(parts) => parts,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    if let Err(error) = validate_definition_access(&state, &principal, &definition).await {
        return failure(state_problem(error, request_id));
    }
    let now = Utc::now();
    if let Err(error) = apply_action(
        &state,
        format!("api-revise-schedule-{key}"),
        ControlActionV1::ReviseSchedule {
            schedule_id: schedule_id.clone(),
            expected_revision: request.expected_revision,
            definition,
            repository_set_content: content,
        },
        now,
    )
    .await
    {
        return failure(state_problem(error, request_id));
    }
    schedule_mutation_response(&state, &principal, schedule_id, StatusCode::OK, request_id).await
}

async fn enable_schedule<StateT: ControlApiState>(
    state: State<StateT>,
    path: Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<ScheduleStateChangeRequestV1>, JsonRejection>,
) -> Response {
    set_schedule_enabled(state, path, headers, proxy, payload, true).await
}

async fn disable_schedule<StateT: ControlApiState>(
    state: State<StateT>,
    path: Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<ScheduleStateChangeRequestV1>, JsonRejection>,
) -> Response {
    set_schedule_enabled(state, path, headers, proxy, payload, false).await
}

async fn set_schedule_enabled<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<ScheduleStateChangeRequestV1>, JsonRejection>,
    enabled: bool,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::SchedulesWrite).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    let request = match payload {
        Ok(Json(request))
            if request.schema_version == SCHEMA_VERSION_V1 && request.expected_revision > 0 =>
        {
            request
        }
        Ok(_) => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
        Err(error) => return failure(json_problem(error, request_id)),
    };
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    let schedule_id = ScheduleId(schedule_id);
    if let Err(error) = authorized_schedule_state(&state, &principal, &schedule_id).await {
        return failure(state_problem(error, request_id));
    }
    if let Err(error) = apply_action(
        &state,
        format!("api-schedule-enabled-{key}"),
        ControlActionV1::SetScheduleEnabled {
            schedule_id: schedule_id.clone(),
            expected_revision: request.expected_revision,
            enabled,
        },
        Utc::now(),
    )
    .await
    {
        return failure(state_problem(error, request_id));
    }
    schedule_mutation_response(&state, &principal, schedule_id, StatusCode::OK, request_id).await
}

async fn delete_schedule<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(schedule_id): Path<String>,
    parameters: Result<Query<ScheduleStateChangeRequestV1>, QueryRejection>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let request = match parameters {
        Ok(Query(request)) => request,
        Err(_) => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
    };
    if request.schema_version != SCHEMA_VERSION_V1 || request.expected_revision == 0 {
        return failure(state_problem(
            ControlApiStateError::ValidationFailed,
            request_id,
        ));
    }
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::SchedulesWrite).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    let schedule_id = ScheduleId(schedule_id);
    if let Err(error) = authorized_schedule_state(&state, &principal, &schedule_id).await {
        return failure(state_problem(error, request_id));
    }
    match apply_action(
        &state,
        format!("api-delete-schedule-{key}"),
        ControlActionV1::DeleteSchedule {
            schedule_id,
            expected_revision: request.expected_revision,
        },
        Utc::now(),
    )
    .await
    {
        Ok(_) => success(StatusCode::NO_CONTENT, request_id, ()),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn trigger_schedule<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(schedule_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::SchedulesWrite).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    let schedule_id = ScheduleId(schedule_id);
    if let Err(error) = authorized_schedule_state(&state, &principal, &schedule_id).await {
        return failure(state_problem(error, request_id));
    }
    match apply_action(
        &state,
        format!("api-trigger-schedule-{key}"),
        ControlActionV1::TriggerSchedule { schedule_id },
        Utc::now(),
    )
    .await
    {
        Ok(outcome) => success(StatusCode::ACCEPTED, request_id, outcome),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn list_jobs<StateT: ControlApiState>(
    State(state): State<StateT>,
    parameters: Result<Query<JobListParametersV1>, QueryRejection>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let parameters = match parameters {
        Ok(Query(parameters)) => parameters,
        Err(_) => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
    };
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::JobsRead).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    let limit = parameters.limit.unwrap_or(DEFAULT_JOB_LIST_LIMIT);
    if limit == 0 || limit > MAX_JOB_LIST_LIMIT {
        return failure(state_problem(
            ControlApiStateError::ValidationFailed,
            request_id,
        ));
    }
    match state.jobs().await {
        Ok(jobs) => {
            let mut jobs = match state.authorized_jobs(&principal, jobs).await {
                Ok(jobs) => jobs,
                Err(error) => return failure(state_problem(error, request_id)),
            };
            jobs.retain(|job| parameters.state.is_none_or(|state| job.state == state));
            jobs.sort_unstable_by(|left, right| {
                right
                    .created_at
                    .cmp(&left.created_at)
                    .then_with(|| right.id.cmp(&left.id))
            });
            let has_more = jobs.len() > limit;
            jobs.truncate(limit);
            success(
                StatusCode::OK,
                request_id,
                JobListResponseV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    jobs,
                    has_more,
                },
            )
        }
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn read_job<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::JobsRead).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    match state.job(JobId(job_id)).await {
        Ok(Some(job)) => match state.authorized_jobs(&principal, vec![job]).await {
            Ok(mut jobs) if jobs.len() == 1 => success(StatusCode::OK, request_id, jobs.remove(0)),
            Ok(_) => failure(state_problem(ControlApiStateError::NotFound, request_id)),
            Err(error) => failure(state_problem(error, request_id)),
        },
        Ok(None) => failure(state_problem(ControlApiStateError::NotFound, request_id)),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn submit_job<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<SubmitJobRequestV1>, JsonRejection>,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::JobsSubmit).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    let request = match payload {
        Ok(Json(request)) if request.schema_version == SCHEMA_VERSION_V1 => request,
        Ok(_) => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
        Err(error) => return failure(json_problem(error, request_id)),
    };
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    if let Err(error) = state
        .validate_scan_spec_access(&principal, &request.spec)
        .await
    {
        return failure(state_problem(error, request_id));
    }
    let content = match RepositorySetContentV1::from_repositories(request.repositories) {
        Ok(content)
            if content.repository_set.repository_count > 0
                && content.repository_set.repository_count
                    <= request.spec.bounds.repository_limit =>
        {
            content
        }
        _ => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
    };
    let now = Utc::now();
    let job_id = request
        .job_id
        .unwrap_or_else(|| JobId(format!("job-{}", Uuid::new_v4().simple())));
    match state
        .submit_job_with_repositories(
            SubmitJobV1 {
                job_id: job_id.clone(),
                idempotency_key: key.to_owned(),
                spec: request.spec,
                submitted_at: now,
            },
            content.repository_ids,
            now,
        )
        .await
    {
        Ok(crate::coordinator::SubmitOutcome::Created(job_id)) => success(
            StatusCode::CREATED,
            request_id,
            SubmitJobResponseV1 {
                schema_version: SCHEMA_VERSION_V1,
                job_id,
                created: true,
            },
        ),
        Ok(crate::coordinator::SubmitOutcome::Existing(job_id)) => success(
            StatusCode::OK,
            request_id,
            SubmitJobResponseV1 {
                schema_version: SCHEMA_VERSION_V1,
                job_id,
                created: false,
            },
        ),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn cancel_job<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    control_job(state, job_id, headers, proxy, true).await
}

async fn resume_job<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    control_job(state, job_id, headers, proxy, false).await
}

async fn control_job<StateT: ControlApiState>(
    state: StateT,
    job_id: String,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    cancel: bool,
) -> Response {
    let request_id = request_id(&headers);
    let principal =
        match authorized_principal(&state, &headers, proxy, ControlScopeV1::JobsControl).await {
            Ok(principal) => principal,
            Err(error) => return failure(state_problem(error, request_id)),
        };
    if let Err(error) = idempotency_key(&headers) {
        return failure(state_problem(error, request_id));
    }
    let job_id = JobId(job_id);
    let existing = match state.job(job_id.clone()).await {
        Ok(Some(job)) => job,
        Ok(None) => return failure(state_problem(ControlApiStateError::NotFound, request_id)),
        Err(error) => return failure(state_problem(error, request_id)),
    };
    match state.authorized_jobs(&principal, vec![existing]).await {
        Ok(jobs) if jobs.len() == 1 => {}
        Ok(_) => return failure(state_problem(ControlApiStateError::NotFound, request_id)),
        Err(error) => return failure(state_problem(error, request_id)),
    }
    let result = if cancel {
        state.cancel_job(job_id.clone(), Utc::now()).await
    } else {
        state.resume_job(job_id.clone(), Utc::now()).await
    };
    match result {
        Ok(()) => match state.job(job_id).await {
            Ok(Some(job)) => success(StatusCode::OK, request_id, job),
            Ok(None) => failure(state_problem(ControlApiStateError::NotFound, request_id)),
            Err(error) => failure(state_problem(error, request_id)),
        },
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn list_credential_profiles<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let principal = match authorized_principal(
        &state,
        &headers,
        proxy,
        ControlScopeV1::CredentialProfilesManage,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    match state.credential_profiles().await {
        Ok(mut profiles) => {
            profiles.retain(|profile| principal_allows_profile(&principal, &profile.id));
            profiles.sort_unstable_by(|left, right| left.id.cmp(&right.id));
            success(
                StatusCode::OK,
                request_id,
                CredentialProfileListResponseV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    profiles,
                },
            )
        }
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn upsert_credential_profile<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<CredentialProfileV1>, JsonRejection>,
) -> Response {
    let request_id = request_id(&headers);
    let principal = match authorized_principal(
        &state,
        &headers,
        proxy,
        ControlScopeV1::CredentialProfilesManage,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    if !principal_allows_profile(&principal, &profile_id) {
        return failure(state_problem(ControlApiStateError::NotFound, request_id));
    }
    let profile = match payload {
        Ok(Json(profile)) if profile.id == profile_id => profile,
        Ok(_) => {
            return failure(state_problem(
                ControlApiStateError::ValidationFailed,
                request_id,
            ));
        }
        Err(error) => return failure(json_problem(error, request_id)),
    };
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    match apply_action(
        &state,
        format!("api-upsert-profile-{key}"),
        ControlActionV1::UpsertCredentialProfile {
            profile: profile.clone(),
        },
        Utc::now(),
    )
    .await
    {
        Ok(_) => success(
            StatusCode::OK,
            request_id,
            CredentialProfileResponseV1 {
                schema_version: SCHEMA_VERSION_V1,
                profile,
            },
        ),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn revoke_credential_profile<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let principal = match authorized_principal(
        &state,
        &headers,
        proxy,
        ControlScopeV1::CredentialProfilesManage,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    if !principal_allows_profile(&principal, &profile_id) {
        return failure(state_problem(ControlApiStateError::NotFound, request_id));
    }
    let key = match idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return failure(state_problem(error, request_id)),
    };
    match apply_action(
        &state,
        format!("api-revoke-profile-{key}"),
        ControlActionV1::RevokeCredentialProfile {
            profile_id: profile_id.clone(),
        },
        Utc::now(),
    )
    .await
    {
        Ok(_) => match state.credential_profiles().await {
            Ok(profiles) => match profiles
                .into_iter()
                .find(|profile| profile.id == profile_id)
            {
                Some(profile) => success(
                    StatusCode::OK,
                    request_id,
                    CredentialProfileResponseV1 {
                        schema_version: SCHEMA_VERSION_V1,
                        profile,
                    },
                ),
                None => failure(state_problem(ControlApiStateError::NotFound, request_id)),
            },
            Err(error) => failure(state_problem(error, request_id)),
        },
        Err(error) => failure(state_problem(error, request_id)),
    }
}

async fn authorized_principal<StateT: ControlApiState>(
    state: &StateT,
    headers: &HeaderMap,
    proxy: Option<axum::Extension<TrustedProxyAuthenticationV1>>,
    scope: ControlScopeV1,
) -> Result<ControlPrincipalV1, ControlApiStateError> {
    let principal = authenticate(state, headers, proxy, Utc::now()).await?;
    if !principal.allows(scope) {
        return Err(ControlApiStateError::NotFound);
    }
    Ok(principal)
}

async fn validate_definition_access<StateT: ControlApiState>(
    state: &StateT,
    principal: &ControlPrincipalV1,
    definition: &ScheduleDefinitionV1,
) -> Result<(), ControlApiStateError> {
    state
        .validate_scan_spec_access(principal, &definition.scan_spec)
        .await?;
    let RepositorySourceRefV1::SavedQuery { query } = &definition.repository_source else {
        return Ok(());
    };
    let scope = authorize_inventory_scope(principal, &InventoryScopeRequestV1::AllAuthorized)
        .map_err(|_| ControlApiStateError::NotFound)?;
    let access = state.inventory_access(principal, &scope).await?;
    if !inventory_access_matches(principal, &scope, &access) {
        return Err(ControlApiStateError::Unavailable);
    }
    let saved = state
        .inventory()
        .saved_query(&access, &query.query_id, Some(query.revision))
        .await
        .map_err(catalog_state_error)?
        .ok_or(ControlApiStateError::NotFound)?;
    match &saved.namespace {
        InventoryNamespaceV1::Public
            if definition.scan_spec.repository_scope
                == crate::coordinator::RepositoryScopeV1::PublicOnly => {}
        InventoryNamespaceV1::Private {
            credential_profile_id,
        } if definition.scan_spec.repository_scope
            == crate::coordinator::RepositoryScopeV1::AllVisible
            && definition.scan_spec.credential_profile_id.as_deref()
                == Some(credential_profile_id.as_str()) => {}
        _ => return Err(ControlApiStateError::ValidationFailed),
    }
    Ok(())
}

async fn apply_action<StateT: ControlApiState>(
    state: &StateT,
    command_id: String,
    action: ControlActionV1,
    issued_at: chrono::DateTime<Utc>,
) -> Result<crate::coordinator::ControlOutcomeV1, ControlApiStateError> {
    state
        .apply_control(ControlCommandV1 {
            schema_version: SCHEMA_VERSION_V1,
            command_id,
            expected_generation: None,
            issued_at,
            action,
        })
        .await
}

async fn schedule_state<StateT: ControlApiState>(
    state: &StateT,
    schedule_id: &ScheduleId,
) -> Result<ScheduleStateV1, ControlApiStateError> {
    state
        .scheduler_snapshot()
        .await?
        .schedules
        .into_iter()
        .find(|state| state.schedule.id == *schedule_id)
        .ok_or(ControlApiStateError::NotFound)
}

async fn authorized_schedule_state<StateT: ControlApiState>(
    state: &StateT,
    principal: &ControlPrincipalV1,
    schedule_id: &ScheduleId,
) -> Result<ScheduleStateV1, ControlApiStateError> {
    let schedule = schedule_state(state, schedule_id).await?;
    state
        .authorized_schedules(principal, vec![schedule])
        .await?
        .pop()
        .ok_or(ControlApiStateError::NotFound)
}

async fn schedule_mutation_response<StateT: ControlApiState>(
    state: &StateT,
    principal: &ControlPrincipalV1,
    schedule_id: ScheduleId,
    status: StatusCode,
    request_id: crate::control_auth::RequestIdV1,
) -> Response {
    match authorized_schedule_state(state, principal, &schedule_id).await {
        Ok(schedule) => success(
            status,
            request_id,
            ScheduleResponseV1 {
                schema_version: SCHEMA_VERSION_V1,
                schedule,
            },
        ),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ControlApiStateError> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let value = values
        .next()
        .ok_or(ControlApiStateError::ValidationFailed)?;
    if values.next().is_some() {
        return Err(ControlApiStateError::ValidationFailed);
    }
    let key = value
        .to_str()
        .map_err(|_| ControlApiStateError::ValidationFailed)?;
    if key.is_empty()
        || key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || key.trim() != key
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ControlApiStateError::ValidationFailed);
    }
    Ok(key)
}

fn principal_allows_profile(principal: &ControlPrincipalV1, profile_id: &str) -> bool {
    CredentialProfileIdV1::parse(profile_id.to_owned()).is_ok_and(|profile_id| {
        principal
            .grant
            .repository_access
            .credential_profiles
            .allows(&profile_id)
    })
}

fn catalog_state_error(error: CatalogError) -> ControlApiStateError {
    match error {
        CatalogError::Unauthorized => ControlApiStateError::NotFound,
        CatalogError::UnsupportedSchemaVersion(_)
        | CatalogError::InvalidInput(_)
        | CatalogError::InvalidEvidence(_)
        | CatalogError::CursorInvalid => ControlApiStateError::ValidationFailed,
        CatalogError::CursorStale | CatalogError::RevisionConflict { .. } => {
            ControlApiStateError::Conflict
        }
        CatalogError::StoreUnavailable => ControlApiStateError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_repository_input_is_canonical_and_bounded_by_scan_spec() {
        let mut spec = test_spec();
        spec.bounds.repository_limit = 2;
        let request = ScheduleDefinitionRequestV1 {
            schema_version: SCHEMA_VERSION_V1,
            cron: UtcCronV1::parse("0 * * * *").unwrap(),
            scan_spec: spec,
            repository_source: ScheduleRepositorySourceRequestV1::Explicit {
                repositories: vec!["owner/b".to_owned(), "owner/a".to_owned()],
            },
            priority: JobPriorityV1::Normal,
            max_run_age_seconds: 3_600,
        };
        let (definition, content) = request.into_core().unwrap();
        assert!(matches!(
            definition.repository_source,
            RepositorySourceRefV1::Explicit { .. }
        ));
        assert_eq!(
            content.unwrap().repository_ids,
            ["owner/a".to_owned(), "owner/b".to_owned()]
        );
    }

    #[test]
    fn unsupported_priority_is_rejected_instead_of_becoming_an_inert_knob() {
        let request = ScheduleDefinitionRequestV1 {
            schema_version: SCHEMA_VERSION_V1,
            cron: UtcCronV1::parse("0 * * * *").unwrap(),
            scan_spec: test_spec(),
            repository_source: ScheduleRepositorySourceRequestV1::Explicit {
                repositories: vec!["owner/repo".to_owned()],
            },
            priority: JobPriorityV1::High,
            max_run_age_seconds: 3_600,
        };
        assert_eq!(
            request.into_core(),
            Err(ControlApiStateError::ValidationFailed)
        );
    }

    #[test]
    fn idempotency_key_is_single_and_normalized() {
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, "schedule-1".parse().unwrap());
        assert_eq!(idempotency_key(&headers).unwrap(), "schedule-1");
        headers.append(IDEMPOTENCY_KEY_HEADER, "duplicate".parse().unwrap());
        assert_eq!(
            idempotency_key(&headers),
            Err(ControlApiStateError::ValidationFailed)
        );
    }

    fn test_spec() -> ScanSpecV1 {
        ScanSpecV1 {
            schema_version: SCHEMA_VERSION_V1,
            target: crate::coordinator::ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: crate::coordinator::RepositoryScopeV1::PublicOnly,
            credential_profile_id: None,
            bounds: crate::coordinator::ScanBoundsV1::default(),
            analyzer_versions: Default::default(),
        }
    }
}
