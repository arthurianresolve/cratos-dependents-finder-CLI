use std::{collections::BTreeSet, sync::Arc};

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;

use crate::{
    catalog::{InventoryAccessV1, InventoryProjectionStore},
    control_auth::{
        AuthorizedInventoryScopeV1, ControlPrincipalV1, CredentialProfileIdV1, OidcTrustPolicyV1,
        service_token_id_from_presented,
    },
    coordinator::{
        ControlCommandV1, ControlOutcomeV1, CredentialProfileV1, DurableCommandV1,
        DurableOutcomeV1, JobId, NewRepositoryTaskV1, OccurrenceMaterializationV1, ProviderKeyV1,
        ProviderPolicyV1, RepositoryScopeV1, RepositorySetContentV1, ScanJobStateV1, ScanJobV1,
        ScanScheduleV1, ScanSpecV1, ScheduleId, ScheduleRevisionV1, ScheduleStateV1,
        SchedulerSnapshotV1, SubmitJobV1, SubmitOutcome, TaskId, TursoCoordinatorStore,
    },
};

use super::{ControlApiState, ControlApiStateError};

/// Production adapter joining the product API to the single-owner durable
/// coordinator and the disposable inventory projection.
#[derive(Clone)]
pub struct CoordinatorControlApiState {
    store: TursoCoordinatorStore,
    inventory: Arc<dyn InventoryProjectionStore>,
    oidc_policy: Option<OidcTrustPolicyV1>,
    private_inventory_enabled: bool,
}

impl CoordinatorControlApiState {
    pub fn new(
        store: TursoCoordinatorStore,
        inventory: Arc<dyn InventoryProjectionStore>,
        oidc_policy: Option<OidcTrustPolicyV1>,
        private_inventory_enabled: bool,
    ) -> Result<Self, ControlApiStateError> {
        if oidc_policy
            .as_ref()
            .is_some_and(|policy| policy.validate().is_err())
        {
            return Err(ControlApiStateError::AuthenticationRejected);
        }
        Ok(Self {
            store,
            inventory,
            oidc_policy,
            private_inventory_enabled,
        })
    }

    pub fn store(&self) -> &TursoCoordinatorStore {
        &self.store
    }
}

impl ControlApiState for CoordinatorControlApiState {
    fn inventory(&self) -> &(dyn InventoryProjectionStore + Send + Sync) {
        self.inventory.as_ref()
    }

    fn readiness(&self) -> BoxFuture<'_, Result<(), ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .agent("operator")
                .await
                .map_err(|_| ControlApiStateError::Unavailable)?
                .ok_or(ControlApiStateError::Unavailable)
                .map(|_| ())
        })
    }

    fn authenticate_service_token<'a>(
        &'a self,
        presented_token: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<ControlPrincipalV1, ControlApiStateError>> {
        Box::pin(async move {
            let token_id = service_token_id_from_presented(presented_token)
                .map_err(|_| ControlApiStateError::AuthenticationRejected)?;
            let record = self
                .store
                .service_token(token_id)
                .await
                .map_err(|_| ControlApiStateError::Unavailable)?
                .ok_or(ControlApiStateError::AuthenticationRejected)?;
            record
                .verify(presented_token, now)
                .cloned()
                .map_err(|_| ControlApiStateError::AuthenticationRejected)
        })
    }

    fn oidc_policy(&self) -> Option<&OidcTrustPolicyV1> {
        self.oidc_policy.as_ref()
    }

    fn inventory_access<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        scope: &'a AuthorizedInventoryScopeV1,
    ) -> BoxFuture<'a, Result<InventoryAccessV1, ControlApiStateError>> {
        Box::pin(async move {
            let private_credential_profiles = if !self.private_inventory_enabled {
                if scope.selected_credential_profiles().is_some()
                    || scope.includes_all_credential_profiles()
                {
                    return Err(ControlApiStateError::AuthenticationRejected);
                }
                BTreeSet::new()
            } else if let Some(selected) = scope.selected_credential_profiles() {
                selected
                    .map(|profile| profile.as_str().to_owned())
                    .collect()
            } else if scope.includes_all_credential_profiles() {
                // All-profile access is intentionally resolved from the durable
                // registry, never from names supplied by a search request.
                self.store
                    .control_snapshot()
                    .await
                    .map_err(|_| ControlApiStateError::Unavailable)?
                    .credential_profiles
                    .into_iter()
                    .filter(|profile| profile.enabled)
                    .map(|profile| profile.id)
                    .collect()
            } else {
                BTreeSet::new()
            };
            let access = InventoryAccessV1 {
                principal_id: principal.id.as_str().to_owned(),
                private_credential_profiles,
            };
            access
                .validate()
                .map_err(|_| ControlApiStateError::AuthenticationRejected)?;
            Ok(access)
        })
    }

    fn scheduler_snapshot(
        &self,
    ) -> BoxFuture<'_, Result<SchedulerSnapshotV1, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .control_snapshot()
                .await
                .map(|snapshot| snapshot.scheduler)
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn occurrence_materializations(
        &self,
    ) -> BoxFuture<'_, Result<Vec<OccurrenceMaterializationV1>, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .control_snapshot()
                .await
                .map(|snapshot| snapshot.occurrence_materializations)
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn schedule<'a>(
        &'a self,
        schedule_id: ScheduleId,
    ) -> BoxFuture<'a, Result<Option<ScanScheduleV1>, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .control_schedule(schedule_id)
                .await
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn schedule_revision<'a>(
        &'a self,
        schedule_id: ScheduleId,
        revision: u64,
    ) -> BoxFuture<'a, Result<Option<ScheduleRevisionV1>, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .control_schedule_revision(schedule_id, revision)
                .await
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn apply_control(
        &self,
        command: ControlCommandV1,
    ) -> BoxFuture<'_, Result<ControlOutcomeV1, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .apply_control(command)
                .await
                .map_err(classify_state_error)
        })
    }

    fn jobs(&self) -> BoxFuture<'_, Result<Vec<ScanJobV1>, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .jobs()
                .await
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn job<'a>(
        &'a self,
        job_id: JobId,
    ) -> BoxFuture<'a, Result<Option<ScanJobV1>, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .job(job_id)
                .await
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn submit_job_with_repositories<'a>(
        &'a self,
        request: SubmitJobV1,
        repositories: Vec<String>,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<SubmitOutcome, ControlApiStateError>> {
        Box::pin(async move {
            request
                .spec
                .validate()
                .map_err(|_| ControlApiStateError::ValidationFailed)?;
            ensure_private_profile_enabled(&self.store, &request.spec).await?;
            for resource in ["core", "search"] {
                match self
                    .store
                    .apply(DurableCommandV1::ConfigureProvider {
                        key: ProviderKeyV1::github_request(
                            request.spec.repository_scope,
                            request.spec.credential_profile_id.as_deref(),
                            resource,
                        ),
                        policy: ProviderPolicyV1::github_requests(),
                    })
                    .await
                    .map_err(classify_state_error)?
                {
                    DurableOutcomeV1::Applied => {}
                    _ => return Err(ControlApiStateError::Unavailable),
                }
            }
            let tasks = repositories
                .into_iter()
                .map(|repository_id| NewRepositoryTaskV1 {
                    task_id: TaskId(format!("task-{}", uuid::Uuid::new_v4().simple())),
                    job_id: request.job_id.clone(),
                    repository_id,
                    not_before: now,
                    created_at: now,
                })
                .collect();
            match self
                .store
                .apply(DurableCommandV1::SubmitJobWithTasks {
                    request,
                    tasks,
                    now,
                })
                .await
                .map_err(classify_state_error)?
            {
                DurableOutcomeV1::Submitted(outcome) => Ok(outcome),
                _ => Err(ControlApiStateError::Unavailable),
            }
        })
    }

    fn cancel_job<'a>(
        &'a self,
        job_id: JobId,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<(), ControlApiStateError>> {
        Box::pin(async move {
            if self
                .store
                .job(job_id.clone())
                .await
                .map_err(|_| ControlApiStateError::Unavailable)?
                .is_some_and(|job| job.state == ScanJobStateV1::Cancelled)
            {
                return Ok(());
            }
            match self
                .store
                .apply(DurableCommandV1::CancelJob { job_id, now })
                .await
                .map_err(classify_state_error)?
            {
                DurableOutcomeV1::Applied => Ok(()),
                _ => Err(ControlApiStateError::Unavailable),
            }
        })
    }

    fn resume_job<'a>(
        &'a self,
        job_id: JobId,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<(), ControlApiStateError>> {
        Box::pin(async move {
            if self
                .store
                .job(job_id.clone())
                .await
                .map_err(|_| ControlApiStateError::Unavailable)?
                .is_some_and(|job| job.state == ScanJobStateV1::Running)
            {
                return Ok(());
            }
            match self
                .store
                .apply(DurableCommandV1::ResumeJob { job_id, now })
                .await
                .map_err(classify_state_error)?
            {
                DurableOutcomeV1::Applied => Ok(()),
                _ => Err(ControlApiStateError::Unavailable),
            }
        })
    }

    fn repository_set<'a>(
        &'a self,
        digest: &'a crate::coordinator::Sha256Digest,
    ) -> BoxFuture<'a, Result<Option<RepositorySetContentV1>, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .control_snapshot()
                .await
                .map_err(|_| ControlApiStateError::Unavailable)
                .map(|snapshot| {
                    snapshot
                        .repository_sets
                        .into_iter()
                        .find(|content| &content.repository_set.digest == digest)
                })
        })
    }

    fn validate_scan_spec_access<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        spec: &'a ScanSpecV1,
    ) -> BoxFuture<'a, Result<(), ControlApiStateError>> {
        Box::pin(async move {
            spec.validate()
                .map_err(|_| ControlApiStateError::ValidationFailed)?;
            match spec.repository_scope {
                RepositoryScopeV1::PublicOnly if principal.grant.repository_access.public => Ok(()),
                RepositoryScopeV1::AllVisible => {
                    let profile = spec
                        .credential_profile_id
                        .as_ref()
                        .ok_or(ControlApiStateError::ValidationFailed)?;
                    let profile_id = CredentialProfileIdV1::parse(profile.clone())
                        .map_err(|_| ControlApiStateError::ValidationFailed)?;
                    if !principal
                        .grant
                        .repository_access
                        .credential_profiles
                        .allows(&profile_id)
                    {
                        return Err(ControlApiStateError::NotFound);
                    }
                    ensure_private_profile_enabled(&self.store, spec).await
                }
                RepositoryScopeV1::PublicOnly => Err(ControlApiStateError::NotFound),
            }
        })
    }

    fn scheduler_inventory_access<'a>(
        &'a self,
        spec: &'a ScanSpecV1,
    ) -> BoxFuture<'a, Result<InventoryAccessV1, ControlApiStateError>> {
        Box::pin(async move {
            spec.validate()
                .map_err(|_| ControlApiStateError::ValidationFailed)?;
            let mut private_credential_profiles = BTreeSet::new();
            if spec.repository_scope == RepositoryScopeV1::AllVisible {
                if !self.private_inventory_enabled {
                    return Err(ControlApiStateError::NotFound);
                }
                ensure_private_profile_enabled(&self.store, spec).await?;
                private_credential_profiles.insert(
                    spec.credential_profile_id
                        .clone()
                        .ok_or(ControlApiStateError::ValidationFailed)?,
                );
            }
            let access = InventoryAccessV1 {
                principal_id: "system:scheduler".to_owned(),
                private_credential_profiles,
            };
            access
                .validate()
                .map_err(|_| ControlApiStateError::Unavailable)?;
            Ok(access)
        })
    }

    fn authorized_schedules<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        schedules: Vec<ScheduleStateV1>,
    ) -> BoxFuture<'a, Result<Vec<ScheduleStateV1>, ControlApiStateError>> {
        Box::pin(async move {
            let enabled_profiles = enabled_credential_profiles(&self.store).await?;
            let mut authorized = Vec::with_capacity(schedules.len());
            for mut state in schedules {
                let allowed_revisions = state
                    .revisions
                    .iter()
                    .filter(|revision| {
                        scan_spec_accessible(principal, &revision.scan_spec, &enabled_profiles)
                    })
                    .map(|revision| revision.revision)
                    .collect::<BTreeSet<_>>();
                if !allowed_revisions.contains(&state.schedule.current_revision) {
                    continue;
                }
                state
                    .revisions
                    .retain(|revision| allowed_revisions.contains(&revision.revision));
                state
                    .occurrences
                    .retain(|occurrence| allowed_revisions.contains(&occurrence.schedule_revision));
                let visible_occurrences = state
                    .occurrences
                    .iter()
                    .map(|occurrence| &occurrence.id)
                    .collect::<BTreeSet<_>>();
                if state
                    .active_occurrence
                    .as_ref()
                    .is_some_and(|occurrence| !visible_occurrences.contains(occurrence))
                {
                    state.active_occurrence = None;
                }
                if state
                    .pending_occurrence
                    .as_ref()
                    .is_some_and(|occurrence| !visible_occurrences.contains(occurrence))
                {
                    state.pending_occurrence = None;
                }
                authorized.push(state);
            }
            Ok(authorized)
        })
    }

    fn authorized_jobs<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        mut jobs: Vec<ScanJobV1>,
    ) -> BoxFuture<'a, Result<Vec<ScanJobV1>, ControlApiStateError>> {
        Box::pin(async move {
            let enabled_profiles = enabled_credential_profiles(&self.store).await?;
            jobs.retain(|job| scan_spec_accessible(principal, &job.spec, &enabled_profiles));
            Ok(jobs)
        })
    }

    fn credential_profiles(
        &self,
    ) -> BoxFuture<'_, Result<Vec<CredentialProfileV1>, ControlApiStateError>> {
        Box::pin(async move {
            self.store
                .control_snapshot()
                .await
                .map(|snapshot| snapshot.credential_profiles)
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }
}

async fn enabled_credential_profiles(
    store: &TursoCoordinatorStore,
) -> Result<BTreeSet<String>, ControlApiStateError> {
    Ok(store
        .control_snapshot()
        .await
        .map_err(|_| ControlApiStateError::Unavailable)?
        .credential_profiles
        .into_iter()
        .filter(|profile| profile.enabled)
        .map(|profile| profile.id)
        .collect())
}

fn scan_spec_accessible(
    principal: &ControlPrincipalV1,
    spec: &ScanSpecV1,
    enabled_profiles: &BTreeSet<String>,
) -> bool {
    if spec.validate().is_err() {
        return false;
    }
    match spec.repository_scope {
        RepositoryScopeV1::PublicOnly => principal.grant.repository_access.public,
        RepositoryScopeV1::AllVisible => {
            spec.credential_profile_id.as_ref().is_some_and(|profile| {
                enabled_profiles.contains(profile)
                    && CredentialProfileIdV1::parse(profile.clone()).is_ok_and(|profile| {
                        principal
                            .grant
                            .repository_access
                            .credential_profiles
                            .allows(&profile)
                    })
            })
        }
    }
}

async fn ensure_private_profile_enabled(
    store: &TursoCoordinatorStore,
    spec: &ScanSpecV1,
) -> Result<(), ControlApiStateError> {
    if spec.repository_scope == RepositoryScopeV1::PublicOnly {
        return Ok(());
    }
    let profile = spec
        .credential_profile_id
        .as_deref()
        .ok_or(ControlApiStateError::ValidationFailed)?;
    match store
        .credential_profile(profile)
        .await
        .map_err(|_| ControlApiStateError::Unavailable)?
    {
        Some(record) if record.enabled => Ok(()),
        Some(_) => Err(ControlApiStateError::Conflict),
        None => Err(ControlApiStateError::NotFound),
    }
}

fn classify_state_error(error: anyhow::Error) -> ControlApiStateError {
    let message = error.to_string();
    if message.contains("NotFound") || message.contains("not found") {
        ControlApiStateError::NotFound
    } else if message.contains("LimitExceeded") || message.contains("capacity") {
        ControlApiStateError::RateLimited
    } else if message.contains("Conflict")
        || message.contains("AlreadyExists")
        || message.contains("InvalidJobTransition")
        || message.contains("ActiveOccurrenceExists")
        || message.contains("ScheduleDeleted")
    {
        ControlApiStateError::Conflict
    } else if message.contains("InvalidBatch")
        || message.contains("InvalidIdentifier")
        || message.contains("InvalidRepositorySet")
        || message.contains("InvalidDefinition")
        || message.contains("InvalidScheduleId")
        || message.contains("InvalidScan")
        || message.contains("UnsupportedSchemaVersion")
        || message.contains("CadenceBelowOneHour")
    {
        ControlApiStateError::ValidationFailed
    } else {
        ControlApiStateError::Unavailable
    }
}
