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
    privacy: Option<Arc<crate::privacy::PrivacyService>>,
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
            privacy: None,
            store,
            inventory,
            oidc_policy,
            private_inventory_enabled,
        })
    }

    pub fn store(&self) -> &TursoCoordinatorStore {
        &self.store
    }

    pub fn with_privacy(mut self, privacy: Arc<crate::privacy::PrivacyService>) -> Self {
        self.privacy = Some(privacy);
        self
    }
}

impl ControlApiState for CoordinatorControlApiState {
    fn privacy(&self) -> Option<&Arc<crate::privacy::PrivacyService>> {
        self.privacy.as_ref()
    }
    fn github_provider_status(
        &self,
    ) -> BoxFuture<'_, Result<crate::coordinator::GithubProviderStatusV1, ControlApiStateError>>
    {
        Box::pin(async move {
            self.store
                .github_provider_status()
                .await
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn resume_github_provider(
        &self,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<crate::coordinator::GithubProviderStatusV1, ControlApiStateError>>
    {
        Box::pin(async move {
            self.store
                .apply(DurableCommandV1::ResumeGithubProvider { now })
                .await
                .map_err(|_| ControlApiStateError::Unavailable)?;
            self.store
                .github_provider_status()
                .await
                .map_err(|_| ControlApiStateError::Unavailable)
        })
    }

    fn inventory(&self) -> &(dyn InventoryProjectionStore + Send + Sync) {
        self.inventory.as_ref()
    }

    fn readiness(&self) -> BoxFuture<'_, Result<(), ControlApiStateError>> {
        Box::pin(async move {
            if let Some(privacy) = &self.privacy
                && !privacy.gate.read().await.ready
            {
                return Err(ControlApiStateError::Unavailable);
            }
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
                let mut eligible = BTreeSet::new();
                let now = Utc::now();
                for profile in selected {
                    if self
                        .store
                        .credential_profile(profile.as_str())
                        .await
                        .map_err(|_| ControlApiStateError::Unavailable)?
                        .is_some_and(|record| record.is_github_eligible(now))
                    {
                        eligible.insert(profile.as_str().to_owned());
                    }
                }
                eligible
            } else if scope.includes_all_credential_profiles() {
                // All-profile access is intentionally resolved from the durable
                // registry, never from names supplied by a search request.
                enabled_credential_profiles(&self.store).await?
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
    let now = Utc::now();
    Ok(store
        .control_snapshot()
        .await
        .map_err(|_| ControlApiStateError::Unavailable)?
        .credential_profiles
        .into_iter()
        .filter(|profile| profile.is_github_eligible(now))
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
        Some(record) if record.is_github_eligible(Utc::now()) => Ok(()),
        Some(_) | None => Err(ControlApiStateError::NotFound),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        catalog::{
            CatalogError, InMemoryInventoryStore, InventoryNamespaceV1, InventoryPageRequestV1,
            InventoryQueryV1,
        },
        control_auth::{
            ControlRoleV1, CredentialProfileAccessV1, InventoryScopeRequestV1,
            PrincipalAuthenticationV1, PrincipalGrantV1, PrincipalIdV1, RepositoryAccessV1,
            authorize_inventory_scope,
        },
        coordinator::{ControlActionV1, ScanBoundsV1, ScanTargetV1},
        secure_cache::EnvelopeKey,
    };
    use chrono::TimeDelta;

    fn reader(profiles: CredentialProfileAccessV1) -> ControlPrincipalV1 {
        ControlPrincipalV1 {
            schema_version: 1,
            id: PrincipalIdV1::parse("service_token:test-reader").unwrap(),
            authentication: PrincipalAuthenticationV1::ServiceToken {
                token_id: "test-reader".to_owned(),
            },
            grant: PrincipalGrantV1::for_roles(
                BTreeSet::from([ControlRoleV1::InventoryReader]),
                RepositoryAccessV1 {
                    public: true,
                    credential_profiles: profiles,
                },
            )
            .unwrap(),
        }
    }

    fn profile(id: &str, now: DateTime<Utc>) -> CredentialProfileV1 {
        CredentialProfileV1 {
            schema_version: 1,
            id: id.to_owned(),
            provider: "github".to_owned(),
            provider_host: "api.github.com".to_owned(),
            secret_reference: "vault://github/test".to_owned(),
            principal_fingerprint: "installation:42".to_owned(),
            secret_version: "1".to_owned(),
            enabled: true,
            expires_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn current_profiles_constrain_selected_all_and_scheduler_access() {
        let directory = tempfile::tempdir().unwrap();
        let store = TursoCoordinatorStore::open(
            directory.path().join("coordinator.db"),
            EnvelopeKey::generate("test-key"),
        )
        .await
        .unwrap();
        let now = Utc::now();
        let recorded_at = now - TimeDelta::hours(2);
        let mut expired = profile("expired", recorded_at);
        expired.expires_at = Some(now - TimeDelta::hours(1));
        let mut disabled = profile("disabled", recorded_at);
        disabled.enabled = false;
        let mut foreign = profile("foreign", recorded_at);
        foreign.provider_host = "github.example".to_owned();
        for record in [profile("active", recorded_at), expired, disabled, foreign] {
            store
                .apply_control(ControlCommandV1 {
                    schema_version: 1,
                    command_id: format!("register-{}", record.id),
                    expected_generation: None,
                    issued_at: recorded_at,
                    action: ControlActionV1::UpsertCredentialProfile { profile: record },
                })
                .await
                .unwrap();
        }
        let state = CoordinatorControlApiState::new(
            store.clone(),
            Arc::new(InMemoryInventoryStore::new([7; 32])),
            None,
            true,
        )
        .unwrap();
        let ids = ["active", "expired", "disabled", "foreign", "missing"]
            .map(|id| CredentialProfileIdV1::parse(id).unwrap());
        for profiles in [
            CredentialProfileAccessV1::All,
            CredentialProfileAccessV1::Selected {
                credential_profile_ids: ids.iter().cloned().collect(),
            },
        ] {
            let principal = reader(profiles);
            let scope =
                authorize_inventory_scope(&principal, &InventoryScopeRequestV1::AllAuthorized)
                    .unwrap();
            assert_eq!(
                state
                    .inventory_access(&principal, &scope)
                    .await
                    .unwrap()
                    .private_credential_profiles,
                BTreeSet::from(["active".to_owned()])
            );
            for id in &ids[1..] {
                let scope = authorize_inventory_scope(
                    &principal,
                    &InventoryScopeRequestV1::CredentialProfile {
                        credential_profile_id: id.clone(),
                    },
                )
                .unwrap();
                let access = state.inventory_access(&principal, &scope).await.unwrap();
                assert!(access.private_credential_profiles.is_empty());
                let query = InventoryQueryV1 {
                    schema_version: 1,
                    namespace: Some(InventoryNamespaceV1::Private {
                        credential_profile_id: id.as_str().to_owned(),
                    }),
                    ..InventoryQueryV1::default()
                };
                assert!(matches!(
                    state
                        .inventory()
                        .search(&access, &query, &InventoryPageRequestV1::default())
                        .await,
                    Err(CatalogError::Unauthorized)
                ));
            }
        }
        let private_spec = ScanSpecV1 {
            schema_version: 1,
            target: ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: RepositoryScopeV1::AllVisible,
            credential_profile_id: Some("active".to_owned()),
            bounds: ScanBoundsV1::default(),
            analyzer_versions: Default::default(),
        };
        assert!(
            state
                .scheduler_inventory_access(&private_spec)
                .await
                .is_ok()
        );
        store
            .apply_control(ControlCommandV1 {
                schema_version: 1,
                command_id: "revoke-active".to_owned(),
                expected_generation: None,
                issued_at: now,
                action: ControlActionV1::RevokeCredentialProfile {
                    profile_id: "active".to_owned(),
                },
            })
            .await
            .unwrap();
        assert!(matches!(
            state.scheduler_inventory_access(&private_spec).await,
            Err(ControlApiStateError::NotFound)
        ));
        assert!(matches!(
            state
                .validate_scan_spec_access(&reader(CredentialProfileAccessV1::All), &private_spec)
                .await,
            Err(ControlApiStateError::NotFound)
        ));
        let principal = reader(CredentialProfileAccessV1::All);
        let scope =
            authorize_inventory_scope(&principal, &InventoryScopeRequestV1::AllAuthorized).unwrap();
        assert!(
            state
                .inventory_access(&principal, &scope)
                .await
                .unwrap()
                .private_credential_profiles
                .is_empty()
        );
        let public_scope =
            authorize_inventory_scope(&principal, &InventoryScopeRequestV1::PublicOnly).unwrap();
        let disabled_state = CoordinatorControlApiState::new(
            store,
            Arc::new(InMemoryInventoryStore::new([8; 32])),
            None,
            false,
        )
        .unwrap();
        assert!(
            disabled_state
                .inventory_access(&principal, &public_scope)
                .await
                .unwrap()
                .private_credential_profiles
                .is_empty()
        );
    }
}
