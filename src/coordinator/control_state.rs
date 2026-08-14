//! Pure control-plane aggregate for schedules and control metadata.
//!
//! The aggregate retains repository sets, revisions, occurrences, credential
//! profiles, and service-token metadata. Jobs and tasks live exclusively in
//! the legacy execution store; the compatibility fields below are never used
//! as execution authority.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::control_auth::{ServiceTokenIdV1, ServiceTokenRecordV1};
use crate::secure_cache::sha256_hex;

use super::{
    credential::CredentialProfileV1,
    dispatch::{
        DeadLetterTaskV1, DispatchError, DispatchJobV1, DispatchSelectionV1, IndexedTaskV1,
        RepositorySetRefV1, RetryDecisionV1, RetryPolicyV1, TaskFailureKindV1,
    },
    domain::{JobId, SCHEMA_VERSION_V1, Sha256Digest, TaskId},
    schedule::{
        CreateScheduleV1, InMemoryScheduler, MaterializationDecisionV1, OccurrenceId,
        OccurrencePlanV1, OccurrenceStateV1, RepositorySetSnapshotV1, SavedQueryRefreshV1,
        ScanScheduleV1, ScheduleDefinitionV1, ScheduleError, ScheduleId, ScheduleOccurrenceV1,
        ScheduleRevisionV1, SchedulerSnapshotV1, resolve_repository_source,
    },
};

pub const MAX_REPOSITORIES_PER_SET: usize = 10_000;
pub const CONTROL_COMMAND_RECEIPT_RETENTION_DAYS: i64 = 7;
pub const MAX_CONTROL_COMMAND_RECEIPTS: usize = 50_000;
const REPOSITORY_SET_DIGEST_DOMAIN: &[u8] = b"crate-dependent-repos/repository-set-content/v1\0";
const COMMAND_DIGEST_DOMAIN: &[u8] = b"crate-dependent-repos/control-command/v1\0";

/// Canonically sorted repository identities covered by a content digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositorySetContentV1 {
    pub schema_version: u16,
    pub repository_set: RepositorySetRefV1,
    pub repository_ids: Vec<String>,
}

impl RepositorySetContentV1 {
    pub fn from_repositories(mut repository_ids: Vec<String>) -> Result<Self, ControlStateError> {
        repository_ids.sort();
        let repository_set = RepositorySetRefV1 {
            schema_version: SCHEMA_VERSION_V1,
            digest: digest_repository_set(&repository_ids)?,
            repository_count: repository_ids.len() as u64,
        };
        let content = Self {
            schema_version: SCHEMA_VERSION_V1,
            repository_set,
            repository_ids,
        };
        content.validate()?;
        Ok(content)
    }

    pub fn validate(&self) -> Result<(), ControlStateError> {
        validate_schema(self.schema_version)?;
        self.repository_set
            .validate()
            .map_err(ControlStateError::Dispatch)?;
        if self.repository_ids.len() > MAX_REPOSITORIES_PER_SET
            || self.repository_set.repository_count != self.repository_ids.len() as u64
            || self
                .repository_ids
                .iter()
                .any(|repository| !normalized_repository(repository))
            || self
                .repository_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || digest_repository_set(&self.repository_ids)? != self.repository_set.digest
        {
            return Err(ControlStateError::InvalidRepositorySet);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ScheduledOccurrenceRefV1 {
    pub schedule_id: ScheduleId,
    pub occurrence_id: OccurrenceId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OccurrenceMaterializationV1 {
    pub schema_version: u16,
    pub occurrence: ScheduledOccurrenceRefV1,
    pub decision: MaterializationDecisionV1,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlTaskStateV1 {
    Pending,
    Leased,
    Succeeded,
    DeadLetter,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlTaskV1 {
    pub schema_version: u16,
    pub task: IndexedTaskV1,
    pub repository_id: String,
    pub state: ControlTaskStateV1,
    pub attempts: u32,
    pub last_failure: Option<TaskFailureKindV1>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlLeaseV1 {
    pub schema_version: u16,
    pub lease_id: String,
    pub agent_id: String,
    pub task_id: TaskId,
    pub attempt: u32,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeasedTaskV1 {
    pub schema_version: u16,
    pub selection: DispatchSelectionV1,
    pub repository_id: String,
    pub lease: ControlLeaseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskFailureOutcomeV1 {
    pub schema_version: u16,
    pub task_id: TaskId,
    pub decision: RetryDecisionV1,
}

/// A normalized, idempotent control-plane command envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlCommandV1 {
    pub schema_version: u16,
    pub command_id: String,
    pub expected_generation: Option<u64>,
    pub issued_at: DateTime<Utc>,
    pub action: ControlActionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ControlActionV1 {
    RegisterRepositorySet {
        content: RepositorySetContentV1,
    },
    CreateSchedule {
        request: CreateScheduleV1,
        #[serde(default)]
        repository_set_content: Option<RepositorySetContentV1>,
    },
    ReviseSchedule {
        schedule_id: ScheduleId,
        expected_revision: u64,
        definition: ScheduleDefinitionV1,
        #[serde(default)]
        repository_set_content: Option<RepositorySetContentV1>,
    },
    SetScheduleEnabled {
        schedule_id: ScheduleId,
        expected_revision: u64,
        enabled: bool,
    },
    DeleteSchedule {
        schedule_id: ScheduleId,
        expected_revision: u64,
    },
    TriggerSchedule {
        schedule_id: ScheduleId,
    },
    TickSchedules,
    ClaimOccurrence {
        schedule_id: ScheduleId,
    },
    MaterializeOccurrence {
        occurrence: ScheduledOccurrenceRefV1,
        refresh: Option<SavedQueryRefreshV1>,
        last_complete: Option<RepositorySetSnapshotV1>,
        repository_set_content: Option<RepositorySetContentV1>,
    },
    /// Link an occurrence to a job already submitted to the canonical legacy
    /// execution store. This is metadata only and creates no shadow job.
    AttachOccurrenceJob {
        occurrence: ScheduledOccurrenceRefV1,
        job_id: JobId,
    },
    /// Mirror a canonical legacy job terminal state onto its occurrence.
    FinishOccurrence {
        occurrence: ScheduledOccurrenceRefV1,
        terminal_state: OccurrenceStateV1,
    },
    UpsertCredentialProfile {
        profile: CredentialProfileV1,
    },
    RevokeCredentialProfile {
        profile_id: String,
    },
    UpsertServiceToken {
        record: ServiceTokenRecordV1,
    },
    RevokeServiceToken {
        token_id: ServiceTokenIdV1,
    },
    PruneBefore {
        cutoff: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlOutcomeV1 {
    pub schema_version: u16,
    pub command_id: String,
    pub generation: u64,
    pub result: ControlResultV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ControlResultV1 {
    RepositorySetRegistered {
        repository_set: RepositorySetRefV1,
    },
    ScheduleCreated {
        schedule_id: ScheduleId,
    },
    ScheduleRevised {
        revision: u64,
    },
    ScheduleUpdated,
    OccurrencePlanned {
        plan: OccurrencePlanV1,
    },
    OccurrencesPlanned {
        plans: Vec<OccurrencePlanV1>,
    },
    OccurrenceClaimed {
        occurrence: Option<ScheduleOccurrenceV1>,
    },
    OccurrenceMaterialized {
        decision: MaterializationDecisionV1,
    },
    OccurrenceJobAttached {
        job_id: JobId,
    },
    OccurrenceFinished,
    CredentialProfileStored {
        profile_id: String,
    },
    ServiceTokenStored {
        token_id: ServiceTokenIdV1,
    },
    ControlHistoryPruned {
        summary: ControlRetentionSummaryV1,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlRetentionSummaryV1 {
    pub schedules: usize,
    pub revisions: usize,
    pub occurrences: usize,
    pub materializations: usize,
    pub repository_sets: usize,
    pub credential_profiles: usize,
    pub service_tokens: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessedControlCommandV1 {
    pub schema_version: u16,
    pub command_id: String,
    pub command_digest: Sha256Digest,
    pub outcome: ControlOutcomeV1,
    /// Receipts are retained only for the documented retry window.
    #[serde(default = "legacy_processed_at")]
    pub processed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlStateSnapshotV1 {
    pub schema_version: u16,
    pub generation: u64,
    pub scheduler: SchedulerSnapshotV1,
    /// Legacy shadow-execution fields are accepted during restore and emitted
    /// empty for wire compatibility. The legacy execution store is canonical.
    #[serde(default)]
    pub jobs: Vec<DispatchJobV1>,
    pub repository_sets: Vec<RepositorySetContentV1>,
    #[serde(default)]
    pub tasks: Vec<ControlTaskV1>,
    #[serde(default)]
    pub leases: Vec<ControlLeaseV1>,
    #[serde(default)]
    pub dead_letters: Vec<DeadLetterTaskV1>,
    pub occurrence_materializations: Vec<OccurrenceMaterializationV1>,
    #[serde(default)]
    pub job_origins: Vec<(JobId, ScheduledOccurrenceRefV1)>,
    #[serde(default)]
    pub retry_policy: RetryPolicyV1,
    pub credential_profiles: Vec<CredentialProfileV1>,
    pub service_tokens: Vec<ServiceTokenRecordV1>,
    #[serde(default)]
    pub processed_commands: Vec<ProcessedControlCommandV1>,
}

#[derive(Clone, Debug, Default)]
pub struct ControlState {
    generation: u64,
    scheduler: InMemoryScheduler,
    repository_sets: BTreeMap<Sha256Digest, RepositorySetContentV1>,
    occurrence_materializations: BTreeMap<OccurrenceId, OccurrenceMaterializationV1>,
    credential_profiles: BTreeMap<String, CredentialProfileV1>,
    service_tokens: BTreeMap<ServiceTokenIdV1, ServiceTokenRecordV1>,
    processed_commands: BTreeMap<String, ProcessedControlCommandV1>,
}

impl ControlState {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn apply(
        &mut self,
        command: ControlCommandV1,
    ) -> Result<ControlOutcomeV1, ControlStateError> {
        validate_schema(command.schema_version)?;
        if !normalized_identifier(&command.command_id) {
            return Err(ControlStateError::InvalidIdentifier);
        }
        self.prune_processed_commands(command.issued_at);
        let command_digest = digest_command(&command)?;
        if let Some(processed) = self.processed_commands.get(&command.command_id) {
            return if processed.command_digest == command_digest {
                Ok(processed.outcome.clone())
            } else {
                Err(ControlStateError::IdempotencyConflict)
            };
        }
        if command
            .expected_generation
            .is_some_and(|expected| expected != self.generation)
        {
            return Err(ControlStateError::GenerationConflict {
                expected: command.expected_generation.expect("checked as present"),
                actual: self.generation,
            });
        }

        let result = self.execute(&command.action, command.issued_at)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(ControlStateError::GenerationOverflow)?;
        let outcome = ControlOutcomeV1 {
            schema_version: SCHEMA_VERSION_V1,
            command_id: command.command_id.clone(),
            generation,
            result,
        };
        self.generation = generation;
        self.processed_commands.insert(
            command.command_id.clone(),
            ProcessedControlCommandV1 {
                schema_version: SCHEMA_VERSION_V1,
                command_id: command.command_id,
                command_digest,
                outcome: outcome.clone(),
                processed_at: command.issued_at,
            },
        );
        Ok(outcome)
    }

    pub fn schedule(&self, schedule_id: &ScheduleId) -> Option<&ScanScheduleV1> {
        self.scheduler.schedule(schedule_id)
    }

    pub fn schedule_revision(
        &self,
        schedule_id: &ScheduleId,
        revision: u64,
    ) -> Option<&ScheduleRevisionV1> {
        self.scheduler.revision(schedule_id, revision)
    }

    pub fn occurrence(
        &self,
        occurrence: &ScheduledOccurrenceRefV1,
    ) -> Option<&ScheduleOccurrenceV1> {
        self.scheduler
            .occurrence(&occurrence.schedule_id, &occurrence.occurrence_id)
    }

    pub(crate) fn retained_job_ids(&self) -> impl Iterator<Item = &JobId> {
        self.scheduler.referenced_job_ids()
    }

    pub fn job(&self, job_id: &JobId) -> Option<&DispatchJobV1> {
        let _ = job_id;
        None
    }

    pub fn task(&self, task_id: &TaskId) -> Option<&ControlTaskV1> {
        let _ = task_id;
        None
    }

    pub fn credential_profile(&self, profile_id: &str) -> Option<&CredentialProfileV1> {
        self.credential_profiles.get(profile_id)
    }

    pub fn service_token(&self, token_id: &ServiceTokenIdV1) -> Option<&ServiceTokenRecordV1> {
        self.service_tokens.get(token_id)
    }

    pub fn snapshot(&self) -> ControlStateSnapshotV1 {
        ControlStateSnapshotV1 {
            schema_version: SCHEMA_VERSION_V1,
            generation: self.generation,
            scheduler: self.scheduler.snapshot(),
            jobs: Vec::new(),
            repository_sets: self.repository_sets.values().cloned().collect(),
            tasks: Vec::new(),
            leases: Vec::new(),
            dead_letters: Vec::new(),
            occurrence_materializations: self
                .occurrence_materializations
                .values()
                .cloned()
                .collect(),
            job_origins: Vec::new(),
            retry_policy: RetryPolicyV1::default(),
            credential_profiles: self.credential_profiles.values().cloned().collect(),
            service_tokens: self.service_tokens.values().cloned().collect(),
            processed_commands: self.processed_commands.values().cloned().collect(),
        }
    }

    pub fn restore(snapshot: ControlStateSnapshotV1) -> Result<Self, ControlStateError> {
        validate_schema(snapshot.schema_version)?;
        let scheduler =
            InMemoryScheduler::restore(snapshot.scheduler).map_err(ControlStateError::Schedule)?;
        let repository_sets = collect_repository_sets(snapshot.repository_sets)?;
        let occurrence_materializations =
            collect_materializations(snapshot.occurrence_materializations, &scheduler)?;
        let credential_profiles =
            collect_credential_profiles(snapshot.credential_profiles, DateTime::<Utc>::MIN_UTC)?;
        let service_tokens = collect_service_tokens(snapshot.service_tokens)?;
        let processed_commands =
            collect_processed_commands(snapshot.processed_commands, snapshot.generation)?;
        Ok(Self {
            generation: snapshot.generation,
            scheduler,
            repository_sets,
            occurrence_materializations,
            credential_profiles,
            service_tokens,
            processed_commands,
        })
    }

    fn execute(
        &mut self,
        action: &ControlActionV1,
        now: DateTime<Utc>,
    ) -> Result<ControlResultV1, ControlStateError> {
        match action {
            ControlActionV1::RegisterRepositorySet { content } => {
                self.register_repository_set(content.clone())?;
                Ok(ControlResultV1::RepositorySetRegistered {
                    repository_set: content.repository_set.clone(),
                })
            }
            ControlActionV1::CreateSchedule {
                request,
                repository_set_content,
            } => {
                let mut repository_sets = self.repository_sets.clone();
                register_definition_content(
                    &mut repository_sets,
                    &request.definition,
                    repository_set_content.as_ref(),
                )?;
                validate_schedule_repository_source(request, &repository_sets)?;
                let mut scheduler = self.scheduler.clone();
                let schedule_id = scheduler
                    .create(request.clone())
                    .map_err(ControlStateError::Schedule)?;
                self.repository_sets = repository_sets;
                self.scheduler = scheduler;
                Ok(ControlResultV1::ScheduleCreated { schedule_id })
            }
            ControlActionV1::ReviseSchedule {
                schedule_id,
                expected_revision,
                definition,
                repository_set_content,
            } => {
                let mut repository_sets = self.repository_sets.clone();
                register_definition_content(
                    &mut repository_sets,
                    definition,
                    repository_set_content.as_ref(),
                )?;
                validate_definition_repository_source(definition, &repository_sets)?;
                let mut scheduler = self.scheduler.clone();
                let revision = scheduler
                    .revise(schedule_id, *expected_revision, definition.clone(), now)
                    .map_err(ControlStateError::Schedule)?;
                self.repository_sets = repository_sets;
                self.scheduler = scheduler;
                Ok(ControlResultV1::ScheduleRevised { revision })
            }
            ControlActionV1::SetScheduleEnabled {
                schedule_id,
                expected_revision,
                enabled,
            } => {
                self.scheduler
                    .set_enabled(schedule_id, *expected_revision, *enabled, now)
                    .map_err(ControlStateError::Schedule)?;
                Ok(ControlResultV1::ScheduleUpdated)
            }
            ControlActionV1::DeleteSchedule {
                schedule_id,
                expected_revision,
            } => {
                self.scheduler
                    .delete(schedule_id, *expected_revision, now)
                    .map_err(ControlStateError::Schedule)?;
                Ok(ControlResultV1::ScheduleUpdated)
            }
            ControlActionV1::TriggerSchedule { schedule_id } => {
                let plan = self
                    .scheduler
                    .manual_trigger(schedule_id, now)
                    .map_err(ControlStateError::Schedule)?;
                Ok(ControlResultV1::OccurrencePlanned { plan })
            }
            ControlActionV1::TickSchedules => {
                let mut scheduler = self.scheduler.clone();
                let plans = scheduler.tick(now).map_err(ControlStateError::Schedule)?;
                self.scheduler = scheduler;
                Ok(ControlResultV1::OccurrencesPlanned { plans })
            }
            ControlActionV1::ClaimOccurrence { schedule_id } => {
                let occurrence = self
                    .scheduler
                    .claim_pending(schedule_id)
                    .map_err(ControlStateError::Schedule)?;
                Ok(ControlResultV1::OccurrenceClaimed { occurrence })
            }
            ControlActionV1::MaterializeOccurrence {
                occurrence,
                refresh,
                last_complete,
                repository_set_content,
            } => self.materialize_occurrence(
                occurrence,
                refresh.as_ref(),
                last_complete.as_ref(),
                repository_set_content.as_ref(),
                now,
            ),
            ControlActionV1::AttachOccurrenceJob { occurrence, job_id } => {
                self.attach_occurrence_job(occurrence, job_id.clone())
            }
            ControlActionV1::FinishOccurrence {
                occurrence,
                terminal_state,
            } => self.finish_occurrence(occurrence, *terminal_state, now),
            ControlActionV1::UpsertCredentialProfile { profile } => {
                self.upsert_credential_profile(profile.clone(), now)
            }
            ControlActionV1::RevokeCredentialProfile { profile_id } => {
                self.revoke_credential_profile(profile_id, now)
            }
            ControlActionV1::UpsertServiceToken { record } => {
                self.upsert_service_token(record.clone())
            }
            ControlActionV1::RevokeServiceToken { token_id } => {
                self.revoke_service_token(token_id, now)
            }
            ControlActionV1::PruneBefore { cutoff } => self.prune_before(*cutoff),
        }
    }

    fn prune_processed_commands(&mut self, now: DateTime<Utc>) {
        let cutoff = now
            .checked_sub_signed(TimeDelta::days(CONTROL_COMMAND_RECEIPT_RETENTION_DAYS))
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        self.processed_commands
            .retain(|_, receipt| receipt.processed_at >= cutoff);
        while self.processed_commands.len() >= MAX_CONTROL_COMMAND_RECEIPTS {
            let Some(oldest) = self
                .processed_commands
                .iter()
                .min_by(|left, right| {
                    left.1
                        .processed_at
                        .cmp(&right.1.processed_at)
                        .then_with(|| left.0.cmp(right.0))
                })
                .map(|(command_id, _)| command_id.clone())
            else {
                break;
            };
            self.processed_commands.remove(&oldest);
        }
    }

    fn register_repository_set(
        &mut self,
        content: RepositorySetContentV1,
    ) -> Result<(), ControlStateError> {
        content.validate()?;
        let digest = content.repository_set.digest.clone();
        if let Some(existing) = self.repository_sets.get(&digest) {
            return if existing == &content {
                Ok(())
            } else {
                Err(ControlStateError::RepositorySetDigestConflict)
            };
        }
        self.repository_sets.insert(digest, content);
        Ok(())
    }

    fn materialize_occurrence(
        &mut self,
        occurrence_ref: &ScheduledOccurrenceRefV1,
        refresh: Option<&SavedQueryRefreshV1>,
        last_complete: Option<&RepositorySetSnapshotV1>,
        content: Option<&RepositorySetContentV1>,
        now: DateTime<Utc>,
    ) -> Result<ControlResultV1, ControlStateError> {
        let occurrence = self
            .occurrence(occurrence_ref)
            .ok_or(ControlStateError::OccurrenceNotFound)?;
        if occurrence.state != OccurrenceStateV1::Active {
            return Err(ControlStateError::InvalidOccurrenceState);
        }
        let revision = self
            .scheduler
            .revision(&occurrence_ref.schedule_id, occurrence.schedule_revision)
            .ok_or(ControlStateError::InvalidOccurrenceState)?;
        let decision =
            resolve_repository_source(&revision.repository_source, refresh, last_complete, now)
                .map_err(ControlStateError::Schedule)?;

        if let Some(existing) = self
            .occurrence_materializations
            .get(&occurrence_ref.occurrence_id)
        {
            return if existing.decision == decision {
                Ok(ControlResultV1::OccurrenceMaterialized { decision })
            } else {
                Err(ControlStateError::MaterializationConflict)
            };
        }

        match &decision {
            MaterializationDecisionV1::Ready { selection } => {
                if let Some(content) = content {
                    if content.repository_set != selection.repository_set {
                        return Err(ControlStateError::RepositorySetMismatch);
                    }
                    self.register_repository_set(content.clone())?;
                }
                if !self
                    .repository_sets
                    .contains_key(&selection.repository_set.digest)
                {
                    return Err(ControlStateError::RepositorySetContentMissing);
                }
            }
            MaterializationDecisionV1::SkippedEmpty { .. } => {
                let mut scheduler = self.scheduler.clone();
                scheduler
                    .finish_active(
                        &occurrence_ref.schedule_id,
                        &occurrence_ref.occurrence_id,
                        OccurrenceStateV1::Skipped,
                        now,
                    )
                    .map_err(ControlStateError::Schedule)?;
                self.scheduler = scheduler;
            }
            MaterializationDecisionV1::Blocked { .. } => {
                let mut scheduler = self.scheduler.clone();
                scheduler
                    .finish_active(
                        &occurrence_ref.schedule_id,
                        &occurrence_ref.occurrence_id,
                        OccurrenceStateV1::Blocked,
                        now,
                    )
                    .map_err(ControlStateError::Schedule)?;
                self.scheduler = scheduler;
            }
        }
        self.occurrence_materializations.insert(
            occurrence_ref.occurrence_id.clone(),
            OccurrenceMaterializationV1 {
                schema_version: SCHEMA_VERSION_V1,
                occurrence: occurrence_ref.clone(),
                decision: decision.clone(),
                observed_at: now,
            },
        );
        Ok(ControlResultV1::OccurrenceMaterialized { decision })
    }

    fn attach_occurrence_job(
        &mut self,
        occurrence: &ScheduledOccurrenceRefV1,
        job_id: JobId,
    ) -> Result<ControlResultV1, ControlStateError> {
        let materialization = self
            .occurrence_materializations
            .get(&occurrence.occurrence_id)
            .ok_or(ControlStateError::OccurrenceNotMaterialized)?;
        if materialization.occurrence != *occurrence
            || !matches!(
                materialization.decision,
                MaterializationDecisionV1::Ready { .. }
            )
        {
            return Err(ControlStateError::InvalidOccurrenceState);
        }
        self.scheduler
            .attach_job(
                &occurrence.schedule_id,
                &occurrence.occurrence_id,
                job_id.clone(),
            )
            .map_err(ControlStateError::Schedule)?;
        Ok(ControlResultV1::OccurrenceJobAttached { job_id })
    }

    fn finish_occurrence(
        &mut self,
        occurrence: &ScheduledOccurrenceRefV1,
        terminal_state: OccurrenceStateV1,
        now: DateTime<Utc>,
    ) -> Result<ControlResultV1, ControlStateError> {
        if !matches!(
            terminal_state,
            OccurrenceStateV1::Completed | OccurrenceStateV1::Failed
        ) {
            return Err(ControlStateError::InvalidOccurrenceState);
        }
        self.scheduler
            .finish_active(
                &occurrence.schedule_id,
                &occurrence.occurrence_id,
                terminal_state,
                now,
            )
            .map_err(ControlStateError::Schedule)?;
        Ok(ControlResultV1::OccurrenceFinished)
    }

    fn upsert_credential_profile(
        &mut self,
        profile: CredentialProfileV1,
        now: DateTime<Utc>,
    ) -> Result<ControlResultV1, ControlStateError> {
        profile
            .validate(now)
            .map_err(|error| ControlStateError::InvalidCredentialProfile(error.to_string()))?;
        if let Some(existing) = self.credential_profiles.get(&profile.id)
            && (profile.created_at != existing.created_at
                || profile.updated_at < existing.updated_at)
        {
            return Err(ControlStateError::CredentialProfileConflict);
        }
        let profile_id = profile.id.clone();
        self.credential_profiles.insert(profile_id.clone(), profile);
        Ok(ControlResultV1::CredentialProfileStored { profile_id })
    }

    fn revoke_credential_profile(
        &mut self,
        profile_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ControlResultV1, ControlStateError> {
        let profile = self
            .credential_profiles
            .get_mut(profile_id)
            .ok_or(ControlStateError::CredentialProfileNotFound)?;
        profile.enabled = false;
        profile.updated_at = profile.updated_at.max(now);
        Ok(ControlResultV1::CredentialProfileStored {
            profile_id: profile_id.to_owned(),
        })
    }

    fn upsert_service_token(
        &mut self,
        record: ServiceTokenRecordV1,
    ) -> Result<ControlResultV1, ControlStateError> {
        record
            .validate()
            .map_err(|error| ControlStateError::InvalidServiceToken(error.to_string()))?;
        if let Some(existing) = self.service_tokens.get(&record.id)
            && existing != &record
        {
            return Err(ControlStateError::ServiceTokenConflict);
        }
        let token_id = record.id.clone();
        self.service_tokens.insert(token_id.clone(), record);
        Ok(ControlResultV1::ServiceTokenStored { token_id })
    }

    fn revoke_service_token(
        &mut self,
        token_id: &ServiceTokenIdV1,
        now: DateTime<Utc>,
    ) -> Result<ControlResultV1, ControlStateError> {
        let record = self
            .service_tokens
            .get_mut(token_id)
            .ok_or(ControlStateError::ServiceTokenNotFound)?;
        record.revoke(now);
        Ok(ControlResultV1::ServiceTokenStored {
            token_id: token_id.clone(),
        })
    }

    fn prune_before(
        &mut self,
        cutoff: DateTime<Utc>,
    ) -> Result<ControlResultV1, ControlStateError> {
        let scheduler = self.scheduler.prune_before(cutoff);
        let retained_occurrences = self.scheduler.retained_occurrence_ids();

        let before_materializations = self.occurrence_materializations.len();
        self.occurrence_materializations
            .retain(|occurrence_id, _| retained_occurrences.contains(occurrence_id));

        let mut referenced_sets = self.scheduler.referenced_repository_sets();
        referenced_sets.extend(self.occurrence_materializations.values().filter_map(
            |materialization| match &materialization.decision {
                MaterializationDecisionV1::Ready { selection } => {
                    Some(selection.repository_set.digest.clone())
                }
                MaterializationDecisionV1::SkippedEmpty { .. }
                | MaterializationDecisionV1::Blocked { .. } => None,
            },
        ));
        let before_repository_sets = self.repository_sets.len();
        self.repository_sets
            .retain(|digest, _| referenced_sets.contains(digest));

        let referenced_profiles = self.scheduler.referenced_credential_profiles();
        let before_profiles = self.credential_profiles.len();
        self.credential_profiles.retain(|profile_id, profile| {
            referenced_profiles.contains(profile_id)
                || profile.updated_at >= cutoff
                || (profile.enabled && profile.expires_at.is_none_or(|expiry| expiry >= cutoff))
        });

        let before_tokens = self.service_tokens.len();
        self.service_tokens.retain(|_, token| {
            token.expires_at >= cutoff
                && token
                    .revoked_at
                    .is_none_or(|revoked_at| revoked_at >= cutoff)
        });

        Ok(ControlResultV1::ControlHistoryPruned {
            summary: ControlRetentionSummaryV1 {
                schedules: scheduler.schedules,
                revisions: scheduler.revisions,
                occurrences: scheduler.occurrences,
                materializations: before_materializations - self.occurrence_materializations.len(),
                repository_sets: before_repository_sets - self.repository_sets.len(),
                credential_profiles: before_profiles - self.credential_profiles.len(),
                service_tokens: before_tokens - self.service_tokens.len(),
            },
        })
    }
}
fn collect_repository_sets(
    contents: Vec<RepositorySetContentV1>,
) -> Result<BTreeMap<Sha256Digest, RepositorySetContentV1>, ControlStateError> {
    let mut result = BTreeMap::new();
    for content in contents {
        content.validate()?;
        let digest = content.repository_set.digest.clone();
        if result.insert(digest, content).is_some() {
            return Err(ControlStateError::InvalidSnapshot);
        }
    }
    Ok(result)
}

fn collect_materializations(
    materializations: Vec<OccurrenceMaterializationV1>,
    scheduler: &InMemoryScheduler,
) -> Result<BTreeMap<OccurrenceId, OccurrenceMaterializationV1>, ControlStateError> {
    let mut result = BTreeMap::new();
    for materialization in materializations {
        validate_schema(materialization.schema_version)?;
        if scheduler
            .occurrence(
                &materialization.occurrence.schedule_id,
                &materialization.occurrence.occurrence_id,
            )
            .is_none()
            || result
                .insert(
                    materialization.occurrence.occurrence_id.clone(),
                    materialization,
                )
                .is_some()
        {
            return Err(ControlStateError::InvalidSnapshot);
        }
    }
    Ok(result)
}

fn collect_credential_profiles(
    profiles: Vec<CredentialProfileV1>,
    validation_time: DateTime<Utc>,
) -> Result<BTreeMap<String, CredentialProfileV1>, ControlStateError> {
    let mut result = BTreeMap::new();
    for profile in profiles {
        profile
            .validate(validation_time)
            .map_err(|error| ControlStateError::InvalidCredentialProfile(error.to_string()))?;
        if result.insert(profile.id.clone(), profile).is_some() {
            return Err(ControlStateError::InvalidSnapshot);
        }
    }
    Ok(result)
}

fn collect_service_tokens(
    records: Vec<ServiceTokenRecordV1>,
) -> Result<BTreeMap<ServiceTokenIdV1, ServiceTokenRecordV1>, ControlStateError> {
    let mut result = BTreeMap::new();
    for record in records {
        record
            .validate()
            .map_err(|error| ControlStateError::InvalidServiceToken(error.to_string()))?;
        if result.insert(record.id.clone(), record).is_some() {
            return Err(ControlStateError::InvalidSnapshot);
        }
    }
    Ok(result)
}

fn collect_processed_commands(
    commands: Vec<ProcessedControlCommandV1>,
    generation: u64,
) -> Result<BTreeMap<String, ProcessedControlCommandV1>, ControlStateError> {
    let mut result = BTreeMap::new();
    for command in commands {
        validate_schema(command.schema_version)?;
        validate_schema(command.outcome.schema_version)?;
        if !normalized_identifier(&command.command_id)
            || command.command_id != command.outcome.command_id
            || command.outcome.generation > generation
            || result.insert(command.command_id.clone(), command).is_some()
        {
            return Err(ControlStateError::InvalidSnapshot);
        }
    }
    while result.len() > MAX_CONTROL_COMMAND_RECEIPTS {
        let oldest = result
            .iter()
            .min_by(|left, right| {
                left.1
                    .processed_at
                    .cmp(&right.1.processed_at)
                    .then_with(|| left.0.cmp(right.0))
            })
            .map(|(command_id, _)| command_id.clone())
            .expect("an over-cap receipt map is non-empty");
        result.remove(&oldest);
    }
    Ok(result)
}

fn validate_schedule_repository_source(
    request: &CreateScheduleV1,
    repository_sets: &BTreeMap<Sha256Digest, RepositorySetContentV1>,
) -> Result<(), ControlStateError> {
    validate_definition_repository_source(&request.definition, repository_sets)
}

fn register_definition_content(
    repository_sets: &mut BTreeMap<Sha256Digest, RepositorySetContentV1>,
    definition: &ScheduleDefinitionV1,
    content: Option<&RepositorySetContentV1>,
) -> Result<(), ControlStateError> {
    match (&definition.repository_source, content) {
        (super::schedule::RepositorySourceRefV1::Explicit { repository_set }, Some(content))
            if &content.repository_set == repository_set =>
        {
            content.validate()?;
            match repository_sets.get(&repository_set.digest) {
                Some(existing) if existing != content => {
                    Err(ControlStateError::RepositorySetDigestConflict)
                }
                Some(_) => Ok(()),
                None => {
                    repository_sets.insert(repository_set.digest.clone(), content.clone());
                    Ok(())
                }
            }
        }
        (super::schedule::RepositorySourceRefV1::Explicit { .. }, None)
        | (super::schedule::RepositorySourceRefV1::SavedQuery { .. }, None) => Ok(()),
        _ => Err(ControlStateError::RepositorySetMismatch),
    }
}

fn validate_definition_repository_source(
    definition: &ScheduleDefinitionV1,
    repository_sets: &BTreeMap<Sha256Digest, RepositorySetContentV1>,
) -> Result<(), ControlStateError> {
    if let super::schedule::RepositorySourceRefV1::Explicit { repository_set } =
        &definition.repository_source
        && repository_sets
            .get(&repository_set.digest)
            .is_none_or(|content| content.repository_set != *repository_set)
    {
        return Err(ControlStateError::RepositorySetContentMissing);
    }
    Ok(())
}

fn digest_repository_set(repository_ids: &[String]) -> Result<Sha256Digest, ControlStateError> {
    if repository_ids.len() > MAX_REPOSITORIES_PER_SET {
        return Err(ControlStateError::InvalidRepositorySet);
    }
    let mut hasher = Sha256::new();
    hasher.update(REPOSITORY_SET_DIGEST_DOMAIN);
    for repository_id in repository_ids {
        if !normalized_repository(repository_id) {
            return Err(ControlStateError::InvalidRepositorySet);
        }
        hash_part(&mut hasher, repository_id.as_bytes());
    }
    Sha256Digest::parse(sha256_hex(&hasher.finalize()))
        .map_err(|_| ControlStateError::InvalidRepositorySet)
}

fn digest_command(command: &ControlCommandV1) -> Result<Sha256Digest, ControlStateError> {
    // Delivery time is not part of semantic request identity. This lets an
    // HTTP client retry the same idempotency key without preserving a hidden
    // first-attempt timestamp.
    let mut action = command.action.clone();
    if let ControlActionV1::CreateSchedule { request, .. } = &mut action {
        request.created_at = DateTime::<Utc>::MIN_UTC;
    }
    let bytes = serde_json::to_vec(&(
        command.schema_version,
        &command.command_id,
        command.expected_generation,
        &action,
    ))
    .map_err(|error| ControlStateError::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(COMMAND_DIGEST_DOMAIN);
    hasher.update(bytes);
    Sha256Digest::parse(sha256_hex(&hasher.finalize()))
        .map_err(|_| ControlStateError::InvalidSnapshot)
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_schema(schema_version: u16) -> Result<(), ControlStateError> {
    if schema_version != SCHEMA_VERSION_V1 {
        return Err(ControlStateError::UnsupportedSchemaVersion(schema_version));
    }
    Ok(())
}

fn normalized_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn normalized_repository(value: &str) -> bool {
    normalized_identifier(value)
        && value.split_once('/').is_some_and(|(owner, name)| {
            !owner.is_empty()
                && !name.is_empty()
                && !name.contains('/')
                && owner.bytes().all(repository_byte)
                && name.bytes().all(repository_byte)
        })
}

fn repository_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn legacy_processed_at() -> DateTime<Utc> {
    DateTime::<Utc>::MIN_UTC
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlStateError {
    Dispatch(DispatchError),
    Schedule(ScheduleError),
    UnsupportedSchemaVersion(u16),
    InvalidIdentifier,
    InvalidRepositorySet,
    RepositorySetDigestConflict,
    RepositorySetContentMissing,
    RepositorySetMismatch,
    OccurrenceNotFound,
    OccurrenceNotMaterialized,
    InvalidOccurrenceState,
    MaterializationConflict,
    InvalidCredentialProfile(String),
    CredentialProfileConflict,
    CredentialProfileNotFound,
    InvalidServiceToken(String),
    ServiceTokenConflict,
    ServiceTokenNotFound,
    IdempotencyConflict,
    GenerationConflict { expected: u64, actual: u64 },
    GenerationOverflow,
    Serialization(String),
    InvalidSnapshot,
}

impl std::fmt::Display for ControlStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ControlStateError {}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};

    use super::*;

    #[test]
    fn command_receipts_deduplicate_within_window_and_expire_after_it() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let content =
            RepositorySetContentV1::from_repositories(vec!["owner/repo".to_owned()]).unwrap();
        let action = ControlActionV1::RegisterRepositorySet { content };
        let mut state = ControlState::default();
        let first = state.apply(command("same", now, action.clone())).unwrap();
        let retry = state
            .apply(command("same", now + TimeDelta::days(1), action.clone()))
            .unwrap();
        assert_eq!(retry, first);
        assert_eq!(state.generation(), 1);

        let after_window = state
            .apply(command("same", now + TimeDelta::days(8), action))
            .unwrap();
        assert_eq!(after_window.generation, 2);
        assert_eq!(state.snapshot().processed_commands.len(), 1);
    }

    #[test]
    fn create_schedule_retry_ignores_server_delivery_timestamp() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let content =
            RepositorySetContentV1::from_repositories(vec!["owner/repo".to_owned()]).unwrap();
        let mut state = ControlState::default();
        state
            .apply(command(
                "register",
                now,
                ControlActionV1::RegisterRepositorySet {
                    content: content.clone(),
                },
            ))
            .unwrap();
        let request = create_schedule_request(now, content.repository_set.clone());
        let first = state
            .apply(command(
                "create",
                now,
                ControlActionV1::CreateSchedule {
                    request: request.clone(),
                    repository_set_content: None,
                },
            ))
            .unwrap();
        let mut retry = request;
        retry.created_at = now + TimeDelta::minutes(1);
        let replay = state
            .apply(command(
                "create",
                now + TimeDelta::minutes(1),
                ControlActionV1::CreateSchedule {
                    request: retry,
                    repository_set_content: None,
                },
            ))
            .unwrap();
        assert_eq!(replay, first);
        assert_eq!(state.generation(), 2);
        assert_eq!(
            state
                .schedule(&ScheduleId("hourly".to_owned()))
                .unwrap()
                .created_at,
            now
        );
    }

    #[test]
    fn failed_schedule_creation_does_not_orphan_repository_content() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let first =
            RepositorySetContentV1::from_repositories(vec!["owner/one".to_owned()]).unwrap();
        let orphan =
            RepositorySetContentV1::from_repositories(vec!["owner/two".to_owned()]).unwrap();
        let mut state = ControlState::default();
        state
            .apply(command(
                "create-first",
                now,
                ControlActionV1::CreateSchedule {
                    request: create_schedule_request(now, first.repository_set.clone()),
                    repository_set_content: Some(first),
                },
            ))
            .unwrap();
        let result = state.apply(command(
            "create-conflict",
            now + TimeDelta::minutes(1),
            ControlActionV1::CreateSchedule {
                request: create_schedule_request(
                    now + TimeDelta::minutes(1),
                    orphan.repository_set.clone(),
                ),
                repository_set_content: Some(orphan.clone()),
            },
        ));
        assert!(matches!(
            result,
            Err(ControlStateError::Schedule(
                ScheduleError::ScheduleAlreadyExists
            ))
        ));
        assert!(
            state
                .snapshot()
                .repository_sets
                .iter()
                .all(|content| content.repository_set != orphan.repository_set)
        );
    }

    #[test]
    fn empty_saved_query_materialization_terminalizes_occurrence() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut request = create_schedule_request(
            now,
            RepositorySetContentV1::from_repositories(vec!["unused/repo".to_owned()])
                .unwrap()
                .repository_set,
        );
        request.definition.repository_source =
            crate::coordinator::RepositorySourceRefV1::SavedQuery {
                query: crate::coordinator::SavedInventoryQueryRefV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    query_id: "empty-query".to_owned(),
                    revision: 1,
                },
            };
        let schedule_id = request.schedule_id.clone();
        let mut state = ControlState::default();
        state
            .apply(command(
                "create-saved",
                now,
                ControlActionV1::CreateSchedule {
                    request,
                    repository_set_content: None,
                },
            ))
            .unwrap();
        let triggered = state
            .apply(command(
                "trigger-saved",
                now,
                ControlActionV1::TriggerSchedule {
                    schedule_id: schedule_id.clone(),
                },
            ))
            .unwrap();
        let ControlResultV1::OccurrencePlanned { plan } = triggered.result else {
            panic!("expected occurrence plan");
        };
        state
            .apply(command(
                "claim-saved",
                now,
                ControlActionV1::ClaimOccurrence {
                    schedule_id: schedule_id.clone(),
                },
            ))
            .unwrap();
        let empty = RepositorySetContentV1::from_repositories(Vec::new()).unwrap();
        let materialized = state
            .apply(command(
                "materialize-saved",
                now,
                ControlActionV1::MaterializeOccurrence {
                    occurrence: ScheduledOccurrenceRefV1 {
                        schedule_id: schedule_id.clone(),
                        occurrence_id: plan.occurrence.id.clone(),
                    },
                    refresh: Some(SavedQueryRefreshV1::Complete {
                        snapshot: RepositorySetSnapshotV1 {
                            schema_version: SCHEMA_VERSION_V1,
                            repository_set: empty.repository_set.clone(),
                            inventory_watermark: "catalog-1".to_owned(),
                            materialized_at: now,
                        },
                    }),
                    last_complete: None,
                    repository_set_content: Some(empty),
                },
            ))
            .unwrap();
        assert!(matches!(
            materialized.result,
            ControlResultV1::OccurrenceMaterialized {
                decision: MaterializationDecisionV1::SkippedEmpty { .. }
            }
        ));
        assert_eq!(
            state
                .occurrence(&ScheduledOccurrenceRefV1 {
                    schedule_id,
                    occurrence_id: plan.occurrence.id,
                })
                .unwrap()
                .state,
            OccurrenceStateV1::Skipped
        );
    }

    #[test]
    fn retention_prunes_terminal_occurrences_and_unreferenced_schedule_state() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let first =
            RepositorySetContentV1::from_repositories(vec!["owner/first".to_owned()]).unwrap();
        let second =
            RepositorySetContentV1::from_repositories(vec!["owner/second".to_owned()]).unwrap();
        let schedule_id = ScheduleId("hourly".to_owned());
        let mut state = ControlState::default();
        state
            .apply(command(
                "create-retained",
                now,
                ControlActionV1::CreateSchedule {
                    request: create_schedule_request(now, first.repository_set.clone()),
                    repository_set_content: Some(first.clone()),
                },
            ))
            .unwrap();
        let planned = state
            .apply(command(
                "trigger-old",
                now,
                ControlActionV1::TriggerSchedule {
                    schedule_id: schedule_id.clone(),
                },
            ))
            .unwrap();
        let ControlResultV1::OccurrencePlanned { plan } = planned.result else {
            panic!("expected occurrence plan");
        };
        state
            .apply(command(
                "claim-old",
                now,
                ControlActionV1::ClaimOccurrence {
                    schedule_id: schedule_id.clone(),
                },
            ))
            .unwrap();
        state
            .apply(command(
                "finish-old",
                now,
                ControlActionV1::FinishOccurrence {
                    occurrence: ScheduledOccurrenceRefV1 {
                        schedule_id: schedule_id.clone(),
                        occurrence_id: plan.occurrence.id.clone(),
                    },
                    terminal_state: OccurrenceStateV1::Completed,
                },
            ))
            .unwrap();

        let revised_at = now + TimeDelta::days(1);
        let definition =
            create_schedule_request(revised_at, second.repository_set.clone()).definition;
        state
            .apply(command(
                "revise-retained",
                revised_at,
                ControlActionV1::ReviseSchedule {
                    schedule_id: schedule_id.clone(),
                    expected_revision: 1,
                    definition,
                    repository_set_content: Some(second.clone()),
                },
            ))
            .unwrap();

        let pruned = state
            .apply(command(
                "prune-control",
                now + TimeDelta::days(400),
                ControlActionV1::PruneBefore {
                    cutoff: now + TimeDelta::days(365),
                },
            ))
            .unwrap();
        let ControlResultV1::ControlHistoryPruned { summary } = pruned.result else {
            panic!("expected retention summary");
        };
        assert_eq!(summary.occurrences, 1);
        assert_eq!(summary.revisions, 1);
        assert_eq!(summary.repository_sets, 1);
        assert!(
            state
                .occurrence(&ScheduledOccurrenceRefV1 {
                    schedule_id: schedule_id.clone(),
                    occurrence_id: plan.occurrence.id,
                })
                .is_none()
        );
        assert!(state.schedule_revision(&schedule_id, 1).is_none());
        assert!(state.schedule_revision(&schedule_id, 2).is_some());
        let snapshot = state.snapshot();
        assert_eq!(snapshot.repository_sets, vec![second]);
        assert_eq!(
            ControlState::restore(snapshot)
                .unwrap()
                .schedule(&schedule_id)
                .unwrap()
                .current_revision,
            2
        );
    }

    fn command(
        command_id: &str,
        issued_at: DateTime<Utc>,
        action: ControlActionV1,
    ) -> ControlCommandV1 {
        ControlCommandV1 {
            schema_version: SCHEMA_VERSION_V1,
            command_id: command_id.to_owned(),
            expected_generation: None,
            issued_at,
            action,
        }
    }

    fn create_schedule_request(
        created_at: DateTime<Utc>,
        repository_set: RepositorySetRefV1,
    ) -> CreateScheduleV1 {
        CreateScheduleV1 {
            schema_version: SCHEMA_VERSION_V1,
            schedule_id: ScheduleId("hourly".to_owned()),
            enabled: true,
            definition: ScheduleDefinitionV1 {
                schema_version: SCHEMA_VERSION_V1,
                cron: crate::coordinator::UtcCronV1::parse("0 * * * *").unwrap(),
                scan_spec: crate::coordinator::ScanSpecV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    target: crate::coordinator::ScanTargetV1 {
                        crate_name: "fs2".to_owned(),
                        version_spec: "=0.4.3".to_owned(),
                    },
                    repository_scope: crate::coordinator::RepositoryScopeV1::PublicOnly,
                    credential_profile_id: None,
                    bounds: crate::coordinator::ScanBoundsV1::default(),
                    analyzer_versions: BTreeMap::new(),
                },
                repository_source: crate::coordinator::RepositorySourceRefV1::Explicit {
                    repository_set,
                },
                priority: crate::coordinator::JobPriorityV1::Normal,
                max_run_age_seconds: 3_600,
            },
            created_at,
        }
    }
}
