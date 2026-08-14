//! Durable coordinator domain, state, back-pressure, and cache primitives.

mod cache;
mod control_state;
mod credential;
mod dispatch;
mod domain;
mod provider;
mod schedule;
mod store;
mod turso_store;

pub use cache::{
    CacheCatalog, CacheContentKindV1, CacheError, CacheInsertOutcome, CacheKeyV1, CacheMetadataV1,
    CacheNamespaceV1, CacheProtectionV1, EvidenceCompletenessV1, RetentionPolicyV1,
    ReuseFingerprintV1,
};
pub use control_state::{
    ControlActionV1, ControlCommandV1, ControlLeaseV1, ControlOutcomeV1, ControlResultV1,
    ControlRetentionSummaryV1, ControlState, ControlStateError, ControlStateSnapshotV1,
    ControlTaskStateV1, ControlTaskV1, LeasedTaskV1, MAX_REPOSITORIES_PER_SET,
    OccurrenceMaterializationV1, ProcessedControlCommandV1, RepositorySetContentV1,
    ScheduledOccurrenceRefV1, TaskFailureOutcomeV1,
};
pub use credential::{
    BrokerCredential, CredentialBroker, CredentialError, CredentialFuture, CredentialProfileV1,
    CredentialRequestV1, HttpCredentialBroker,
};
pub use dispatch::{
    AdmissionPlanV1, AdmissionQueue, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_RUN_AGE_SECONDS,
    DeadLetterTaskV1, DispatchError, DispatchJobV1, DispatchSelectionV1, FailureClassV1,
    IndexedTaskV1, JobPriorityV1, MAX_QUEUED_JOBS, MAX_RUNNING_JOBS, QueueSubmitOutcomeV1,
    QueuedJobV1, ReadyTaskIndex, RepositorySetRefV1, RetryDecisionV1, RetryPolicyV1,
    TaskFailureKindV1,
};
pub use domain::{
    AgentAuthorizationV1, ArtifactRefV1, DomainError, JobEventKindV1, JobEventV1, JobId,
    JobProgressV1, LeaseV1, PermitId, QuotaUsageV1, RepositoryScopeV1, RepositoryTaskStateV1,
    RepositoryTaskV1, ReservationId, SCHEMA_VERSION_V1, ScanBoundsV1, ScanJobStateV1, ScanJobV1,
    ScanSpecV1, ScanTargetV1, Sha256Digest, TaskId, TaskUsageV1,
};
pub use provider::{
    CircuitPhaseV1, CircuitPolicyV1, PermitDecision, ProviderError, ProviderGate, ProviderKeyV1,
    ProviderOutcomeClassV1, ProviderPermitV1, ProviderPolicyV1, ProviderRateStateV1,
    RateLimitObservationV1,
};
pub use schedule::{
    CreateScheduleV1, CronError, InMemoryScheduler, MAX_SCHEDULE_RUN_AGE_SECONDS, MAX_SCHEDULES,
    MaterializationDecisionV1, OccurrenceId, OccurrencePlanV1, OccurrenceStateV1,
    OccurrenceTriggerV1, RepositorySetProvenanceV1, RepositorySetSelectionV1,
    RepositorySetSnapshotV1, RepositorySourceRefV1, STALE_REPOSITORY_SET_REASON,
    SavedInventoryQueryRefV1, SavedQueryRefreshV1, ScanScheduleV1, ScheduleDefinitionV1,
    ScheduleError, ScheduleId, ScheduleOccurrenceV1, ScheduleRevisionV1, ScheduleStateV1,
    SchedulerRetentionSummaryV1, SchedulerSnapshotV1, UtcCronV1, resolve_repository_source,
};
pub use store::{
    InMemoryStateStore, MAX_ACTIVE_JOBS, NewRepositoryTaskV1, OperationalRetentionSummaryV1,
    QuotaLedgerV1, QuotaReservationStateV1, QuotaReservationV1, QuotaResourceV1,
    ReservationOutcome, StateStore, StoreError, SubmitJobV1, SubmitOutcome, TaskFailureV1,
};
pub(crate) use turso_store::artifacts_from_checkpoint;
pub use turso_store::{
    AgentRecordV1, ArtifactProjectionOutcomeV1, ArtifactRecordV1, BackupManifestV1,
    DurableCommandV1, DurableOutcomeV1, FailedAttemptProjectionKeyV1,
    FailedAttemptProjectionOutcomeV1, FailedAttemptProjectionRecordV1, InventoryProjectionStateV1,
    TursoCoordinatorStore,
};
