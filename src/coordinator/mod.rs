//! Durable coordinator domain, state, back-pressure, and cache primitives.

mod cache;
mod domain;
mod provider;
mod store;
mod turso_store;

pub use cache::{
    CacheCatalog, CacheContentKindV1, CacheError, CacheInsertOutcome, CacheKeyV1, CacheMetadataV1,
    CacheNamespaceV1, CacheProtectionV1, EvidenceCompletenessV1, RetentionPolicyV1,
    ReuseFingerprintV1,
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
pub use store::{
    InMemoryStateStore, MAX_ACTIVE_JOBS, NewRepositoryTaskV1, QuotaLedgerV1,
    QuotaReservationStateV1, QuotaReservationV1, QuotaResourceV1, ReservationOutcome, StateStore,
    StoreError, SubmitJobV1, SubmitOutcome, TaskFailureV1,
};
pub use turso_store::{
    AgentRecordV1, ArtifactRecordV1, BackupManifestV1, DurableCommandV1, DurableOutcomeV1,
    TursoCoordinatorStore,
};
