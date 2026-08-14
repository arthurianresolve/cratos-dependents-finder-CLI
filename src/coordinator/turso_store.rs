//! Encrypted, single-owner Turso journal for the coordinator state machine.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::control_auth::{ServiceTokenIdV1, ServiceTokenRecordV1};
use crate::secure_cache::{EnvelopeKey, sha256_hex};

use super::{
    AgentAuthorizationV1, ArtifactRefV1, CacheCatalog, CacheContentKindV1, CacheKeyV1,
    CacheMetadataV1, CacheNamespaceV1, CacheProtectionV1, ControlCommandV1, ControlOutcomeV1,
    ControlState, ControlStateSnapshotV1, ControlTaskV1, DispatchJobV1, InMemoryStateStore,
    JobEventV1, JobId, NewRepositoryTaskV1, OperationalRetentionSummaryV1, PermitDecision,
    PermitId, ProviderKeyV1, ProviderOutcomeClassV1, ProviderPolicyV1, QuotaResourceV1,
    RateLimitObservationV1, RepositoryScopeV1, RepositoryTaskStateV1, RepositoryTaskV1,
    ReservationId, ReservationOutcome, ReuseFingerprintV1, ScanJobV1, ScanScheduleV1, ScheduleId,
    ScheduleOccurrenceV1, ScheduleRevisionV1, ScheduledOccurrenceRefV1, StateStore as _,
    StoreError, SubmitJobV1, SubmitOutcome, TaskFailureV1, TaskId, TaskUsageV1,
};

const DATABASE_SCHEMA_VERSION: u16 = 1;
const SNAPSHOT_SCHEMA_VERSION: u16 = 1;
const ACTOR_QUEUE_CAPACITY: usize = 256;
const MAX_ENROLLED_AGENTS: u64 = 16;
const COMPACTION_COMMAND_THRESHOLD: u64 = 1_024;
const COMPACTION_BYTE_THRESHOLD: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionStatsV1 {
    pub watermark_sequence: u64,
    pub commands_compacted: u64,
    pub bytes_compacted: u64,
}

#[derive(Debug)]
struct JournalState {
    total_commands: u64,
    watermark_sequence: u64,
    tail_commands: u64,
    tail_bytes: u64,
}

impl JournalState {
    fn should_compact(&self) -> bool {
        self.tail_commands >= COMPACTION_COMMAND_THRESHOLD
            || self.tail_bytes >= COMPACTION_BYTE_THRESHOLD
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct CoordinatorSnapshotV1 {
    schema_version: u16,
    command_count: u64,
    state: super::store::StateSnapshotV1,
    artifacts: Vec<ArtifactRecordV1>,
    /// Absent in snapshots written before failed-attempt catalog projection
    /// became durable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failed_attempt_projections: Vec<FailedAttemptProjectionRecordV1>,
    /// Absent in snapshots written before the control plane was introduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control: Option<ControlStateSnapshotV1>,
}

#[derive(Debug)]
struct LoadedState {
    memory: InMemoryStateStore,
    control: ControlState,
    artifacts: BTreeMap<TaskId, ArtifactRecordV1>,
    failed_attempt_projections:
        BTreeMap<FailedAttemptProjectionKeyV1, FailedAttemptProjectionRecordV1>,
    reuse_index: ReuseIndex,
    journal: JournalState,
}

#[derive(Clone, Copy, Debug)]
struct JournalAppend {
    sequence: u64,
    stored_bytes: u64,
}

/// Every durable mutation is a versioned, replayable state-machine command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DurableCommandV1 {
    /// Apply a command to the independent control-plane aggregate. The
    /// aggregate shares this authenticated journal without coupling its jobs
    /// or tasks to the legacy worker state machine.
    Control {
        command: Box<ControlCommandV1>,
    },
    SubmitJob {
        request: SubmitJobV1,
    },
    SubmitJobWithTasks {
        request: SubmitJobV1,
        tasks: Vec<NewRepositoryTaskV1>,
        now: DateTime<Utc>,
    },
    StartJob {
        job_id: JobId,
        now: DateTime<Utc>,
    },
    StartNextQueuedJob {
        now: DateTime<Utc>,
    },
    PauseJob {
        job_id: JobId,
        now: DateTime<Utc>,
    },
    ResumeJob {
        job_id: JobId,
        now: DateTime<Utc>,
    },
    CancelJob {
        job_id: JobId,
        now: DateTime<Utc>,
    },
    FinalizeJob {
        job_id: JobId,
        partial_reasons: BTreeSet<String>,
        now: DateTime<Utc>,
    },
    EnqueueTask {
        task: NewRepositoryTaskV1,
    },
    LeaseNextTask {
        job_id: JobId,
        agent_id: String,
        lease_id: String,
        lease_seconds: u64,
        now: DateTime<Utc>,
    },
    LeaseNextAuthorizedTask {
        authorization: AgentAuthorizationV1,
        agent_id: String,
        lease_id: String,
        lease_seconds: u64,
        now: DateTime<Utc>,
    },
    HeartbeatTask {
        task_id: TaskId,
        agent_id: String,
        lease_id: String,
        lease_seconds: u64,
        now: DateTime<Utc>,
    },
    DeferTask {
        task_id: TaskId,
        agent_id: String,
        lease_id: String,
        not_before: DateTime<Utc>,
        reason_code: String,
        now: DateTime<Utc>,
    },
    CompleteTask {
        task_id: TaskId,
        agent_id: String,
        lease_id: String,
        result: ArtifactRefV1,
        now: DateTime<Utc>,
    },
    CompleteTaskWithArtifact {
        task_id: TaskId,
        agent_id: String,
        lease_id: String,
        result: ArtifactRefV1,
        artifact: Box<ArtifactRecordV1>,
        #[serde(default)]
        usage: TaskUsageV1,
        now: DateTime<Utc>,
    },
    MarkArtifactProjected {
        task_id: TaskId,
        artifact_digest: super::Sha256Digest,
        now: DateTime<Utc>,
    },
    MarkFailedAttemptProjected {
        key: FailedAttemptProjectionKeyV1,
        projection_digest: super::Sha256Digest,
        now: DateTime<Utc>,
    },
    RemoveExpiredArtifact {
        task_id: TaskId,
        now: DateTime<Utc>,
    },
    /// Remove every metadata record for an authenticated object that failed
    /// integrity or schema validation. The content-addressed object is removed
    /// separately by the API under its per-object lifecycle lock.
    InvalidateCacheKey {
        key: CacheKeyV1,
        now: DateTime<Utc>,
    },
    TouchCacheKey {
        key: CacheKeyV1,
        accessed_at: DateTime<Utc>,
    },
    FailTask {
        task_id: TaskId,
        agent_id: String,
        lease_id: String,
        failure: String,
        retry_at: Option<DateTime<Utc>>,
        #[serde(default)]
        usage: TaskUsageV1,
        now: DateTime<Utc>,
    },
    ReclaimExpiredLeases {
        now: DateTime<Utc>,
    },
    /// Remove historical events older than the retention cutoff only for jobs
    /// that are already terminal. Active-job event history is never pruned.
    PruneEventsBefore {
        cutoff: DateTime<Utc>,
    },
    /// Expire failed-attempt projection records at the same boundary as their
    /// searchable catalog attempts. Pending records are intentionally removed
    /// once their retention window ends so private aliases cannot outlive the
    /// declared policy.
    PruneFailedAttemptProjectionsBefore {
        cutoff: DateTime<Utc>,
    },
    /// Remove whole terminal runs only after their evidence metadata has been
    /// collected. Artifact and schedule references are consulted atomically
    /// by the actor.
    PruneTerminalRunsBefore {
        cutoff: DateTime<Utc>,
    },
    ReserveQuota {
        reservation_id: ReservationId,
        job_id: JobId,
        resource: QuotaResourceV1,
        amount: u64,
        now: DateTime<Utc>,
    },
    ReconcileQuota {
        reservation_id: ReservationId,
        actual_amount: u64,
        now: DateTime<Utc>,
    },
    ReleaseQuota {
        reservation_id: ReservationId,
        now: DateTime<Utc>,
    },
    ConfigureProvider {
        key: ProviderKeyV1,
        policy: ProviderPolicyV1,
    },
    AcquireProviderPermit {
        key: ProviderKeyV1,
        permit_id: PermitId,
        agent_id: String,
        now: DateTime<Utc>,
    },
    FinishProviderRequest {
        permit_id: PermitId,
        agent_id: String,
        outcome: ProviderOutcomeClassV1,
        observation: RateLimitObservationV1,
        now: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableOutcomeV1 {
    Applied,
    ArtifactProjection(ArtifactProjectionOutcomeV1),
    FailedAttemptProjection(FailedAttemptProjectionOutcomeV1),
    Control(ControlOutcomeV1),
    Submitted(SubmitOutcome),
    StartedJob(Option<JobId>),
    Task(Option<RepositoryTaskV1>),
    Tasks(Vec<TaskId>),
    Reservation(ReservationOutcome),
    Permit(PermitDecision),
    QuotaExceeded(QuotaResourceV1),
    EventsPruned(usize),
    FailedAttemptProjectionsPruned(usize),
    RunsPruned(OperationalRetentionSummaryV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupManifestV1 {
    pub schema_version: u16,
    pub created_at: DateTime<Utc>,
    pub source_database: String,
    pub database_sha256: String,
    pub database_bytes: u64,
    pub journal_commands: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentRecordV1 {
    pub agent_id: String,
    pub certificate_sha256: String,
    pub enrolled_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub authorization: AgentAuthorizationV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRecordV1 {
    pub job_id: JobId,
    pub task_id: TaskId,
    pub metadata: CacheMetadataV1,
    #[serde(default)]
    pub inventory_projection: InventoryProjectionStateV1,
}

/// A bounded retention page. Only selected candidates are cloned; the actor
/// computes blob exclusivity against the complete metadata index.
#[derive(Clone, Debug, Default)]
pub(crate) struct ArtifactRetentionPageV1 {
    pub candidates: Vec<ArtifactRecordV1>,
    pub total_candidates: usize,
    pub removable_blob_keys: BTreeSet<CacheKeyV1>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum InventoryProjectionStateV1 {
    /// The record predates durable projection tracking and must be reconciled.
    #[default]
    LegacyUnknown,
    Pending,
    Projected {
        at: DateTime<Utc>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactProjectionOutcomeV1 {
    Marked,
    AlreadyProjected,
}

/// Stable key for one repository task attempt. A task can fail, retry, and
/// fail again, so task ID alone is not sufficient for the projection outbox.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FailedAttemptProjectionKeyV1 {
    pub task_id: TaskId,
    pub task_attempt: u32,
}

/// Durable, privacy-bounded input for a failed-attempt catalog projection.
/// The worker-provided failure text is intentionally excluded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailedAttemptProjectionRecordV1 {
    pub key: FailedAttemptProjectionKeyV1,
    pub job_id: JobId,
    pub namespace: CacheNamespaceV1,
    pub repository_alias: String,
    pub normalized_repository_alias: String,
    pub completed_at: DateTime<Utc>,
    pub failure_code: String,
    pub failure_message: String,
    pub projection_digest: super::Sha256Digest,
    #[serde(default)]
    pub inventory_projection: InventoryProjectionStateV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailedAttemptProjectionOutcomeV1 {
    Marked,
    AlreadyProjected,
}

type ReuseIndex = BTreeMap<(CacheNamespaceV1, ReuseFingerprintV1), BTreeSet<TaskId>>;

enum ActorRequest {
    Apply {
        command: Box<DurableCommandV1>,
        response: oneshot::Sender<Result<DurableOutcomeV1, String>>,
    },
    Job {
        job_id: JobId,
        response: oneshot::Sender<Option<ScanJobV1>>,
    },
    Jobs {
        response: oneshot::Sender<Vec<ScanJobV1>>,
    },
    ControlSnapshot {
        response: oneshot::Sender<ControlStateSnapshotV1>,
    },
    ControlSchedule {
        schedule_id: ScheduleId,
        response: oneshot::Sender<Option<ScanScheduleV1>>,
    },
    ControlScheduleRevision {
        schedule_id: ScheduleId,
        revision: u64,
        response: oneshot::Sender<Option<ScheduleRevisionV1>>,
    },
    ControlOccurrence {
        occurrence: ScheduledOccurrenceRefV1,
        response: oneshot::Sender<Option<ScheduleOccurrenceV1>>,
    },
    DispatchJob {
        job_id: JobId,
        response: oneshot::Sender<Option<DispatchJobV1>>,
    },
    ControlTask {
        task_id: TaskId,
        response: oneshot::Sender<Option<ControlTaskV1>>,
    },
    CredentialProfile {
        profile_id: String,
        response: oneshot::Sender<Option<super::CredentialProfileV1>>,
    },
    ServiceToken {
        token_id: ServiceTokenIdV1,
        response: oneshot::Sender<Option<ServiceTokenRecordV1>>,
    },
    Task {
        task_id: TaskId,
        response: oneshot::Sender<Option<RepositoryTaskV1>>,
    },
    TasksForJob {
        job_id: JobId,
        after_repository: Option<String>,
        limit: usize,
        response: oneshot::Sender<Vec<RepositoryTaskV1>>,
    },
    Artifact {
        task_id: TaskId,
        response: oneshot::Sender<Option<ArtifactRecordV1>>,
    },
    PendingArtifacts {
        after_task_id: Option<TaskId>,
        limit: usize,
        response: oneshot::Sender<Vec<ArtifactRecordV1>>,
    },
    Artifacts {
        response: oneshot::Sender<Vec<ArtifactRecordV1>>,
    },
    PendingFailedAttemptProjections {
        after: Option<FailedAttemptProjectionKeyV1>,
        limit: usize,
        response: oneshot::Sender<Vec<FailedAttemptProjectionRecordV1>>,
    },
    ExpiredArtifacts {
        now: DateTime<Utc>,
        limit: usize,
        response: oneshot::Sender<ArtifactRetentionPageV1>,
    },
    ReusableArtifact {
        namespace: CacheNamespaceV1,
        fingerprint: ReuseFingerprintV1,
        now: DateTime<Utc>,
        response: oneshot::Sender<Option<ArtifactRecordV1>>,
    },
    Events {
        response: oneshot::Sender<Vec<JobEventV1>>,
    },
    EventsForJob {
        job_id: JobId,
        after_sequence: Option<u64>,
        limit: usize,
        response: oneshot::Sender<Vec<JobEventV1>>,
    },
    Backup {
        destination: PathBuf,
        response: oneshot::Sender<Result<BackupManifestV1, String>>,
    },
    Compact {
        response: oneshot::Sender<Result<CompactionStatsV1, String>>,
    },
    RegisterAgent {
        record: AgentRecordV1,
        response: oneshot::Sender<Result<(), String>>,
    },
    RevokeAgent {
        agent_id: String,
        now: DateTime<Utc>,
        response: oneshot::Sender<Result<(), String>>,
    },
    Agent {
        agent_id: String,
        response: oneshot::Sender<Result<Option<AgentRecordV1>, String>>,
    },
}

/// Cloneable async handle. A single background actor exclusively owns both the
/// Turso connection and the in-memory state machine.
#[derive(Clone, Debug)]
pub struct TursoCoordinatorStore {
    sender: mpsc::Sender<ActorRequest>,
    _owner_lock: Arc<File>,
}

impl TursoCoordinatorStore {
    pub async fn open(database_path: impl Into<PathBuf>, key: EnvelopeKey) -> Result<Self> {
        let requested_path = database_path.into();
        let file_name = requested_path
            .file_name()
            .context("coordinator database path has no file name")?;
        let parent = requested_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating coordinator directory {}", parent.display()))?;
        let database_path = fs::canonicalize(parent)
            .with_context(|| format!("resolving coordinator directory {}", parent.display()))?
            .join(file_name);
        let database_path_text = database_path
            .to_str()
            .ok_or_else(|| anyhow!("Turso database path is not valid UTF-8"))?
            .to_owned();
        let owner_lock = Arc::new(acquire_owner_lock(&database_path)?);
        let database = turso::Builder::new_local(&database_path_text)
            .build()
            .await
            .context("opening embedded Turso database")?;
        let connection = database.connect().context("connecting to embedded Turso")?;
        migrate(&connection).await?;
        let loaded = replay(&connection, &key).await?;

        let (sender, receiver) = mpsc::channel(ACTOR_QUEUE_CAPACITY);
        tokio::spawn(run_actor(
            receiver,
            database,
            connection,
            database_path,
            key,
            loaded.memory,
            loaded.control,
            loaded.artifacts,
            loaded.failed_attempt_projections,
            loaded.reuse_index,
            loaded.journal,
            owner_lock.clone(),
        ));
        Ok(Self {
            sender,
            _owner_lock: owner_lock,
        })
    }

    pub async fn apply(&self, command: DurableCommandV1) -> Result<DurableOutcomeV1> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Apply {
                command: Box::new(command),
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))?
            .map_err(anyhow::Error::msg)
    }

    /// Fill one available running-job slot with the oldest queued job.
    pub async fn start_next_queued_job(&self, now: DateTime<Utc>) -> Result<Option<JobId>> {
        match self
            .apply(DurableCommandV1::StartNextQueuedJob { now })
            .await?
        {
            DurableOutcomeV1::StartedJob(job_id) => Ok(job_id),
            _ => unreachable!("queue dispatch commands always produce a job outcome"),
        }
    }

    /// Apply one idempotent control-plane command through the encrypted
    /// coordinator journal.
    pub async fn apply_control(&self, command: ControlCommandV1) -> Result<ControlOutcomeV1> {
        match self
            .apply(DurableCommandV1::Control {
                command: Box::new(command),
            })
            .await?
        {
            DurableOutcomeV1::Control(outcome) => Ok(outcome),
            _ => unreachable!("control commands always produce control outcomes"),
        }
    }

    pub async fn control_snapshot(&self) -> Result<ControlStateSnapshotV1> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ControlSnapshot { response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn control_schedule(
        &self,
        schedule_id: ScheduleId,
    ) -> Result<Option<ScanScheduleV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ControlSchedule {
                schedule_id,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn control_schedule_revision(
        &self,
        schedule_id: ScheduleId,
        revision: u64,
    ) -> Result<Option<ScheduleRevisionV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ControlScheduleRevision {
                schedule_id,
                revision,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn control_occurrence(
        &self,
        occurrence: ScheduledOccurrenceRefV1,
    ) -> Result<Option<ScheduleOccurrenceV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ControlOccurrence {
                occurrence,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn dispatch_job(&self, job_id: JobId) -> Result<Option<DispatchJobV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::DispatchJob { job_id, response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn control_task(&self, task_id: TaskId) -> Result<Option<ControlTaskV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ControlTask { task_id, response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn credential_profile(
        &self,
        profile_id: impl Into<String>,
    ) -> Result<Option<super::CredentialProfileV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::CredentialProfile {
                profile_id: profile_id.into(),
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn service_token(
        &self,
        token_id: ServiceTokenIdV1,
    ) -> Result<Option<ServiceTokenRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ServiceToken { token_id, response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn job(&self, job_id: JobId) -> Result<Option<ScanJobV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Job { job_id, response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn jobs(&self) -> Result<Vec<ScanJobV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Jobs { response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn task(&self, task_id: TaskId) -> Result<Option<RepositoryTaskV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Task { task_id, response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn tasks_for_job(
        &self,
        job_id: JobId,
        after_repository: Option<String>,
        limit: usize,
    ) -> Result<Vec<RepositoryTaskV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::TasksForJob {
                job_id,
                after_repository,
                limit,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn artifact(&self, task_id: TaskId) -> Result<Option<ArtifactRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Artifact { task_id, response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    /// Return the complete artifact metadata index in deterministic task order.
    pub(crate) async fn artifacts(&self) -> Result<Vec<ArtifactRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Artifacts { response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn pending_artifacts_page(
        &self,
        after_task_id: Option<TaskId>,
        limit: usize,
    ) -> Result<Vec<ArtifactRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::PendingArtifacts {
                after_task_id,
                limit,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn pending_failed_attempt_projections_page(
        &self,
        after: Option<FailedAttemptProjectionKeyV1>,
        limit: usize,
    ) -> Result<Vec<FailedAttemptProjectionRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::PendingFailedAttemptProjections {
                after,
                limit,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub(crate) async fn expired_artifacts_page(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<ArtifactRetentionPageV1> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ExpiredArtifacts {
                now,
                limit,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    /// Locate an unexpired, complete artifact with the exact namespace and
    /// immutable-analysis fingerprint. The actor maintains an ordered index so
    /// one lookup is logarithmic in the number of retained fingerprints.
    pub async fn reusable_artifact(
        &self,
        namespace: CacheNamespaceV1,
        fingerprint: ReuseFingerprintV1,
        now: DateTime<Utc>,
    ) -> Result<Option<ArtifactRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::ReusableArtifact {
                namespace,
                fingerprint,
                now,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn events(&self) -> Result<Vec<JobEventV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Events { response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    pub async fn events_for_job(
        &self,
        job_id: JobId,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<JobEventV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::EventsForJob {
                job_id,
                after_sequence,
                limit,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))
    }

    /// Checkpoint and copy the database while the actor prevents writes.
    pub async fn backup(&self, destination: impl Into<PathBuf>) -> Result<BackupManifestV1> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Backup {
                destination: destination.into(),
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))?
            .map_err(anyhow::Error::msg)
    }

    /// Atomically checkpoint the current state and prune the journal prefix it
    /// covers. Ordinary operation also invokes this automatically at bounded
    /// command and byte thresholds.
    pub async fn compact(&self) -> Result<CompactionStatsV1> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Compact { response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))?
            .map_err(anyhow::Error::msg)
    }

    pub async fn register_agent(&self, record: AgentRecordV1) -> Result<()> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::RegisterAgent { record, response })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))?
            .map_err(anyhow::Error::msg)
    }

    pub async fn revoke_agent(
        &self,
        agent_id: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::RevokeAgent {
                agent_id: agent_id.into(),
                now,
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))?
            .map_err(anyhow::Error::msg)
    }

    pub async fn agent(&self, agent_id: impl Into<String>) -> Result<Option<AgentRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Agent {
                agent_id: agent_id.into(),
                response,
            })
            .await
            .map_err(|_| anyhow!("coordinator state actor stopped"))?;
        result
            .await
            .map_err(|_| anyhow!("coordinator state actor dropped response"))?
            .map_err(anyhow::Error::msg)
    }

    pub fn restore(backup: &Path, manifest: &BackupManifestV1, destination: &Path) -> Result<()> {
        ensure!(
            manifest.schema_version == DATABASE_SCHEMA_VERSION,
            "unsupported backup schema {}",
            manifest.schema_version
        );
        let bytes = fs::read(backup)
            .with_context(|| format!("reading backup database {}", backup.display()))?;
        ensure!(
            bytes.len() as u64 == manifest.database_bytes,
            "backup size does not match manifest"
        );
        ensure!(
            sha256_hex(&bytes) == manifest.database_sha256,
            "backup SHA-256 does not match manifest"
        );
        if destination.exists() {
            bail!(
                "restore destination {} already exists; restore never overwrites",
                destination.display()
            );
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating restore directory {}", parent.display()))?;
        }
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("creating restore file beside {}", destination.display()))?;
        use std::io::Write as _;
        temp.write_all(&bytes)?;
        temp.as_file_mut().sync_all()?;
        temp.persist_noclobber(destination)
            .map_err(|error| error.error)
            .with_context(|| format!("restoring database {}", destination.display()))?;
        Ok(())
    }
}

/// Read the authenticated artifact index from an offline checkpoint without
/// acquiring ownership or starting a state actor.
pub(crate) async fn artifacts_from_checkpoint(
    database_path: &Path,
    key: &EnvelopeKey,
) -> Result<Vec<ArtifactRecordV1>> {
    let database_path = database_path
        .to_str()
        .context("coordinator checkpoint path is not valid UTF-8")?;
    let database = turso::Builder::new_local(database_path)
        .build()
        .await
        .context("opening coordinator checkpoint")?;
    let connection = database
        .connect()
        .context("connecting to coordinator checkpoint")?;
    let loaded = replay(&connection, key)
        .await
        .context("replaying coordinator checkpoint")?;
    Ok(loaded.artifacts.into_values().collect())
}

fn acquire_owner_lock(database_path: &Path) -> Result<File> {
    let mut lock_path = database_path.as_os_str().to_os_string();
    lock_path.push(".owner.lock");
    let lock_path = PathBuf::from(lock_path);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening coordinator owner lock {}", lock_path.display()))?;
    file.try_lock().with_context(|| {
        format!(
            "coordinator database {} is already owned by another process",
            database_path.display()
        )
    })?;
    Ok(file)
}

#[allow(clippy::too_many_arguments)]
async fn run_actor(
    mut receiver: mpsc::Receiver<ActorRequest>,
    _database: turso::Database,
    connection: turso::Connection,
    database_path: PathBuf,
    key: EnvelopeKey,
    mut memory: InMemoryStateStore,
    mut control: ControlState,
    mut artifacts: BTreeMap<TaskId, ArtifactRecordV1>,
    mut failed_attempt_projections: BTreeMap<
        FailedAttemptProjectionKeyV1,
        FailedAttemptProjectionRecordV1,
    >,
    mut reuse_index: ReuseIndex,
    mut journal: JournalState,
    _owner_lock: Arc<File>,
) {
    while let Some(request) = receiver.recv().await {
        match request {
            ActorRequest::Apply { command, response } => {
                let result = apply_and_persist(
                    &connection,
                    &key,
                    &mut memory,
                    &mut control,
                    &mut artifacts,
                    &mut failed_attempt_projections,
                    &mut reuse_index,
                    &mut journal,
                    &command,
                )
                .await
                .map_err(|error| error.to_string());
                let _ = response.send(result);
            }
            ActorRequest::Job { job_id, response } => {
                let _ = response.send(memory.job(&job_id).cloned());
            }
            ActorRequest::Jobs { response } => {
                let _ = response.send(memory.jobs().into_iter().cloned().collect());
            }
            ActorRequest::ControlSnapshot { response } => {
                let _ = response.send(control.snapshot());
            }
            ActorRequest::ControlSchedule {
                schedule_id,
                response,
            } => {
                let _ = response.send(control.schedule(&schedule_id).cloned());
            }
            ActorRequest::ControlScheduleRevision {
                schedule_id,
                revision,
                response,
            } => {
                let _ = response.send(control.schedule_revision(&schedule_id, revision).cloned());
            }
            ActorRequest::ControlOccurrence {
                occurrence,
                response,
            } => {
                let _ = response.send(control.occurrence(&occurrence).cloned());
            }
            ActorRequest::DispatchJob { job_id, response } => {
                let _ = response.send(control.job(&job_id).cloned());
            }
            ActorRequest::ControlTask { task_id, response } => {
                let _ = response.send(control.task(&task_id).cloned());
            }
            ActorRequest::CredentialProfile {
                profile_id,
                response,
            } => {
                let _ = response.send(control.credential_profile(&profile_id).cloned());
            }
            ActorRequest::ServiceToken { token_id, response } => {
                let _ = response.send(control.service_token(&token_id).cloned());
            }
            ActorRequest::Task { task_id, response } => {
                let _ = response.send(memory.task(&task_id).cloned());
            }
            ActorRequest::TasksForJob {
                job_id,
                after_repository,
                limit,
                response,
            } => {
                let _ = response.send(memory.tasks_for_job_page(
                    &job_id,
                    after_repository.as_deref(),
                    limit,
                ));
            }
            ActorRequest::Artifact { task_id, response } => {
                let _ = response.send(artifacts.get(&task_id).cloned());
            }
            ActorRequest::Artifacts { response } => {
                let _ = response.send(artifacts.values().cloned().collect());
            }
            ActorRequest::PendingArtifacts {
                after_task_id,
                limit,
                response,
            } => {
                let _ = response.send(pending_artifact_page(
                    &artifacts,
                    after_task_id.as_ref(),
                    limit,
                ));
            }
            ActorRequest::PendingFailedAttemptProjections {
                after,
                limit,
                response,
            } => {
                let _ = response.send(pending_failed_attempt_projection_page(
                    &failed_attempt_projections,
                    after.as_ref(),
                    limit,
                ));
            }
            ActorRequest::ExpiredArtifacts {
                now,
                limit,
                response,
            } => {
                let _ = response.send(expired_artifact_page(&artifacts, now, limit));
            }
            ActorRequest::ReusableArtifact {
                namespace,
                fingerprint,
                now,
                response,
            } => {
                let artifact = reuse_index
                    .get(&(namespace, fingerprint.clone()))
                    .and_then(|task_ids| {
                        task_ids.iter().find_map(|task_id| {
                            artifacts.get(task_id).filter(|artifact| {
                                artifact.metadata.can_reuse_at(&fingerprint, now)
                            })
                        })
                    })
                    .cloned();
                let _ = response.send(artifact);
            }
            ActorRequest::Events { response } => {
                let _ = response.send(memory.events());
            }
            ActorRequest::EventsForJob {
                job_id,
                after_sequence,
                limit,
                response,
            } => {
                let _ = response.send(memory.events_for_job_page(&job_id, after_sequence, limit));
            }
            ActorRequest::Backup {
                destination,
                response,
            } => {
                let result = async {
                    compact_state(
                        &connection,
                        &key,
                        &memory,
                        &control,
                        &artifacts,
                        &failed_attempt_projections,
                        &mut journal,
                    )
                    .await?;
                    backup_database(
                        &connection,
                        &database_path,
                        &destination,
                        journal.total_commands,
                    )
                    .await
                }
                .await
                .map_err(|error| format!("backing up coordinator state: {error:#}"));
                let _ = response.send(result);
            }
            ActorRequest::Compact { response } => {
                let result = compact_state(
                    &connection,
                    &key,
                    &memory,
                    &control,
                    &artifacts,
                    &failed_attempt_projections,
                    &mut journal,
                )
                .await
                .map_err(|error| format!("compacting coordinator journal: {error:#}"));
                let _ = response.send(result);
            }
            ActorRequest::RegisterAgent { record, response } => {
                let result = register_agent(&connection, &record)
                    .await
                    .map_err(|error| format!("registering agent: {error:#}"));
                let _ = response.send(result);
            }
            ActorRequest::RevokeAgent {
                agent_id,
                now,
                response,
            } => {
                let result = revoke_agent(&connection, &agent_id, now)
                    .await
                    .map_err(|error| format!("revoking agent: {error:#}"));
                let _ = response.send(result);
            }
            ActorRequest::Agent { agent_id, response } => {
                let result = load_agent(&connection, &agent_id)
                    .await
                    .map_err(|error| format!("loading agent: {error:#}"));
                let _ = response.send(result);
            }
        }
    }
}

fn pending_artifact_page(
    artifacts: &BTreeMap<TaskId, ArtifactRecordV1>,
    after_task_id: Option<&TaskId>,
    limit: usize,
) -> Vec<ArtifactRecordV1> {
    if limit == 0 {
        return Vec::new();
    }
    let is_pending = |artifact: &&ArtifactRecordV1| {
        matches!(
            artifact.inventory_projection,
            InventoryProjectionStateV1::LegacyUnknown | InventoryProjectionStateV1::Pending
        )
    };
    let mut selected = Vec::with_capacity(limit.min(artifacts.len()));
    if let Some(after) = after_task_id {
        selected.extend(
            artifacts
                .range((
                    std::ops::Bound::Excluded(after.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .map(|(_, artifact)| artifact)
                .filter(is_pending)
                .take(limit)
                .cloned(),
        );
        if selected.len() < limit {
            selected.extend(
                artifacts
                    .range((
                        std::ops::Bound::Unbounded,
                        std::ops::Bound::Included(after.clone()),
                    ))
                    .map(|(_, artifact)| artifact)
                    .filter(is_pending)
                    .take(limit - selected.len())
                    .cloned(),
            );
        }
    } else {
        selected.extend(artifacts.values().filter(is_pending).take(limit).cloned());
    }
    selected
}

fn pending_failed_attempt_projection_page(
    projections: &BTreeMap<FailedAttemptProjectionKeyV1, FailedAttemptProjectionRecordV1>,
    after: Option<&FailedAttemptProjectionKeyV1>,
    limit: usize,
) -> Vec<FailedAttemptProjectionRecordV1> {
    if limit == 0 {
        return Vec::new();
    }
    let is_pending = |record: &&FailedAttemptProjectionRecordV1| {
        matches!(
            record.inventory_projection,
            InventoryProjectionStateV1::LegacyUnknown | InventoryProjectionStateV1::Pending
        )
    };
    let mut selected = Vec::with_capacity(limit.min(projections.len()));
    if let Some(after) = after {
        selected.extend(
            projections
                .range((
                    std::ops::Bound::Excluded(after.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .map(|(_, record)| record)
                .filter(is_pending)
                .take(limit)
                .cloned(),
        );
        if selected.len() < limit {
            selected.extend(
                projections
                    .range((
                        std::ops::Bound::Unbounded,
                        std::ops::Bound::Included(after.clone()),
                    ))
                    .map(|(_, record)| record)
                    .filter(is_pending)
                    .take(limit - selected.len())
                    .cloned(),
            );
        }
    } else {
        selected.extend(projections.values().filter(is_pending).take(limit).cloned());
    }
    selected
}

fn expired_artifact_page(
    artifacts: &BTreeMap<TaskId, ArtifactRecordV1>,
    now: DateTime<Utc>,
    limit: usize,
) -> ArtifactRetentionPageV1 {
    let mut page = ArtifactRetentionPageV1 {
        candidates: Vec::with_capacity(limit.min(artifacts.len())),
        ..ArtifactRetentionPageV1::default()
    };
    for artifact in artifacts.values() {
        if artifact.metadata.content_kind == CacheContentKindV1::DerivedEvidence
            && artifact.metadata.is_retention_candidate(now)
        {
            page.total_candidates += 1;
            if page.candidates.len() < limit {
                page.candidates.push(artifact.clone());
            }
        }
    }
    page.removable_blob_keys = page
        .candidates
        .iter()
        .map(|artifact| artifact.metadata.key.clone())
        .collect();
    if page.removable_blob_keys.is_empty() {
        return page;
    }
    let selected_tasks = page
        .candidates
        .iter()
        .map(|artifact| artifact.task_id.clone())
        .collect::<BTreeSet<_>>();
    for artifact in artifacts.values() {
        if !selected_tasks.contains(&artifact.task_id) {
            page.removable_blob_keys.remove(&artifact.metadata.key);
        }
    }
    page
}

#[expect(
    clippy::too_many_arguments,
    reason = "the journal boundary must update every independently snapshotted aggregate atomically"
)]
async fn apply_and_persist(
    connection: &turso::Connection,
    key: &EnvelopeKey,
    memory: &mut InMemoryStateStore,
    control: &mut ControlState,
    artifacts: &mut BTreeMap<TaskId, ArtifactRecordV1>,
    failed_attempt_projections: &mut BTreeMap<
        FailedAttemptProjectionKeyV1,
        FailedAttemptProjectionRecordV1,
    >,
    reuse_index: &mut ReuseIndex,
    journal: &mut JournalState,
    command: &DurableCommandV1,
) -> Result<DurableOutcomeV1> {
    validate_artifact_command(memory, artifacts, command)?;
    validate_failed_attempt_projection_command(memory, failed_attempt_projections, command)?;
    let control_generation = control.generation();
    let outcome = apply_to_state(
        memory,
        control,
        artifacts,
        failed_attempt_projections,
        command,
    )?;
    if matches!(
        outcome,
        DurableOutcomeV1::Submitted(SubmitOutcome::Existing(_))
            | DurableOutcomeV1::Reservation(ReservationOutcome::AlreadyReserved)
            | DurableOutcomeV1::EventsPruned(0)
            | DurableOutcomeV1::FailedAttemptProjectionsPruned(0)
            | DurableOutcomeV1::StartedJob(None)
            | DurableOutcomeV1::Task(None)
            | DurableOutcomeV1::ArtifactProjection(ArtifactProjectionOutcomeV1::AlreadyProjected)
            | DurableOutcomeV1::FailedAttemptProjection(
                FailedAttemptProjectionOutcomeV1::AlreadyProjected
            )
    ) || matches!(&outcome, DurableOutcomeV1::Tasks(tasks) if tasks.is_empty())
        || matches!(&outcome, DurableOutcomeV1::RunsPruned(summary) if summary.is_empty())
        || matches!(command, DurableCommandV1::Control { .. })
            && control.generation() == control_generation
    {
        return Ok(outcome);
    }
    let appended = match append(connection, key, command).await {
        Ok(appended) => appended,
        Err(error) => {
            let restored = replay(connection, key).await.unwrap_or_else(|replay_error| {
                panic!(
                    "coordinator journal recovery failed after persistence error: {replay_error:#}"
                )
            });
            *memory = restored.memory;
            *control = restored.control;
            *artifacts = restored.artifacts;
            *failed_attempt_projections = restored.failed_attempt_projections;
            *reuse_index = restored.reuse_index;
            *journal = restored.journal;
            return Err(error).context("persisting coordinator command");
        }
    };
    update_artifact_index(artifacts, reuse_index, command, &outcome);
    update_failed_attempt_projection_outbox(failed_attempt_projections, memory, command, &outcome);
    journal.total_commands = journal.total_commands.saturating_add(1);
    journal.tail_commands = journal.tail_commands.saturating_add(1);
    journal.tail_bytes = journal.tail_bytes.saturating_add(appended.stored_bytes);
    journal.watermark_sequence = appended.sequence;
    if journal.should_compact()
        && let Err(error) = compact_state(
            connection,
            key,
            memory,
            control,
            artifacts,
            failed_attempt_projections,
            journal,
        )
        .await
    {
        // The command is already committed. Reporting failure would invite an
        // ambiguous retry, so retain the tail and retry compaction later.
        tracing::warn!(%error, "automatic coordinator journal compaction failed");
    }
    Ok(outcome)
}

fn apply_to_state(
    memory: &mut InMemoryStateStore,
    control: &mut ControlState,
    artifacts: &BTreeMap<TaskId, ArtifactRecordV1>,
    failed_attempt_projections: &BTreeMap<
        FailedAttemptProjectionKeyV1,
        FailedAttemptProjectionRecordV1,
    >,
    command: &DurableCommandV1,
) -> Result<DurableOutcomeV1> {
    match command {
        DurableCommandV1::Control { command } => {
            let mut candidate = control.clone();
            let outcome = candidate
                .apply(command.as_ref().clone())
                .map_err(anyhow::Error::new)?;
            *control = candidate;
            Ok(DurableOutcomeV1::Control(outcome))
        }
        DurableCommandV1::MarkArtifactProjected { task_id, .. } => {
            let outcome = match &artifacts
                .get(task_id)
                .context("artifact task was not found")?
                .inventory_projection
            {
                InventoryProjectionStateV1::Projected { .. } => {
                    ArtifactProjectionOutcomeV1::AlreadyProjected
                }
                InventoryProjectionStateV1::LegacyUnknown | InventoryProjectionStateV1::Pending => {
                    ArtifactProjectionOutcomeV1::Marked
                }
            };
            Ok(DurableOutcomeV1::ArtifactProjection(outcome))
        }
        DurableCommandV1::MarkFailedAttemptProjected { key, .. } => {
            let outcome = match &failed_attempt_projections
                .get(key)
                .context("failed-attempt projection was not found")?
                .inventory_projection
            {
                InventoryProjectionStateV1::Projected { .. } => {
                    FailedAttemptProjectionOutcomeV1::AlreadyProjected
                }
                InventoryProjectionStateV1::LegacyUnknown | InventoryProjectionStateV1::Pending => {
                    FailedAttemptProjectionOutcomeV1::Marked
                }
            };
            Ok(DurableOutcomeV1::FailedAttemptProjection(outcome))
        }
        DurableCommandV1::PruneFailedAttemptProjectionsBefore { cutoff } => {
            Ok(DurableOutcomeV1::FailedAttemptProjectionsPruned(
                failed_attempt_projections
                    .values()
                    .filter(|record| record.completed_at < *cutoff)
                    .count(),
            ))
        }
        DurableCommandV1::PruneTerminalRunsBefore { cutoff } => {
            let protected_jobs = artifacts
                .values()
                .map(|artifact| artifact.job_id.clone())
                .chain(control.retained_job_ids().cloned())
                .collect::<BTreeSet<_>>();
            Ok(DurableOutcomeV1::RunsPruned(
                memory.prune_terminal_runs_before(*cutoff, &protected_jobs),
            ))
        }
        _ => apply_to_memory(memory, command),
    }
}

async fn migrate(connection: &turso::Connection) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS coordinator_metadata (\
                 key TEXT PRIMARY KEY, value TEXT NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS coordinator_journal (\
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,\
                 record_id TEXT NOT NULL UNIQUE,\
                 key_id TEXT NOT NULL,\
                 payload BLOB NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS coordinator_snapshot (\
                 snapshot_id INTEGER PRIMARY KEY CHECK (snapshot_id = 1),\
                 format_version INTEGER NOT NULL,\
                 watermark_sequence INTEGER NOT NULL,\
                 key_id TEXT NOT NULL,\
                 payload_sha256 TEXT NOT NULL,\
                 payload BLOB NOT NULL,\
                 created_at TEXT NOT NULL\
             );\
             CREATE TABLE IF NOT EXISTS coordinator_agents (\
                 agent_id TEXT PRIMARY KEY,\
                 certificate_sha256 TEXT NOT NULL UNIQUE,\
                 enrolled_at TEXT NOT NULL,\
                 revoked_at TEXT,\
                 authorization_json TEXT NOT NULL DEFAULT '{}'\
             );",
        )
        .await
        .context("creating coordinator schema")?;
    migrate_agent_authorization(connection).await?;
    let mut rows = connection
        .query(
            "SELECT value FROM coordinator_metadata WHERE key = 'schema_version'",
            (),
        )
        .await?;
    if let Some(row) = rows.next().await? {
        let version: String = row.get(0)?;
        ensure!(
            version == DATABASE_SCHEMA_VERSION.to_string(),
            "unsupported coordinator database schema {version}"
        );
    } else {
        connection
            .execute(
                "INSERT INTO coordinator_metadata (key, value) VALUES ('schema_version', ?1)",
                turso::params![DATABASE_SCHEMA_VERSION.to_string()],
            )
            .await?;
    }
    Ok(())
}

async fn migrate_agent_authorization(connection: &turso::Connection) -> Result<()> {
    let mut rows = connection
        .query("PRAGMA table_info(coordinator_agents)", ())
        .await?;
    let mut present = false;
    while let Some(row) = rows.next().await? {
        let name: String = row.get(1)?;
        present |= name == "authorization_json";
    }
    if !present {
        connection
            .execute(
                "ALTER TABLE coordinator_agents ADD COLUMN authorization_json TEXT NOT NULL \
                 DEFAULT '{}'",
                (),
            )
            .await?;
    }
    Ok(())
}

async fn replay(connection: &turso::Connection, key: &EnvelopeKey) -> Result<LoadedState> {
    let (
        mut memory,
        mut control,
        mut artifacts,
        mut failed_attempt_projections,
        snapshot_watermark,
        snapshot_commands,
    ) = load_snapshot(connection, key).await?.unwrap_or_default();
    let mut reuse_index = build_reuse_index(&artifacts);
    let mut rows = connection
        .query(
            "SELECT sequence, record_id, key_id, payload FROM coordinator_journal \
             WHERE sequence > ?1 ORDER BY sequence",
            turso::params![
                i64::try_from(snapshot_watermark)
                    .context("snapshot watermark exceeds database integer range")?
            ],
        )
        .await?;
    let mut journal = JournalState {
        total_commands: snapshot_commands,
        watermark_sequence: snapshot_watermark,
        tail_commands: 0,
        tail_bytes: 0,
    };
    while let Some(row) = rows.next().await? {
        let sequence = u64::try_from(row.get::<i64>(0)?).context("journal sequence is negative")?;
        let record_id: String = row.get(1)?;
        let key_id: String = row.get(2)?;
        let payload: Vec<u8> = row.get(3)?;
        ensure!(
            key_id == key.key_id(),
            "journal requires envelope key {key_id}"
        );
        let command_bytes = key
            .open(record_aad(&record_id, &key_id).as_bytes(), &payload)
            .with_context(|| format!("decrypting journal record {record_id}"))?;
        let command: DurableCommandV1 = serde_json::from_slice(&command_bytes)
            .with_context(|| format!("decoding journal record {record_id}"))?;
        validate_artifact_command(&memory, &artifacts, &command)
            .with_context(|| format!("validating journal record {record_id}"))?;
        validate_failed_attempt_projection_command(&memory, &failed_attempt_projections, &command)
            .with_context(|| format!("validating journal record {record_id}"))?;
        let outcome = apply_to_state(
            &mut memory,
            &mut control,
            &artifacts,
            &failed_attempt_projections,
            &command,
        )
        .with_context(|| format!("replaying journal record {record_id}"))?;
        update_artifact_index(&mut artifacts, &mut reuse_index, &command, &outcome);
        update_failed_attempt_projection_outbox(
            &mut failed_attempt_projections,
            &memory,
            &command,
            &outcome,
        );
        journal.total_commands = journal.total_commands.saturating_add(1);
        journal.tail_commands = journal.tail_commands.saturating_add(1);
        journal.tail_bytes = journal.tail_bytes.saturating_add(payload.len() as u64);
        journal.watermark_sequence = sequence;
    }
    Ok(LoadedState {
        memory,
        control,
        artifacts,
        failed_attempt_projections,
        reuse_index,
        journal,
    })
}

async fn load_snapshot(
    connection: &turso::Connection,
    key: &EnvelopeKey,
) -> Result<
    Option<(
        InMemoryStateStore,
        ControlState,
        BTreeMap<TaskId, ArtifactRecordV1>,
        BTreeMap<FailedAttemptProjectionKeyV1, FailedAttemptProjectionRecordV1>,
        u64,
        u64,
    )>,
> {
    let mut rows = connection
        .query(
            "SELECT format_version, watermark_sequence, key_id, payload_sha256, payload \
             FROM coordinator_snapshot WHERE snapshot_id = 1",
            (),
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    let format_version =
        u16::try_from(row.get::<i64>(0)?).context("snapshot format version is outside u16")?;
    ensure!(
        format_version == SNAPSHOT_SCHEMA_VERSION,
        "unsupported coordinator snapshot schema {format_version}"
    );
    let watermark = u64::try_from(row.get::<i64>(1)?).context("snapshot watermark is negative")?;
    let key_id: String = row.get(2)?;
    ensure!(
        key_id == key.key_id(),
        "snapshot requires envelope key {key_id}"
    );
    let expected_digest: String = row.get(3)?;
    ensure!(
        expected_digest.len() == 64 && expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "snapshot contains an invalid SHA-256 digest"
    );
    let payload: Vec<u8> = row.get(4)?;
    let plaintext = key
        .open(
            snapshot_aad(format_version, watermark, &key_id, &expected_digest).as_bytes(),
            &payload,
        )
        .context("authenticating coordinator snapshot")?;
    ensure!(
        plaintext.len() <= MAX_SNAPSHOT_BYTES,
        "coordinator snapshot exceeds the decode limit"
    );
    ensure!(
        sha256_hex(&plaintext) == expected_digest,
        "coordinator snapshot digest mismatch"
    );
    let snapshot: CoordinatorSnapshotV1 =
        serde_json::from_slice(&plaintext).context("decoding coordinator snapshot")?;
    ensure!(
        snapshot.schema_version == SNAPSHOT_SCHEMA_VERSION,
        "unsupported coordinator snapshot payload schema {}",
        snapshot.schema_version
    );
    let memory = InMemoryStateStore::from_snapshot(snapshot.state)
        .context("restoring coordinator state snapshot")?;
    let control = snapshot
        .control
        .map(ControlState::restore)
        .transpose()
        .context("restoring control-plane state snapshot")?
        .unwrap_or_default();
    let mut artifacts = BTreeMap::new();
    let mut catalog = CacheCatalog::default();
    for artifact in snapshot.artifacts {
        catalog
            .insert(artifact.metadata.clone())
            .map_err(|error| anyhow!("invalid snapshot artifact metadata: {error}"))?;
        ensure!(
            artifacts
                .insert(artifact.task_id.clone(), artifact)
                .is_none(),
            "snapshot contains duplicate artifact task IDs"
        );
    }
    let mut failed_attempt_projections = BTreeMap::new();
    for record in snapshot.failed_attempt_projections {
        ensure!(
            failed_attempt_projection_digest(&record) == record.projection_digest,
            "snapshot contains an invalid failed-attempt projection digest"
        );
        ensure!(
            failed_attempt_projections
                .insert(record.key.clone(), record)
                .is_none(),
            "snapshot contains duplicate failed-attempt projection keys"
        );
    }
    Ok(Some((
        memory,
        control,
        artifacts,
        failed_attempt_projections,
        watermark,
        snapshot.command_count,
    )))
}

async fn compact_state(
    connection: &turso::Connection,
    key: &EnvelopeKey,
    memory: &InMemoryStateStore,
    control: &ControlState,
    artifacts: &BTreeMap<TaskId, ArtifactRecordV1>,
    failed_attempt_projections: &BTreeMap<
        FailedAttemptProjectionKeyV1,
        FailedAttemptProjectionRecordV1,
    >,
    journal: &mut JournalState,
) -> Result<CompactionStatsV1> {
    let stats = CompactionStatsV1 {
        watermark_sequence: journal.watermark_sequence,
        commands_compacted: journal.tail_commands,
        bytes_compacted: journal.tail_bytes,
    };
    if journal.tail_commands == 0 {
        return Ok(stats);
    }
    let snapshot = CoordinatorSnapshotV1 {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        command_count: journal.total_commands,
        state: memory.snapshot(),
        artifacts: artifacts.values().cloned().collect(),
        failed_attempt_projections: failed_attempt_projections.values().cloned().collect(),
        control: Some(control.snapshot()),
    };
    let plaintext = serde_json::to_vec(&snapshot).context("serializing coordinator snapshot")?;
    ensure!(
        plaintext.len() <= MAX_SNAPSHOT_BYTES,
        "coordinator snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte limit"
    );
    let digest = sha256_hex(&plaintext);
    let payload = key.seal(
        snapshot_aad(
            SNAPSHOT_SCHEMA_VERSION,
            journal.watermark_sequence,
            key.key_id(),
            &digest,
        )
        .as_bytes(),
        &plaintext,
    )?;
    let watermark = i64::try_from(journal.watermark_sequence)
        .context("journal watermark exceeds database integer range")?;
    connection.execute_batch("BEGIN IMMEDIATE").await?;
    let transaction = async {
        let mut rows = connection
            .query(
                "SELECT COALESCE(MAX(sequence), 0) FROM coordinator_journal",
                (),
            )
            .await?;
        let maximum: i64 = rows
            .next()
            .await?
            .context("journal maximum query returned no row")?
            .get(0)?;
        ensure!(
            maximum == watermark,
            "journal changed while creating its snapshot"
        );
        connection
            .execute(
                "INSERT INTO coordinator_snapshot (snapshot_id, format_version, \
                 watermark_sequence, key_id, payload_sha256, payload, created_at) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(snapshot_id) DO UPDATE SET \
                 format_version = excluded.format_version, \
                 watermark_sequence = excluded.watermark_sequence, \
                 key_id = excluded.key_id, payload_sha256 = excluded.payload_sha256, \
                 payload = excluded.payload, created_at = excluded.created_at",
                turso::params![
                    i64::from(SNAPSHOT_SCHEMA_VERSION),
                    watermark,
                    key.key_id(),
                    digest,
                    payload,
                    Utc::now().to_rfc3339()
                ],
            )
            .await?;
        connection
            .execute(
                "DELETE FROM coordinator_journal WHERE sequence <= ?1",
                turso::params![watermark],
            )
            .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    match transaction {
        Ok(()) => connection.execute_batch("COMMIT").await?,
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK").await;
            return Err(error);
        }
    }
    journal.tail_commands = 0;
    journal.tail_bytes = 0;
    Ok(stats)
}

async fn append(
    connection: &turso::Connection,
    key: &EnvelopeKey,
    command: &DurableCommandV1,
) -> Result<JournalAppend> {
    let record_id = Uuid::new_v4().to_string();
    let command_bytes = serde_json::to_vec(command)?;
    let payload = key.seal(
        record_aad(&record_id, key.key_id()).as_bytes(),
        &command_bytes,
    )?;
    let stored_bytes = payload.len() as u64;
    connection.execute_batch("BEGIN IMMEDIATE").await?;
    let inserted = connection
        .execute(
            "INSERT INTO coordinator_journal (record_id, key_id, payload) VALUES (?1, ?2, ?3)",
            turso::params![record_id, key.key_id(), payload],
        )
        .await;
    let sequence = match inserted {
        Ok(_) => {
            let mut rows = connection.query("SELECT last_insert_rowid()", ()).await?;
            let row = rows
                .next()
                .await?
                .context("journal insert did not return a sequence")?;
            let sequence =
                u64::try_from(row.get::<i64>(0)?).context("journal sequence is negative")?;
            connection.execute_batch("COMMIT").await?;
            sequence
        }
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK").await;
            return Err(error.into());
        }
    };
    Ok(JournalAppend {
        sequence,
        stored_bytes,
    })
}

fn apply_to_memory(
    memory: &mut InMemoryStateStore,
    command: &DurableCommandV1,
) -> Result<DurableOutcomeV1> {
    let outcome = match command {
        DurableCommandV1::Control { .. } => {
            bail!("control command requires the control-plane aggregate")
        }
        DurableCommandV1::MarkArtifactProjected { .. } => {
            bail!("projection command requires the artifact index")
        }
        DurableCommandV1::MarkFailedAttemptProjected { .. } => {
            bail!("projection command requires the failed-attempt outbox")
        }
        DurableCommandV1::PruneFailedAttemptProjectionsBefore { .. } => {
            bail!("failed-attempt retention requires the projection outbox")
        }
        DurableCommandV1::PruneTerminalRunsBefore { .. } => {
            bail!("whole-run retention requires the artifact index")
        }
        DurableCommandV1::SubmitJob { request } => {
            DurableOutcomeV1::Submitted(memory.submit_job(request.clone())?)
        }
        DurableCommandV1::SubmitJobWithTasks {
            request,
            tasks,
            now,
        } => submit_job_with_tasks(memory, request, tasks, *now)?,
        DurableCommandV1::StartJob { job_id, now } => {
            memory.start_job(job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::StartNextQueuedJob { now } => {
            DurableOutcomeV1::StartedJob(memory.start_next_queued_job(*now)?)
        }
        DurableCommandV1::PauseJob { job_id, now } => {
            memory.pause_job(job_id, *now)?;
            let _ = memory.start_next_queued_job(*now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::ResumeJob { job_id, now } => {
            memory.resume_job(job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::CancelJob { job_id, now } => {
            memory.cancel_job(job_id, *now)?;
            let _ = memory.start_next_queued_job(*now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::FinalizeJob {
            job_id,
            partial_reasons,
            now,
        } => {
            memory.finalize_job(job_id, partial_reasons.clone(), *now)?;
            let _ = memory.start_next_queued_job(*now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::EnqueueTask { task } => {
            memory.enqueue_task(task.clone())?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::LeaseNextTask {
            job_id,
            agent_id,
            lease_id,
            lease_seconds,
            now,
        } => DurableOutcomeV1::Task(memory.lease_next_task(
            job_id,
            agent_id,
            lease_id,
            *lease_seconds,
            *now,
        )?),
        DurableCommandV1::LeaseNextAuthorizedTask {
            authorization,
            agent_id,
            lease_id,
            lease_seconds,
            now,
        } => DurableOutcomeV1::Task(memory.lease_next_authorized_task(
            authorization,
            agent_id,
            lease_id,
            *lease_seconds,
            *now,
        )?),
        DurableCommandV1::HeartbeatTask {
            task_id,
            agent_id,
            lease_id,
            lease_seconds,
            now,
        } => {
            memory.heartbeat_task(task_id, agent_id, lease_id, *lease_seconds, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::DeferTask {
            task_id,
            agent_id,
            lease_id,
            not_before,
            reason_code,
            now,
        } => {
            memory.defer_task(task_id, agent_id, lease_id, *not_before, reason_code, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::CompleteTask {
            task_id,
            agent_id,
            lease_id,
            result,
            now,
        } => {
            let job_id = memory
                .task(task_id)
                .context("task was not found")?
                .job_id
                .clone();
            memory.complete_task(task_id, agent_id, lease_id, result.clone(), *now)?;
            auto_finalize_job(memory, &job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::CompleteTaskWithArtifact {
            task_id,
            agent_id,
            lease_id,
            result,
            artifact,
            usage,
            now,
        } => {
            memory.validate_completion(task_id, agent_id, lease_id, result, *now)?;
            if let Some(resource) =
                apply_task_usage(memory, &artifact.job_id, task_id, lease_id, *usage, *now)?
            {
                let _ = memory.start_next_queued_job(*now)?;
                return Ok(DurableOutcomeV1::QuotaExceeded(resource));
            }
            let already_succeeded = memory
                .task(task_id)
                .is_some_and(|task| task.state == RepositoryTaskStateV1::Succeeded);
            if !already_succeeded {
                let reservation_id = ReservationId(format!("artifact:{}", task_id.0));
                let reservation = memory.reserve_quota(
                    reservation_id.clone(),
                    &artifact.job_id,
                    QuotaResourceV1::ArtifactBytes,
                    result.stored_bytes,
                    *now,
                );
                if let Err(StoreError::QuotaExceeded(resource)) = reservation {
                    let _ = memory.start_next_queued_job(*now)?;
                    return Ok(DurableOutcomeV1::QuotaExceeded(resource));
                }
                reservation?;
                memory.reconcile_quota(&reservation_id, result.stored_bytes, *now)?;
            }
            memory.complete_task(task_id, agent_id, lease_id, result.clone(), *now)?;
            auto_finalize_job(memory, &artifact.job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::RemoveExpiredArtifact { .. }
        | DurableCommandV1::InvalidateCacheKey { .. }
        | DurableCommandV1::TouchCacheKey { .. } => DurableOutcomeV1::Applied,
        DurableCommandV1::FailTask {
            task_id,
            agent_id,
            lease_id,
            failure,
            retry_at,
            usage,
            now,
        } => {
            let failure = TaskFailureV1 {
                task_id: task_id.clone(),
                agent_id: agent_id.clone(),
                lease_id: lease_id.clone(),
                failure: failure.clone(),
                retry_at: *retry_at,
                observed_at: *now,
            };
            let job_id = memory
                .task(task_id)
                .context("task was not found")?
                .job_id
                .clone();
            memory.validate_failure(&failure)?;
            if let Some(resource) =
                apply_task_usage(memory, &job_id, task_id, lease_id, *usage, *now)?
            {
                let _ = memory.start_next_queued_job(*now)?;
                return Ok(DurableOutcomeV1::QuotaExceeded(resource));
            }
            memory.fail_task(failure)?;
            auto_finalize_job(memory, &job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::ReclaimExpiredLeases { now } => {
            DurableOutcomeV1::Tasks(memory.reclaim_expired_leases(*now)?)
        }
        DurableCommandV1::PruneEventsBefore { cutoff } => {
            DurableOutcomeV1::EventsPruned(memory.prune_events_before(*cutoff)?)
        }
        DurableCommandV1::ReserveQuota {
            reservation_id,
            job_id,
            resource,
            amount,
            now,
        } => match memory.reserve_quota(reservation_id.clone(), job_id, *resource, *amount, *now) {
            Ok(outcome) => DurableOutcomeV1::Reservation(outcome),
            Err(StoreError::QuotaExceeded(resource)) => {
                let _ = memory.start_next_queued_job(*now)?;
                DurableOutcomeV1::QuotaExceeded(resource)
            }
            Err(error) => return Err(error.into()),
        },
        DurableCommandV1::ReconcileQuota {
            reservation_id,
            actual_amount,
            now,
        } => {
            memory.reconcile_quota(reservation_id, *actual_amount, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::ReleaseQuota {
            reservation_id,
            now,
        } => {
            memory.release_quota(reservation_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::ConfigureProvider { key, policy } => {
            memory.configure_provider(key.clone(), *policy)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::AcquireProviderPermit {
            key,
            permit_id,
            agent_id,
            now,
        } => DurableOutcomeV1::Permit(memory.acquire_provider_permit(
            key,
            permit_id.clone(),
            agent_id,
            *now,
        )?),
        DurableCommandV1::FinishProviderRequest {
            permit_id,
            agent_id,
            outcome,
            observation,
            now,
        } => {
            memory.finish_provider_request(permit_id, agent_id, *outcome, observation, *now)?;
            DurableOutcomeV1::Applied
        }
    };
    Ok(outcome)
}

fn apply_task_usage(
    memory: &mut InMemoryStateStore,
    job_id: &JobId,
    task_id: &TaskId,
    lease_id: &str,
    usage: TaskUsageV1,
    now: DateTime<Utc>,
) -> Result<Option<QuotaResourceV1>> {
    for (resource, amount, label) in [
        (
            QuotaResourceV1::ProviderRequests,
            usage.provider_requests,
            "provider_requests",
        ),
        (
            QuotaResourceV1::DownloadedBytes,
            usage.downloaded_bytes,
            "downloaded_bytes",
        ),
    ] {
        if amount == 0 {
            continue;
        }
        let reservation_id = ReservationId(format!("usage:{label}:{}:{lease_id}", task_id.0));
        match memory.reserve_quota(reservation_id.clone(), job_id, resource, amount, now) {
            Ok(_) => memory.reconcile_quota(&reservation_id, amount, now)?,
            Err(StoreError::QuotaExceeded(resource)) => return Ok(Some(resource)),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(None)
}

fn submit_job_with_tasks(
    memory: &mut InMemoryStateStore,
    request: &SubmitJobV1,
    tasks: &[NewRepositoryTaskV1],
    now: DateTime<Utc>,
) -> Result<DurableOutcomeV1> {
    Ok(DurableOutcomeV1::Submitted(
        memory.submit_job_with_tasks_atomic(request, tasks, now)?,
    ))
}

fn validate_artifact_command(
    memory: &InMemoryStateStore,
    artifacts: &BTreeMap<TaskId, ArtifactRecordV1>,
    command: &DurableCommandV1,
) -> Result<()> {
    if let DurableCommandV1::RemoveExpiredArtifact { task_id, now } = command {
        if let Some(artifact) = artifacts.get(task_id) {
            ensure!(
                artifact.metadata.is_retention_candidate(*now),
                "artifact is still retained"
            );
        }
        return Ok(());
    }
    if let DurableCommandV1::MarkArtifactProjected {
        task_id,
        artifact_digest,
        ..
    } = command
    {
        let artifact = artifacts
            .get(task_id)
            .context("artifact task was not found")?;
        ensure!(
            artifact.metadata.key.digest == *artifact_digest,
            "artifact digest changed before inventory projection"
        );
        return Ok(());
    }
    let DurableCommandV1::CompleteTaskWithArtifact {
        task_id,
        result,
        artifact,
        ..
    } = command
    else {
        return Ok(());
    };
    ensure!(artifact.task_id == *task_id, "artifact task ID mismatch");
    ensure!(
        artifact.metadata.key.digest == result.digest,
        "artifact digest metadata mismatch"
    );
    ensure!(
        artifact.metadata.content_length == result.stored_bytes,
        "artifact length metadata mismatch"
    );
    ensure!(
        artifact.metadata.content_kind == CacheContentKindV1::DerivedEvidence,
        "task results must be derived evidence"
    );
    ensure!(
        matches!(
            artifact.metadata.protection,
            CacheProtectionV1::EnvelopeEncrypted { .. }
        ),
        "task evidence must use application envelope encryption"
    );
    CacheCatalog::default()
        .insert(artifact.metadata.clone())
        .map_err(|error| anyhow!("invalid artifact cache metadata: {error}"))?;
    let task = memory
        .task(task_id)
        .context("artifact task was not found")?;
    ensure!(task.job_id == artifact.job_id, "artifact job ID mismatch");
    let job = memory
        .job(&artifact.job_id)
        .context("artifact job was not found")?;
    let expected_namespace = match job.spec.repository_scope {
        RepositoryScopeV1::PublicOnly => CacheNamespaceV1::Public,
        RepositoryScopeV1::AllVisible => CacheNamespaceV1::Private {
            principal_id: job
                .spec
                .credential_profile_id
                .clone()
                .context("private job lacks credential profile")?,
        },
    };
    ensure!(
        artifact.metadata.key.namespace == expected_namespace,
        "artifact cache namespace does not match job scope"
    );
    if let Some(existing) = artifacts.get(task_id) {
        ensure!(
            artifact_records_compatible(existing, artifact),
            "task artifact metadata conflicts"
        );
    }
    Ok(())
}

fn validate_failed_attempt_projection_command(
    memory: &InMemoryStateStore,
    projections: &BTreeMap<FailedAttemptProjectionKeyV1, FailedAttemptProjectionRecordV1>,
    command: &DurableCommandV1,
) -> Result<()> {
    match command {
        DurableCommandV1::MarkFailedAttemptProjected {
            key,
            projection_digest,
            ..
        } => {
            let record = projections
                .get(key)
                .context("failed-attempt projection was not found")?;
            ensure!(
                record.projection_digest == *projection_digest,
                "failed-attempt projection changed before it was marked"
            );
        }
        DurableCommandV1::FailTask {
            task_id,
            retry_at,
            now,
            ..
        } => {
            let record = failed_attempt_projection_record(memory, task_id, *retry_at, *now)?;
            if let Some(existing) = projections.get(&record.key) {
                ensure!(
                    existing.projection_digest == record.projection_digest,
                    "failed-attempt projection conflicts with its durable outbox record"
                );
            }
        }
        _ => {}
    }
    Ok(())
}

fn failed_attempt_projection_record(
    memory: &InMemoryStateStore,
    task_id: &TaskId,
    retry_at: Option<DateTime<Utc>>,
    completed_at: DateTime<Utc>,
) -> Result<FailedAttemptProjectionRecordV1> {
    let task = memory.task(task_id).context("task was not found")?;
    let job = memory
        .job(&task.job_id)
        .context("failed-attempt task job was not found")?;
    let namespace = match job.spec.repository_scope {
        RepositoryScopeV1::PublicOnly => CacheNamespaceV1::Public,
        RepositoryScopeV1::AllVisible => CacheNamespaceV1::Private {
            principal_id: job
                .spec
                .credential_profile_id
                .clone()
                .context("private job lacks credential profile")?,
        },
    };
    let repository_alias = task.repository_id.clone();
    let normalized_repository_alias = crate::catalog::normalize_repository_alias(&repository_alias);
    ensure!(
        !normalized_repository_alias.is_empty(),
        "failed-attempt repository alias is empty"
    );
    let (failure_code, failure_message) = if retry_at.is_some() {
        (
            "scan_attempt_retryable",
            "repository scan attempt failed and is scheduled for retry",
        )
    } else {
        ("scan_attempt_failed", "repository scan attempt failed")
    };
    let mut record = FailedAttemptProjectionRecordV1 {
        key: FailedAttemptProjectionKeyV1 {
            task_id: task.id.clone(),
            task_attempt: task.attempt,
        },
        job_id: task.job_id.clone(),
        namespace,
        repository_alias,
        normalized_repository_alias,
        completed_at,
        failure_code: failure_code.to_owned(),
        failure_message: failure_message.to_owned(),
        projection_digest: super::Sha256Digest::parse("0".repeat(64))
            .expect("zero digest has valid syntax"),
        inventory_projection: InventoryProjectionStateV1::Pending,
    };
    record.projection_digest = failed_attempt_projection_digest(&record);
    Ok(record)
}

fn failed_attempt_projection_digest(
    record: &FailedAttemptProjectionRecordV1,
) -> super::Sha256Digest {
    let canonical = serde_json::to_vec(&(
        "failed-attempt-projection-v1",
        &record.key,
        &record.job_id,
        &record.namespace,
        &record.repository_alias,
        &record.normalized_repository_alias,
        record.completed_at,
        &record.failure_code,
        &record.failure_message,
    ))
    .expect("failed-attempt projection fields are JSON serializable");
    super::Sha256Digest::parse(sha256_hex(&canonical))
        .expect("SHA-256 output always has valid digest syntax")
}

fn update_artifact_index(
    artifacts: &mut BTreeMap<TaskId, ArtifactRecordV1>,
    reuse_index: &mut ReuseIndex,
    command: &DurableCommandV1,
    outcome: &DurableOutcomeV1,
) {
    if matches!(outcome, DurableOutcomeV1::QuotaExceeded(_)) {
        return;
    }
    match command {
        DurableCommandV1::CompleteTaskWithArtifact { artifact, .. } => {
            let artifact = artifacts
                .entry(artifact.task_id.clone())
                .or_insert_with(|| artifact.as_ref().clone());
            index_reusable_artifact(reuse_index, artifact);
        }
        DurableCommandV1::MarkArtifactProjected { task_id, now, .. } => {
            let artifact = artifacts
                .get_mut(task_id)
                .expect("projection command was validated before persistence");
            if !matches!(
                artifact.inventory_projection,
                InventoryProjectionStateV1::Projected { .. }
            ) {
                artifact.inventory_projection = InventoryProjectionStateV1::Projected { at: *now };
            }
        }
        DurableCommandV1::RemoveExpiredArtifact { task_id, .. } => {
            if let Some(artifact) = artifacts.remove(task_id) {
                remove_reusable_artifact(reuse_index, &artifact);
            }
        }
        DurableCommandV1::InvalidateCacheKey { key, .. } => {
            let removed = artifacts
                .extract_if(.., |_, artifact| artifact.metadata.key == *key)
                .map(|(_, artifact)| artifact)
                .collect::<Vec<_>>();
            for artifact in removed {
                remove_reusable_artifact(reuse_index, &artifact);
            }
        }
        DurableCommandV1::TouchCacheKey { key, accessed_at } => {
            for artifact in artifacts
                .values_mut()
                .filter(|artifact| artifact.metadata.key == *key)
            {
                if artifact.metadata.last_accessed_at < *accessed_at {
                    artifact.metadata.last_accessed_at = *accessed_at;
                }
            }
        }
        _ => {}
    }
}

fn update_failed_attempt_projection_outbox(
    projections: &mut BTreeMap<FailedAttemptProjectionKeyV1, FailedAttemptProjectionRecordV1>,
    memory: &InMemoryStateStore,
    command: &DurableCommandV1,
    outcome: &DurableOutcomeV1,
) {
    if matches!(outcome, DurableOutcomeV1::QuotaExceeded(_)) {
        return;
    }
    match command {
        DurableCommandV1::FailTask {
            task_id,
            retry_at,
            now,
            ..
        } => {
            let record = failed_attempt_projection_record(memory, task_id, *retry_at, *now)
                .expect("failure projection command was validated before persistence");
            projections.entry(record.key.clone()).or_insert(record);
        }
        DurableCommandV1::MarkFailedAttemptProjected { key, now, .. } => {
            let record = projections
                .get_mut(key)
                .expect("projection marker command was validated before persistence");
            if !matches!(
                record.inventory_projection,
                InventoryProjectionStateV1::Projected { .. }
            ) {
                record.inventory_projection = InventoryProjectionStateV1::Projected { at: *now };
            }
        }
        DurableCommandV1::PruneFailedAttemptProjectionsBefore { cutoff } => {
            projections.retain(|_, record| record.completed_at >= *cutoff);
        }
        _ => {}
    }
}

fn index_reusable_artifact(index: &mut ReuseIndex, artifact: &ArtifactRecordV1) {
    if artifact.metadata.completeness != super::EvidenceCompletenessV1::Complete {
        return;
    }
    let Some(fingerprint) = artifact.metadata.reuse_fingerprint.clone() else {
        return;
    };
    index
        .entry((artifact.metadata.key.namespace.clone(), fingerprint))
        .or_default()
        .insert(artifact.task_id.clone());
}

fn build_reuse_index(artifacts: &BTreeMap<TaskId, ArtifactRecordV1>) -> ReuseIndex {
    let mut index = ReuseIndex::new();
    for artifact in artifacts.values() {
        index_reusable_artifact(&mut index, artifact);
    }
    index
}

fn remove_reusable_artifact(index: &mut ReuseIndex, artifact: &ArtifactRecordV1) {
    let Some(fingerprint) = artifact.metadata.reuse_fingerprint.as_ref() else {
        return;
    };
    let key = (artifact.metadata.key.namespace.clone(), fingerprint.clone());
    let Some(task_ids) = index.get_mut(&key) else {
        return;
    };
    task_ids.remove(&artifact.task_id);
    if task_ids.is_empty() {
        index.remove(&key);
    }
}

fn artifact_records_compatible(left: &ArtifactRecordV1, right: &ArtifactRecordV1) -> bool {
    left.job_id == right.job_id
        && left.task_id == right.task_id
        && left.metadata.schema_version == right.metadata.schema_version
        && left.metadata.key == right.metadata.key
        && left.metadata.content_kind == right.metadata.content_kind
        && left.metadata.content_length == right.metadata.content_length
        && left.metadata.github_blob_sha == right.metadata.github_blob_sha
        && left.metadata.protection == right.metadata.protection
        && left.metadata.completeness == right.metadata.completeness
        && left.metadata.reuse_fingerprint == right.metadata.reuse_fingerprint
}

fn auto_finalize_job(
    memory: &mut InMemoryStateStore,
    job_id: &JobId,
    now: DateTime<Utc>,
) -> Result<()> {
    let job = memory.job(job_id).context("job was not found")?;
    if !job.state.is_terminal()
        && job.progress.tasks_total > 0
        && job.progress.tasks_pending == 0
        && job.progress.tasks_leased == 0
    {
        memory.finalize_job(job_id, BTreeSet::new(), now)?;
        let _ = memory.start_next_queued_job(now)?;
    }
    Ok(())
}

async fn backup_database(
    connection: &turso::Connection,
    source: &Path,
    destination: &Path,
    command_count: u64,
) -> Result<BackupManifestV1> {
    if destination.exists() {
        bail!(
            "backup destination {} already exists",
            destination.display()
        );
    }
    // The actor admits no writes while this checkpoint and copy execute.
    let mut rows = connection
        .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
        .await?;
    while rows.next().await?.is_some() {}
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let bytes = tokio::fs::read(source)
        .await
        .with_context(|| format!("reading database {}", source.display()))?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write as _;
    temp.write_all(&bytes)?;
    temp.as_file_mut().sync_all()?;
    temp.persist_noclobber(destination)
        .map_err(|error| error.error)?;
    Ok(BackupManifestV1 {
        schema_version: DATABASE_SCHEMA_VERSION,
        created_at: Utc::now(),
        source_database: source.display().to_string(),
        database_sha256: sha256_hex(&bytes),
        database_bytes: bytes.len() as u64,
        journal_commands: command_count,
    })
}

fn record_aad(record_id: &str, key_id: &str) -> String {
    format!("crate-dependent-repos:coordinator-journal:v1:{record_id}:{key_id}")
}

fn snapshot_aad(version: u16, watermark: u64, key_id: &str, digest: &str) -> String {
    format!("crate-dependent-repos:coordinator-snapshot:v{version}:{watermark}:{key_id}:{digest}")
}

async fn register_agent(connection: &turso::Connection, record: &AgentRecordV1) -> Result<()> {
    ensure!(!record.agent_id.trim().is_empty(), "agent ID is empty");
    record.authorization.validate()?;
    ensure!(
        record.certificate_sha256.len() == 64
            && record
                .certificate_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "invalid agent certificate SHA-256"
    );
    if let Some(existing) = load_agent(connection, &record.agent_id).await? {
        ensure!(
            existing == *record,
            "agent ID already has a different identity"
        );
        return Ok(());
    }
    if record.agent_id != "operator" {
        let mut rows = connection
            .query(
                "SELECT COUNT(*) FROM coordinator_agents WHERE agent_id <> 'operator' AND revoked_at IS NULL",
                (),
            )
            .await?;
        let count: i64 = rows
            .next()
            .await?
            .expect("COUNT always returns one row")
            .get(0)?;
        ensure!(
            u64::try_from(count).unwrap_or(u64::MAX) < MAX_ENROLLED_AGENTS,
            "agent enrollment limit {MAX_ENROLLED_AGENTS} reached"
        );
    }
    connection
        .execute(
            "INSERT INTO coordinator_agents \
             (agent_id, certificate_sha256, enrolled_at, revoked_at, authorization_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            turso::params![
                record.agent_id.clone(),
                record.certificate_sha256.to_ascii_lowercase(),
                record.enrolled_at.to_rfc3339(),
                record.revoked_at.map(|value| value.to_rfc3339()),
                serde_json::to_string(&record.authorization)?
            ],
        )
        .await?;
    Ok(())
}

async fn revoke_agent(
    connection: &turso::Connection,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    ensure!(
        agent_id != "operator",
        "the operator identity cannot be revoked"
    );
    let changed = connection
        .execute(
            "UPDATE coordinator_agents SET revoked_at = ?2 \
             WHERE agent_id = ?1 AND revoked_at IS NULL",
            turso::params![agent_id, now.to_rfc3339()],
        )
        .await?;
    ensure!(changed == 1, "agent is unknown or already revoked");
    Ok(())
}

async fn load_agent(
    connection: &turso::Connection,
    agent_id: &str,
) -> Result<Option<AgentRecordV1>> {
    let mut rows = connection
        .query(
            "SELECT agent_id, certificate_sha256, enrolled_at, revoked_at, authorization_json \
             FROM coordinator_agents WHERE agent_id = ?1",
            turso::params![agent_id],
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    let enrolled_at: String = row.get(2)?;
    let revoked_at: Option<String> = row.get(3)?;
    let authorization_json: String = row.get(4)?;
    Ok(Some(AgentRecordV1 {
        agent_id: row.get(0)?,
        certificate_sha256: row.get(1)?,
        enrolled_at: DateTime::parse_from_rfc3339(&enrolled_at)?.with_timezone(&Utc),
        revoked_at: revoked_at
            .as_deref()
            .map(DateTime::parse_from_rfc3339)
            .transpose()?
            .map(|value| value.with_timezone(&Utc)),
        authorization: serde_json::from_str(&authorization_json)
            .context("decoding agent authorization")?,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::coordinator::{
        CacheKeyV1, ControlActionV1, ControlCommandV1, ControlResultV1, CreateScheduleV1,
        EvidenceCompletenessV1, JobPriorityV1, OccurrenceStateV1, RepositoryScopeV1,
        RepositorySetContentV1, RepositorySourceRefV1, SCHEMA_VERSION_V1, ScanBoundsV1,
        ScanJobStateV1, ScanSpecV1, ScanTargetV1, ScheduleDefinitionV1, ScheduleId,
        ScheduledOccurrenceRefV1, Sha256Digest, UtcCronV1,
    };

    fn submit_request(job: &str, now: DateTime<Utc>) -> SubmitJobV1 {
        SubmitJobV1 {
            job_id: JobId(job.to_owned()),
            idempotency_key: format!("key-{job}"),
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
            submitted_at: now,
        }
    }

    fn control_command(
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

    fn submit(job: &str, now: DateTime<Utc>) -> DurableCommandV1 {
        DurableCommandV1::SubmitJob {
            request: submit_request(job, now),
        }
    }

    fn register_repository_set(
        command_id: &str,
        repository: &str,
        now: DateTime<Utc>,
    ) -> ControlCommandV1 {
        ControlCommandV1 {
            schema_version: SCHEMA_VERSION_V1,
            command_id: command_id.to_owned(),
            expected_generation: None,
            issued_at: now,
            action: ControlActionV1::RegisterRepositorySet {
                content: RepositorySetContentV1::from_repositories(vec![repository.to_owned()])
                    .unwrap(),
            },
        }
    }

    fn task(job: &str, task: &str, repository: &str, now: DateTime<Utc>) -> NewRepositoryTaskV1 {
        NewRepositoryTaskV1 {
            task_id: TaskId(task.to_owned()),
            job_id: JobId(job.to_owned()),
            repository_id: repository.to_owned(),
            not_before: now,
            created_at: now,
        }
    }

    #[test]
    fn batch_submission_is_atomic_and_repository_set_idempotent() {
        let now = Utc::now();
        let request = submit_request("batch", now);
        let tasks = vec![
            task("batch", "task-a", "example/a", now),
            task("batch", "task-b", "example/b", now),
        ];
        let mut memory = InMemoryStateStore::default();
        assert_eq!(
            submit_job_with_tasks(&mut memory, &request, &tasks, now).unwrap(),
            DurableOutcomeV1::Submitted(SubmitOutcome::Created(JobId("batch".to_owned())))
        );
        let job = memory.job(&JobId("batch".to_owned())).unwrap();
        assert_eq!(job.state, ScanJobStateV1::Running);
        assert_eq!(job.progress.tasks_total, 2);
        assert_eq!(job.quota_usage.repositories, 2);

        let retry_tasks = vec![
            task("batch", "retry-a", "example/a", now),
            task("batch", "retry-b", "example/b", now),
        ];
        assert!(matches!(
            submit_job_with_tasks(&mut memory, &request, &retry_tasks, now).unwrap(),
            DurableOutcomeV1::Submitted(SubmitOutcome::Existing(_))
        ));
        let mismatched = vec![task("batch", "retry-c", "example/c", now)];
        assert!(submit_job_with_tasks(&mut memory, &request, &mismatched, now).is_err());
        assert_eq!(
            memory
                .repository_ids_for_job(&JobId("batch".to_owned()))
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn rejected_batch_leaves_no_partial_state_before_or_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let now = Utc::now();
        let store = TursoCoordinatorStore::open(&database, key).await.unwrap();
        store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: submit_request("accepted", now),
                tasks: vec![task("accepted", "shared-task", "example/accepted", now)],
                now,
            })
            .await
            .unwrap();
        let before_events = store.events().await.unwrap();

        let error = store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: submit_request("rejected", now),
                tasks: vec![task("rejected", "shared-task", "example/rejected", now)],
                now,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("TaskIdConflict"));
        assert!(
            store
                .job(JobId("rejected".to_owned()))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(store.events().await.unwrap(), before_events);

        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert!(
            reopened
                .job(JobId("rejected".to_owned()))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(reopened.events().await.unwrap(), before_events);
    }

    #[tokio::test]
    async fn deferred_task_state_and_retry_budget_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let now = Utc::now();
        let task_id = TaskId("deferred-task".to_owned());
        let store = TursoCoordinatorStore::open(&database, key).await.unwrap();
        store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: submit_request("deferred", now),
                tasks: vec![task("deferred", &task_id.0, "example/deferred", now)],
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::LeaseNextTask {
                job_id: JobId("deferred".to_owned()),
                agent_id: "agent".to_owned(),
                lease_id: "lease".to_owned(),
                lease_seconds: 60,
                now,
            })
            .await
            .unwrap();
        let not_before = now + chrono::TimeDelta::seconds(30);
        assert_eq!(
            store
                .apply(DurableCommandV1::DeferTask {
                    task_id: task_id.clone(),
                    agent_id: "agent".to_owned(),
                    lease_id: "lease".to_owned(),
                    not_before,
                    reason_code: "provider_wait".to_owned(),
                    now: now + chrono::TimeDelta::seconds(1),
                })
                .await
                .unwrap(),
            DurableOutcomeV1::Applied
        );
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let task = reopened.task(task_id).await.unwrap().unwrap();
        assert_eq!(task.state, RepositoryTaskStateV1::Pending);
        assert_eq!(task.attempt, 0);
        assert_eq!(task.not_before, not_before);
        assert!(task.lease.is_none());
    }

    #[tokio::test]
    async fn twenty_sixth_batch_waits_and_is_promoted_durably() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let now = Utc::now();
        let store = TursoCoordinatorStore::open(&database, key).await.unwrap();
        for index in 0..=super::super::dispatch::MAX_RUNNING_JOBS {
            let job = format!("dispatch-{index:02}");
            store
                .apply(DurableCommandV1::SubmitJobWithTasks {
                    request: submit_request(&job, now + chrono::TimeDelta::seconds(index as i64)),
                    tasks: vec![task(
                        &job,
                        &format!("dispatch-task-{index:02}"),
                        &format!("example/repo-{index:02}"),
                        now,
                    )],
                    now,
                })
                .await
                .unwrap();
        }
        let queued_id = JobId(format!(
            "dispatch-{:02}",
            super::super::dispatch::MAX_RUNNING_JOBS
        ));
        assert_eq!(
            store.job(queued_id.clone()).await.unwrap().unwrap().state,
            ScanJobStateV1::Queued
        );

        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reopened
                .job(queued_id.clone())
                .await
                .unwrap()
                .unwrap()
                .state,
            ScanJobStateV1::Queued
        );
        reopened
            .apply(DurableCommandV1::PauseJob {
                job_id: JobId("dispatch-00".to_owned()),
                now: now + chrono::TimeDelta::minutes(1),
            })
            .await
            .unwrap();
        assert_eq!(
            reopened.job(queued_id).await.unwrap().unwrap().state,
            ScanJobStateV1::Running
        );
        assert_eq!(
            reopened
                .jobs()
                .await
                .unwrap()
                .into_iter()
                .filter(|job| job.state == ScanJobStateV1::Running)
                .count(),
            super::super::dispatch::MAX_RUNNING_JOBS
        );
    }

    #[test]
    fn task_usage_reconciliation_is_idempotent_per_lease() {
        let now = Utc::now();
        let request = submit_request("usage", now);
        let tasks = vec![task("usage", "task-usage", "example/app", now)];
        let mut memory = InMemoryStateStore::default();
        submit_job_with_tasks(&mut memory, &request, &tasks, now).unwrap();
        let usage = TaskUsageV1 {
            provider_requests: 7,
            downloaded_bytes: 4_096,
        };
        for _ in 0..2 {
            assert_eq!(
                apply_task_usage(
                    &mut memory,
                    &JobId("usage".to_owned()),
                    &TaskId("task-usage".to_owned()),
                    "lease-1",
                    usage,
                    now,
                )
                .unwrap(),
                None
            );
        }
        let job = memory.job(&JobId("usage".to_owned())).unwrap();
        assert_eq!(job.quota_usage.provider_requests, 7);
        assert_eq!(job.quota_usage.downloaded_bytes, 4_096);
    }

    #[test]
    fn rejected_failure_does_not_apply_task_usage() {
        let now = Utc::now();
        let job_id = JobId("failure-validation".to_owned());
        let task_id = TaskId("task-failure-validation".to_owned());
        let request = submit_request(&job_id.0, now);
        let tasks = vec![task(&job_id.0, &task_id.0, "example/app", now)];
        let mut memory = InMemoryStateStore::default();
        submit_job_with_tasks(&mut memory, &request, &tasks, now).unwrap();
        apply_to_memory(
            &mut memory,
            &DurableCommandV1::LeaseNextTask {
                job_id: job_id.clone(),
                agent_id: "worker-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                lease_seconds: 120,
                now,
            },
        )
        .unwrap();

        let before_job = memory.job(&job_id).cloned();
        let before_task = memory.task(&task_id).cloned();
        let before_provider_quota = memory
            .quota(&job_id, QuotaResourceV1::ProviderRequests)
            .cloned();
        let before_download_quota = memory
            .quota(&job_id, QuotaResourceV1::DownloadedBytes)
            .cloned();
        let before_events = memory.events();
        let error = apply_to_memory(
            &mut memory,
            &DurableCommandV1::FailTask {
                task_id: task_id.clone(),
                agent_id: "worker-1".to_owned(),
                lease_id: "wrong-lease".to_owned(),
                failure: "temporary".to_owned(),
                retry_at: Some(now + chrono::TimeDelta::seconds(30)),
                usage: TaskUsageV1 {
                    provider_requests: 7,
                    downloaded_bytes: 4_096,
                },
                now: now + chrono::TimeDelta::seconds(1),
            },
        )
        .unwrap_err();

        assert_eq!(
            error.downcast_ref::<StoreError>(),
            Some(&StoreError::LeaseMismatch)
        );
        assert_eq!(memory.job(&job_id).cloned(), before_job);
        assert_eq!(memory.task(&task_id).cloned(), before_task);
        assert_eq!(
            memory
                .quota(&job_id, QuotaResourceV1::ProviderRequests)
                .cloned(),
            before_provider_quota
        );
        assert_eq!(
            memory
                .quota(&job_id, QuotaResourceV1::DownloadedBytes)
                .cloned(),
            before_download_quota
        );
        assert_eq!(memory.events(), before_events);
    }

    #[tokio::test]
    async fn rejected_failure_keeps_live_and_replayed_state_identical() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        EnvelopeKey::generate("test-key")
            .persist_new(&key_path)
            .unwrap();
        let now = Utc::now();
        let job_id = JobId("failure-replay".to_owned());
        let task_id = TaskId("task-failure-replay".to_owned());
        let store = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: submit_request(&job_id.0, now),
                tasks: vec![task(&job_id.0, &task_id.0, "example/app", now)],
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::LeaseNextTask {
                job_id: job_id.clone(),
                agent_id: "worker-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                lease_seconds: 120,
                now,
            })
            .await
            .unwrap();
        let before_job = store.job(job_id.clone()).await.unwrap();
        let before_task = store.task(task_id.clone()).await.unwrap();
        let before_events = store.events().await.unwrap();

        let error = store
            .apply(DurableCommandV1::FailTask {
                task_id: task_id.clone(),
                agent_id: "worker-1".to_owned(),
                lease_id: "wrong-lease".to_owned(),
                failure: "temporary".to_owned(),
                retry_at: Some(now + chrono::TimeDelta::seconds(30)),
                usage: TaskUsageV1 {
                    provider_requests: 7,
                    downloaded_bytes: 4_096,
                },
                now: now + chrono::TimeDelta::seconds(1),
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("LeaseMismatch"));
        assert_eq!(store.job(job_id.clone()).await.unwrap(), before_job);
        assert_eq!(store.task(task_id.clone()).await.unwrap(), before_task);
        assert_eq!(store.events().await.unwrap(), before_events);

        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(reopened.job(job_id).await.unwrap(), before_job);
        assert_eq!(reopened.task(task_id).await.unwrap(), before_task);
        assert_eq!(reopened.events().await.unwrap(), before_events);
    }

    #[tokio::test]
    async fn failed_attempt_projection_outbox_survives_compaction_and_marking() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        EnvelopeKey::generate("test-key")
            .persist_new(&key_path)
            .unwrap();
        let now = Utc::now();
        let job_id = JobId("failure-outbox".to_owned());
        let task_id = TaskId("failure-outbox-task".to_owned());
        let store = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: submit_request(&job_id.0, now),
                tasks: vec![task(&job_id.0, &task_id.0, "Example/App", now)],
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::LeaseNextTask {
                job_id,
                agent_id: "worker".to_owned(),
                lease_id: "lease".to_owned(),
                lease_seconds: 120,
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::FailTask {
                task_id: task_id.clone(),
                agent_id: "worker".to_owned(),
                lease_id: "lease".to_owned(),
                failure: "sensitive upstream response".to_owned(),
                retry_at: None,
                usage: TaskUsageV1::default(),
                now: now + chrono::TimeDelta::seconds(1),
            })
            .await
            .unwrap();
        let [pending] = store
            .pending_failed_attempt_projections_page(None, 10)
            .await
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(pending.key.task_attempt, 1);
        assert_eq!(pending.normalized_repository_alias, "example/app");
        assert!(!pending.failure_message.contains("sensitive"));
        store.compact().await.unwrap();
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reopened
                .pending_failed_attempt_projections_page(None, 10)
                .await
                .unwrap(),
            vec![pending.clone()]
        );
        assert_eq!(
            reopened
                .apply(DurableCommandV1::MarkFailedAttemptProjected {
                    key: pending.key.clone(),
                    projection_digest: pending.projection_digest.clone(),
                    now: now + chrono::TimeDelta::seconds(2),
                })
                .await
                .unwrap(),
            DurableOutcomeV1::FailedAttemptProjection(FailedAttemptProjectionOutcomeV1::Marked)
        );
        reopened.compact().await.unwrap();
        drop(reopened);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert!(
            reopened
                .pending_failed_attempt_projections_page(None, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reopened
                .apply(DurableCommandV1::PruneFailedAttemptProjectionsBefore {
                    cutoff: now + chrono::TimeDelta::days(365),
                })
                .await
                .unwrap(),
            DurableOutcomeV1::FailedAttemptProjectionsPruned(1)
        );
        assert_eq!(
            reopened
                .apply(DurableCommandV1::PruneFailedAttemptProjectionsBefore {
                    cutoff: now + chrono::TimeDelta::days(365),
                })
                .await
                .unwrap(),
            DurableOutcomeV1::FailedAttemptProjectionsPruned(0)
        );
        reopened.compact().await.unwrap();
        drop(reopened);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert!(
            reopened
                .apply(DurableCommandV1::MarkFailedAttemptProjected {
                    key: pending.key,
                    projection_digest: pending.projection_digest,
                    now: now + chrono::TimeDelta::days(365),
                })
                .await
                .is_err()
        );
    }

    #[test]
    fn failed_attempt_projection_retention_expires_pending_private_aliases() {
        let cutoff = Utc::now();
        let key = FailedAttemptProjectionKeyV1 {
            task_id: TaskId("expired-private-task".to_owned()),
            task_attempt: 1,
        };
        let record = FailedAttemptProjectionRecordV1 {
            key: key.clone(),
            job_id: JobId("expired-private-job".to_owned()),
            namespace: CacheNamespaceV1::Private {
                principal_id: "private-profile".to_owned(),
            },
            repository_alias: "Private/Repository".to_owned(),
            normalized_repository_alias: "private/repository".to_owned(),
            completed_at: cutoff - chrono::TimeDelta::seconds(1),
            failure_code: "scan_attempt_failed".to_owned(),
            failure_message: "repository scan attempt failed".to_owned(),
            projection_digest: Sha256Digest::parse("a".repeat(64)).unwrap(),
            inventory_projection: InventoryProjectionStateV1::Pending,
        };
        let mut projections = BTreeMap::from([(key, record)]);
        update_failed_attempt_projection_outbox(
            &mut projections,
            &InMemoryStateStore::default(),
            &DurableCommandV1::PruneFailedAttemptProjectionsBefore { cutoff },
            &DurableOutcomeV1::FailedAttemptProjectionsPruned(1),
        );
        assert!(projections.is_empty());
    }

    #[test]
    fn terminal_run_retention_preserves_retained_occurrence_jobs() {
        let now = Utc::now();
        let cutoff = now + chrono::TimeDelta::days(365);
        let protected_job = JobId("scheduled-protected".to_owned());
        let orphan_job = JobId("scheduled-orphan".to_owned());
        let mut memory = InMemoryStateStore::default();
        for job_id in [&protected_job, &orphan_job] {
            memory.submit_job(submit_request(&job_id.0, now)).unwrap();
            memory.start_job(job_id, now).unwrap();
            memory.cancel_job(job_id, now).unwrap();
        }

        let content =
            RepositorySetContentV1::from_repositories(vec!["owner/repository".to_owned()]).unwrap();
        let schedule_id = ScheduleId("retained-job".to_owned());
        let mut control = ControlState::default();
        control
            .apply(control_command(
                "create-retained-job",
                now,
                ControlActionV1::CreateSchedule {
                    request: CreateScheduleV1 {
                        schema_version: SCHEMA_VERSION_V1,
                        schedule_id: schedule_id.clone(),
                        enabled: true,
                        definition: ScheduleDefinitionV1 {
                            schema_version: SCHEMA_VERSION_V1,
                            cron: UtcCronV1::parse("0 * * * *").unwrap(),
                            scan_spec: submit_request("spec", now).spec,
                            repository_source: RepositorySourceRefV1::Explicit {
                                repository_set: content.repository_set.clone(),
                            },
                            priority: JobPriorityV1::Normal,
                            max_run_age_seconds: 3_600,
                        },
                        created_at: now,
                    },
                    repository_set_content: Some(content),
                },
            ))
            .unwrap();
        let planned = control
            .apply(control_command(
                "trigger-retained-job",
                now,
                ControlActionV1::TriggerSchedule {
                    schedule_id: schedule_id.clone(),
                },
            ))
            .unwrap();
        let ControlResultV1::OccurrencePlanned { plan } = planned.result else {
            panic!("expected a planned occurrence")
        };
        control
            .apply(control_command(
                "claim-retained-job",
                now,
                ControlActionV1::ClaimOccurrence {
                    schedule_id: schedule_id.clone(),
                },
            ))
            .unwrap();
        let occurrence = ScheduledOccurrenceRefV1 {
            schedule_id,
            occurrence_id: plan.occurrence.id,
        };
        control
            .apply(control_command(
                "materialize-retained-job",
                now,
                ControlActionV1::MaterializeOccurrence {
                    occurrence: occurrence.clone(),
                    refresh: None,
                    last_complete: None,
                    repository_set_content: None,
                },
            ))
            .unwrap();
        control
            .apply(control_command(
                "attach-retained-job",
                now,
                ControlActionV1::AttachOccurrenceJob {
                    occurrence: occurrence.clone(),
                    job_id: protected_job.clone(),
                },
            ))
            .unwrap();

        let artifacts = BTreeMap::new();
        let failed_attempts = BTreeMap::new();
        let DurableOutcomeV1::RunsPruned(first) = apply_to_state(
            &mut memory,
            &mut control,
            &artifacts,
            &failed_attempts,
            &DurableCommandV1::PruneTerminalRunsBefore { cutoff },
        )
        .unwrap() else {
            panic!("expected run-retention outcome")
        };
        assert_eq!(first.jobs, 1);
        assert!(memory.job(&protected_job).is_some());
        assert!(memory.job(&orphan_job).is_none());

        control
            .apply(control_command(
                "finish-retained-job",
                now + chrono::TimeDelta::seconds(1),
                ControlActionV1::FinishOccurrence {
                    occurrence,
                    terminal_state: OccurrenceStateV1::Completed,
                },
            ))
            .unwrap();
        control
            .apply(control_command(
                "prune-retained-job",
                cutoff,
                ControlActionV1::PruneBefore { cutoff },
            ))
            .unwrap();
        let DurableOutcomeV1::RunsPruned(second) = apply_to_state(
            &mut memory,
            &mut control,
            &artifacts,
            &failed_attempts,
            &DurableCommandV1::PruneTerminalRunsBefore { cutoff },
        )
        .unwrap() else {
            panic!("expected run-retention outcome")
        };
        assert_eq!(second.jobs, 1);
        assert!(memory.job(&protected_job).is_none());
    }

    #[tokio::test]
    async fn replays_encrypted_journal_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let now = Utc::now();

        let store = TursoCoordinatorStore::open(&database, key).await.unwrap();
        assert!(matches!(
            store.apply(submit("job-1", now)).await.unwrap(),
            DurableOutcomeV1::Submitted(SubmitOutcome::Created(_))
        ));
        assert_eq!(store.events().await.unwrap().len(), 1);
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reopened
                .job(JobId("job-1".to_owned()))
                .await
                .unwrap()
                .unwrap()
                .created_at,
            now
        );
    }

    #[tokio::test]
    async fn control_command_is_idempotent_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let command = register_repository_set("register-acme-repo", "acme/repo", Utc::now());

        let store = TursoCoordinatorStore::open(&database_path, key)
            .await
            .unwrap();
        let first = store.apply_control(command.clone()).await.unwrap();
        let duplicate = store.apply_control(command).await.unwrap();
        assert_eq!(duplicate, first);
        assert_eq!(store.control_snapshot().await.unwrap().generation, 1);
        assert_eq!(store.compact().await.unwrap().commands_compacted, 1);
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database_path,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let snapshot = reopened.control_snapshot().await.unwrap();
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.repository_sets.len(), 1);
        assert_eq!(snapshot.processed_commands.len(), 1);
    }

    #[tokio::test]
    async fn control_snapshot_replays_journal_tail() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let now = Utc::now();

        let store = TursoCoordinatorStore::open(&database_path, key)
            .await
            .unwrap();
        store
            .apply_control(register_repository_set("register-first", "acme/first", now))
            .await
            .unwrap();
        store.compact().await.unwrap();
        store
            .apply_control(register_repository_set(
                "register-second",
                "acme/second",
                now + chrono::TimeDelta::seconds(1),
            ))
            .await
            .unwrap();
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database_path,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let snapshot = reopened.control_snapshot().await.unwrap();
        assert_eq!(snapshot.generation, 2);
        assert_eq!(snapshot.repository_sets.len(), 2);
        assert_eq!(snapshot.processed_commands.len(), 2);
    }

    #[test]
    fn snapshot_without_control_field_decodes_as_empty_control_state() {
        let snapshot = CoordinatorSnapshotV1 {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            command_count: 0,
            state: InMemoryStateStore::default().snapshot(),
            artifacts: Vec::new(),
            failed_attempt_projections: Vec::new(),
            control: Some(ControlState::default().snapshot()),
        };
        let mut encoded = serde_json::to_value(snapshot).unwrap();
        encoded.as_object_mut().unwrap().remove("control");

        let decoded: CoordinatorSnapshotV1 = serde_json::from_value(encoded).unwrap();
        assert!(decoded.control.is_none());
    }

    #[tokio::test]
    async fn compaction_replays_snapshot_then_journal_tail() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let now = Utc::now();

        let store = TursoCoordinatorStore::open(&database_path, key)
            .await
            .unwrap();
        store.apply(submit("compact-tail", now)).await.unwrap();
        let compacted = store.compact().await.unwrap();
        assert_eq!(compacted.commands_compacted, 1);
        assert!(compacted.watermark_sequence > 0);
        store
            .apply(DurableCommandV1::StartJob {
                job_id: JobId("compact-tail".to_owned()),
                now: now + chrono::TimeDelta::seconds(1),
            })
            .await
            .unwrap();
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let database = turso::Builder::new_local(database_path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM coordinator_snapshot").await,
            1
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM coordinator_journal").await,
            1
        );
        drop(connection);
        drop(database);

        let reopened = TursoCoordinatorStore::open(
            &database_path,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let job = reopened
            .job(JobId("compact-tail".to_owned()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(job.state, ScanJobStateV1::Running);
        assert_eq!(reopened.events().await.unwrap().len(), 2);
        assert_eq!(reopened.compact().await.unwrap().commands_compacted, 1);
        drop(reopened);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let database = turso::Builder::new_local(database_path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM coordinator_journal").await,
            0
        );
    }

    #[tokio::test]
    async fn pruned_event_state_survives_snapshot_and_tail_replay() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let old = Utc::now() - chrono::TimeDelta::days(400);
        let cutoff = Utc::now() - chrono::TimeDelta::days(365);
        let store = TursoCoordinatorStore::open(&database_path, key)
            .await
            .unwrap();
        store.apply(submit("terminal-old", old)).await.unwrap();
        store
            .apply(DurableCommandV1::StartJob {
                job_id: JobId("terminal-old".to_owned()),
                now: old + chrono::TimeDelta::seconds(1),
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::FinalizeJob {
                job_id: JobId("terminal-old".to_owned()),
                partial_reasons: BTreeSet::new(),
                now: old + chrono::TimeDelta::seconds(2),
            })
            .await
            .unwrap();
        store.apply(submit("active-old", old)).await.unwrap();
        assert_eq!(store.events().await.unwrap().len(), 4);
        assert_eq!(
            store
                .apply(DurableCommandV1::PruneEventsBefore { cutoff })
                .await
                .unwrap(),
            DurableOutcomeV1::EventsPruned(3)
        );
        assert_eq!(store.events().await.unwrap().len(), 1);
        store.compact().await.unwrap();
        store
            .apply(DurableCommandV1::StartJob {
                job_id: JobId("active-old".to_owned()),
                now: Utc::now(),
            })
            .await
            .unwrap();
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let reopened = TursoCoordinatorStore::open(
            &database_path,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let events = reopened.events().await.unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.job_id.0 == "active-old"));
    }

    #[tokio::test]
    async fn corrupted_snapshot_fails_closed_after_compaction() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let store = TursoCoordinatorStore::open(&database_path, key)
            .await
            .unwrap();
        store.apply(submit("corrupt", Utc::now())).await.unwrap();
        store.compact().await.unwrap();
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let database = turso::Builder::new_local(database_path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute(
                "UPDATE coordinator_snapshot SET payload = ?1 WHERE snapshot_id = 1",
                turso::params![vec![0_u8; 32]],
            )
            .await
            .unwrap();
        drop(connection);
        drop(database);

        let error = TursoCoordinatorStore::open(
            &database_path,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("snapshot")
                || error.to_string().contains("application envelope")
        );
    }

    #[tokio::test]
    async fn failed_compaction_rolls_back_snapshot_and_keeps_journal() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("coordinator.db");
        let database = turso::Builder::new_local(database_path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        migrate(&connection).await.unwrap();
        let key = EnvelopeKey::generate("test-key");
        let mut memory = InMemoryStateStore::default();
        let mut control = ControlState::default();
        let mut artifacts = BTreeMap::new();
        let mut failed_attempt_projections = BTreeMap::new();
        let mut reuse_index = ReuseIndex::new();
        let mut journal = JournalState {
            total_commands: 0,
            watermark_sequence: 0,
            tail_commands: 0,
            tail_bytes: 0,
        };
        apply_and_persist(
            &connection,
            &key,
            &mut memory,
            &mut control,
            &mut artifacts,
            &mut failed_attempt_projections,
            &mut reuse_index,
            &mut journal,
            &submit("rollback", Utc::now()),
        )
        .await
        .unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_journal_prune BEFORE DELETE ON coordinator_journal \
                 BEGIN SELECT RAISE(ABORT, 'injected prune failure'); END;",
            )
            .await
            .unwrap();

        assert!(
            compact_state(
                &connection,
                &key,
                &memory,
                &control,
                &artifacts,
                &failed_attempt_projections,
                &mut journal,
            )
            .await
            .is_err()
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM coordinator_snapshot").await,
            0
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM coordinator_journal").await,
            1
        );
        let replayed = replay(&connection, &key).await.unwrap();
        assert!(replayed.memory.job(&JobId("rollback".to_owned())).is_some());
    }

    #[test]
    fn automatic_compaction_is_bounded_by_commands_or_bytes() {
        let journal = |tail_commands, tail_bytes| JournalState {
            total_commands: tail_commands,
            watermark_sequence: tail_commands,
            tail_commands,
            tail_bytes,
        };
        assert!(!journal(COMPACTION_COMMAND_THRESHOLD - 1, 0).should_compact());
        assert!(journal(COMPACTION_COMMAND_THRESHOLD, 0).should_compact());
        assert!(journal(1, COMPACTION_BYTE_THRESHOLD).should_compact());
    }

    async fn scalar(connection: &turso::Connection, query: &str) -> i64 {
        let mut rows = connection.query(query, ()).await.unwrap();
        rows.next().await.unwrap().unwrap().get(0).unwrap()
    }

    #[tokio::test]
    async fn rejects_a_second_database_owner() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        EnvelopeKey::generate("test-key")
            .persist_new(&key_path)
            .unwrap();
        let store = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let error = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("already owned"));

        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        TursoCoordinatorStore::open(&database, EnvelopeKey::load(&key_path, "test-key").unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn persists_agent_enrollment_and_revocation() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let enrolled_at = Utc::now();
        let record = AgentRecordV1 {
            agent_id: "worker-1".to_owned(),
            certificate_sha256: "ab".repeat(32),
            enrolled_at,
            revoked_at: None,
            authorization: AgentAuthorizationV1 {
                private_credential_profiles: BTreeSet::from(["production".to_owned()]),
            },
        };

        let store = TursoCoordinatorStore::open(&database, key).await.unwrap();
        store.register_agent(record.clone()).await.unwrap();
        assert_eq!(store.agent("worker-1").await.unwrap(), Some(record));
        let revoked_at = enrolled_at + chrono::TimeDelta::seconds(1);
        store.revoke_agent("worker-1", revoked_at).await.unwrap();
        assert_eq!(
            store.agent("worker-1").await.unwrap().unwrap().revoked_at,
            Some(revoked_at)
        );

        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reopened
                .agent("worker-1")
                .await
                .unwrap()
                .unwrap()
                .revoked_at,
            Some(revoked_at)
        );
    }

    #[tokio::test]
    async fn atomically_journals_artifact_metadata_and_completes_job() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate("test-key");
        key.persist_new(&key_path).unwrap();
        let now = Utc::now();
        let job_id = JobId("job-artifact".to_owned());
        let task_id = TaskId("task-artifact".to_owned());
        let digest = Sha256Digest::parse("cd".repeat(32)).unwrap();
        let result = ArtifactRefV1 {
            digest: digest.clone(),
            media_type: "application/vnd.crate-dependent-repos.evidence.v1+json".to_owned(),
            stored_bytes: 12,
        };
        let reuse_fingerprint = ReuseFingerprintV1 {
            repository_id: "42".to_owned(),
            tree_sha: "tree".to_owned(),
            analyzer_version: "cargo-repository-v1".to_owned(),
            bounds_hash: Sha256Digest::parse("ab".repeat(32)).unwrap(),
            target_hash: Sha256Digest::parse("bc".repeat(32)).unwrap(),
            evidence_profile_hash: Sha256Digest::parse("de".repeat(32)).unwrap(),
        };
        let metadata = CacheMetadataV1 {
            schema_version: SCHEMA_VERSION_V1,
            key: CacheKeyV1 {
                namespace: CacheNamespaceV1::Public,
                digest,
            },
            content_kind: CacheContentKindV1::DerivedEvidence,
            content_length: 12,
            github_blob_sha: None,
            protection: CacheProtectionV1::EnvelopeEncrypted {
                algorithm: "AES-256-GCM".to_owned(),
                wrapping_key_id: "test-key".to_owned(),
            },
            completeness: EvidenceCompletenessV1::Complete,
            reuse_fingerprint: Some(reuse_fingerprint.clone()),
            created_at: now,
            last_accessed_at: now,
            retain_until: now + chrono::TimeDelta::days(365),
            reference_count: 0,
        };
        let artifact = ArtifactRecordV1 {
            job_id: job_id.clone(),
            task_id: task_id.clone(),
            metadata,
            inventory_projection: InventoryProjectionStateV1::Pending,
        };
        let mut legacy_artifact = serde_json::to_value(&artifact).unwrap();
        legacy_artifact
            .as_object_mut()
            .unwrap()
            .remove("inventory_projection");
        assert_eq!(
            serde_json::from_value::<ArtifactRecordV1>(legacy_artifact)
                .unwrap()
                .inventory_projection,
            InventoryProjectionStateV1::LegacyUnknown
        );

        let store = TursoCoordinatorStore::open(&database, key).await.unwrap();
        store.apply(submit(&job_id.0, now)).await.unwrap();
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
                agent_id: "worker-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                lease_seconds: 120,
                now,
            })
            .await
            .unwrap();
        store
            .apply(DurableCommandV1::CompleteTaskWithArtifact {
                task_id: task_id.clone(),
                agent_id: "worker-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                result: result.clone(),
                artifact: Box::new(artifact.clone()),
                usage: TaskUsageV1::default(),
                now,
            })
            .await
            .unwrap();

        assert_eq!(
            store.artifact(task_id.clone()).await.unwrap(),
            Some(artifact.clone())
        );
        assert_eq!(
            store.pending_artifacts_page(None, 1).await.unwrap(),
            vec![artifact.clone()]
        );
        assert_eq!(
            store
                .reusable_artifact(CacheNamespaceV1::Public, reuse_fingerprint.clone(), now,)
                .await
                .unwrap(),
            Some(artifact.clone())
        );
        assert!(
            store
                .reusable_artifact(
                    CacheNamespaceV1::Private {
                        principal_id: "other".to_owned(),
                    },
                    reuse_fingerprint.clone(),
                    now,
                )
                .await
                .unwrap()
                .is_none()
        );
        let job = store.job(job_id.clone()).await.unwrap().unwrap();
        assert_eq!(job.state, ScanJobStateV1::Completed);
        assert_eq!(job.quota_usage.artifact_bytes, 12);
        assert_eq!(
            store.task(task_id.clone()).await.unwrap().unwrap().result,
            Some(result)
        );
        let wrong_digest = Sha256Digest::parse("ef".repeat(32)).unwrap();
        assert!(
            store
                .apply(DurableCommandV1::MarkArtifactProjected {
                    task_id: task_id.clone(),
                    artifact_digest: wrong_digest,
                    now,
                })
                .await
                .is_err()
        );
        assert_eq!(
            store
                .artifact(task_id.clone())
                .await
                .unwrap()
                .unwrap()
                .inventory_projection,
            InventoryProjectionStateV1::Pending
        );
        let projected_at = now + chrono::TimeDelta::seconds(1);
        assert_eq!(
            store
                .apply(DurableCommandV1::MarkArtifactProjected {
                    task_id: task_id.clone(),
                    artifact_digest: artifact.metadata.key.digest.clone(),
                    now: projected_at,
                })
                .await
                .unwrap(),
            DurableOutcomeV1::ArtifactProjection(ArtifactProjectionOutcomeV1::Marked)
        );
        assert_eq!(
            store
                .apply(DurableCommandV1::MarkArtifactProjected {
                    task_id: task_id.clone(),
                    artifact_digest: artifact.metadata.key.digest.clone(),
                    now: projected_at + chrono::TimeDelta::seconds(1),
                })
                .await
                .unwrap(),
            DurableOutcomeV1::ArtifactProjection(ArtifactProjectionOutcomeV1::AlreadyProjected)
        );
        assert!(
            store
                .pending_artifacts_page(None, 1)
                .await
                .unwrap()
                .is_empty()
        );

        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            reopened
                .artifact(task_id.clone())
                .await
                .unwrap()
                .unwrap()
                .inventory_projection,
            InventoryProjectionStateV1::Projected { at: projected_at }
        );
        assert!(
            reopened
                .reusable_artifact(CacheNamespaceV1::Public, reuse_fingerprint.clone(), now,)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            reopened
                .reusable_artifact(
                    CacheNamespaceV1::Public,
                    reuse_fingerprint,
                    now + chrono::TimeDelta::days(365),
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reopened.job(job_id.clone()).await.unwrap().unwrap().state,
            ScanJobStateV1::Completed
        );
        let retention_page = reopened
            .expired_artifacts_page(now + chrono::TimeDelta::days(366), 1)
            .await
            .unwrap();
        assert_eq!(retention_page.total_candidates, 1);
        let mut projected_artifact = artifact.clone();
        projected_artifact.inventory_projection =
            InventoryProjectionStateV1::Projected { at: projected_at };
        assert_eq!(retention_page.candidates, vec![projected_artifact]);
        assert!(
            retention_page
                .removable_blob_keys
                .contains(&artifact.metadata.key)
        );
        assert_eq!(
            reopened
                .apply(DurableCommandV1::PruneTerminalRunsBefore {
                    cutoff: now + chrono::TimeDelta::days(365),
                })
                .await
                .unwrap(),
            DurableOutcomeV1::RunsPruned(OperationalRetentionSummaryV1::default())
        );
        reopened
            .apply(DurableCommandV1::RemoveExpiredArtifact {
                task_id: task_id.clone(),
                now: now + chrono::TimeDelta::days(366),
            })
            .await
            .unwrap();
        assert!(reopened.artifact(task_id.clone()).await.unwrap().is_none());
        let DurableOutcomeV1::RunsPruned(summary) = reopened
            .apply(DurableCommandV1::PruneTerminalRunsBefore {
                cutoff: now + chrono::TimeDelta::days(365),
            })
            .await
            .unwrap()
        else {
            panic!("unexpected retention outcome")
        };
        assert_eq!(summary.jobs, 1);
        assert_eq!(summary.tasks, 1);
        reopened.compact().await.unwrap();

        drop(reopened);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let collected = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert!(collected.artifact(task_id).await.unwrap().is_none());
        assert!(collected.job(job_id).await.unwrap().is_none());
    }
}
