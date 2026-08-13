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

use crate::secure_cache::{EnvelopeKey, sha256_hex};

use super::{
    AgentAuthorizationV1, ArtifactRefV1, CacheCatalog, CacheContentKindV1, CacheKeyV1,
    CacheMetadataV1, CacheNamespaceV1, CacheProtectionV1, InMemoryStateStore, JobEventV1, JobId,
    NewRepositoryTaskV1, PermitDecision, PermitId, ProviderKeyV1, ProviderOutcomeClassV1,
    ProviderPolicyV1, QuotaResourceV1, RateLimitObservationV1, RepositoryScopeV1,
    RepositoryTaskStateV1, RepositoryTaskV1, ReservationId, ReservationOutcome, ReuseFingerprintV1,
    ScanJobV1, StateStore as _, StoreError, SubmitJobV1, SubmitOutcome, TaskFailureV1, TaskId,
    TaskUsageV1,
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
}

#[derive(Debug)]
struct LoadedState {
    memory: InMemoryStateStore,
    artifacts: BTreeMap<TaskId, ArtifactRecordV1>,
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
    HeartbeatTask {
        task_id: TaskId,
        agent_id: String,
        lease_id: String,
        lease_seconds: u64,
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
    Submitted(SubmitOutcome),
    Task(Option<RepositoryTaskV1>),
    Tasks(Vec<TaskId>),
    Reservation(ReservationOutcome),
    Permit(PermitDecision),
    QuotaExceeded(QuotaResourceV1),
    EventsPruned(usize),
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
    Artifacts {
        response: oneshot::Sender<Vec<ArtifactRecordV1>>,
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
            loaded.artifacts,
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

    pub async fn artifacts(&self) -> Result<Vec<ArtifactRecordV1>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(ActorRequest::Artifacts { response })
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
    mut artifacts: BTreeMap<TaskId, ArtifactRecordV1>,
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
                    &mut artifacts,
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
                    compact_state(&connection, &key, &memory, &artifacts, &mut journal).await?;
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
                let result = compact_state(&connection, &key, &memory, &artifacts, &mut journal)
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

async fn apply_and_persist(
    connection: &turso::Connection,
    key: &EnvelopeKey,
    memory: &mut InMemoryStateStore,
    artifacts: &mut BTreeMap<TaskId, ArtifactRecordV1>,
    reuse_index: &mut ReuseIndex,
    journal: &mut JournalState,
    command: &DurableCommandV1,
) -> Result<DurableOutcomeV1> {
    validate_artifact_command(memory, artifacts, command)?;
    let outcome = apply_to_memory(memory, command)?;
    if matches!(
        outcome,
        DurableOutcomeV1::Submitted(SubmitOutcome::Existing(_))
            | DurableOutcomeV1::Reservation(ReservationOutcome::AlreadyReserved)
            | DurableOutcomeV1::EventsPruned(0)
    ) {
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
            *artifacts = restored.artifacts;
            *reuse_index = restored.reuse_index;
            *journal = restored.journal;
            return Err(error).context("persisting coordinator command");
        }
    };
    update_artifact_index(artifacts, reuse_index, command, &outcome);
    journal.total_commands = journal.total_commands.saturating_add(1);
    journal.tail_commands = journal.tail_commands.saturating_add(1);
    journal.tail_bytes = journal.tail_bytes.saturating_add(appended.stored_bytes);
    journal.watermark_sequence = appended.sequence;
    if journal.should_compact()
        && let Err(error) = compact_state(connection, key, memory, artifacts, journal).await
    {
        // The command is already committed. Reporting failure would invite an
        // ambiguous retry, so retain the tail and retry compaction later.
        tracing::warn!(%error, "automatic coordinator journal compaction failed");
    }
    Ok(outcome)
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
    let (mut memory, mut artifacts, snapshot_watermark, snapshot_commands) =
        load_snapshot(connection, key).await?.unwrap_or_default();
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
        let outcome = apply_to_memory(&mut memory, &command)
            .with_context(|| format!("replaying journal record {record_id}"))?;
        update_artifact_index(&mut artifacts, &mut reuse_index, &command, &outcome);
        journal.total_commands = journal.total_commands.saturating_add(1);
        journal.tail_commands = journal.tail_commands.saturating_add(1);
        journal.tail_bytes = journal.tail_bytes.saturating_add(payload.len() as u64);
        journal.watermark_sequence = sequence;
    }
    Ok(LoadedState {
        memory,
        artifacts,
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
        BTreeMap<TaskId, ArtifactRecordV1>,
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
    Ok(Some((memory, artifacts, watermark, snapshot.command_count)))
}

async fn compact_state(
    connection: &turso::Connection,
    key: &EnvelopeKey,
    memory: &InMemoryStateStore,
    artifacts: &BTreeMap<TaskId, ArtifactRecordV1>,
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
        DurableCommandV1::PauseJob { job_id, now } => {
            memory.pause_job(job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::ResumeJob { job_id, now } => {
            memory.resume_job(job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::CancelJob { job_id, now } => {
            memory.cancel_job(job_id, *now)?;
            DurableOutcomeV1::Applied
        }
        DurableCommandV1::FinalizeJob {
            job_id,
            partial_reasons,
            now,
        } => {
            memory.finalize_job(job_id, partial_reasons.clone(), *now)?;
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
            Err(StoreError::QuotaExceeded(resource)) => DurableOutcomeV1::QuotaExceeded(resource),
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
    ensure!(
        !tasks.is_empty(),
        "a submitted job must contain a repository task"
    );
    ensure!(
        tasks.len() as u64 <= request.spec.bounds.repository_limit,
        "repository task count exceeds the scan bound"
    );
    let mut task_ids = BTreeSet::new();
    let mut repositories = BTreeSet::new();
    for task in tasks {
        ensure!(task.job_id == request.job_id, "task job ID mismatch");
        ensure!(
            !task.task_id.0.trim().is_empty() && !task.repository_id.trim().is_empty(),
            "task identifiers must not be empty"
        );
        ensure!(task_ids.insert(task.task_id.clone()), "duplicate task ID");
        ensure!(
            repositories.insert(task.repository_id.clone()),
            "duplicate repository task"
        );
    }

    match memory.submit_job(request.clone())? {
        SubmitOutcome::Existing(job_id) => {
            ensure!(
                memory.repository_ids_for_job(&job_id) == repositories,
                "idempotency key is already associated with a different repository set"
            );
            Ok(DurableOutcomeV1::Submitted(SubmitOutcome::Existing(job_id)))
        }
        SubmitOutcome::Created(job_id) => {
            let reservation_id = ReservationId(format!("repositories:{}", job_id.0));
            memory.reserve_quota(
                reservation_id.clone(),
                &job_id,
                QuotaResourceV1::Repositories,
                tasks.len() as u64,
                now,
            )?;
            memory.reconcile_quota(&reservation_id, tasks.len() as u64, now)?;
            for task in tasks {
                memory.enqueue_task(task.clone())?;
            }
            memory.start_job(&job_id, now)?;
            Ok(DurableOutcomeV1::Submitted(SubmitOutcome::Created(job_id)))
        }
    }
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
        CacheKeyV1, EvidenceCompletenessV1, RepositoryScopeV1, SCHEMA_VERSION_V1, ScanBoundsV1,
        ScanJobStateV1, ScanSpecV1, ScanTargetV1, Sha256Digest,
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

    fn submit(job: &str, now: DateTime<Utc>) -> DurableCommandV1 {
        DurableCommandV1::SubmitJob {
            request: submit_request(job, now),
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
        let mut artifacts = BTreeMap::new();
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
            &mut artifacts,
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
            compact_state(&connection, &key, &memory, &artifacts, &mut journal)
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
        };

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

        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reopened = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert!(reopened.artifact(task_id.clone()).await.unwrap().is_some());
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
            reopened.job(job_id).await.unwrap().unwrap().state,
            ScanJobStateV1::Completed
        );
        reopened
            .apply(DurableCommandV1::RemoveExpiredArtifact {
                task_id: task_id.clone(),
                now: now + chrono::TimeDelta::days(366),
            })
            .await
            .unwrap();
        assert!(reopened.artifact(task_id.clone()).await.unwrap().is_none());

        drop(reopened);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let collected = TursoCoordinatorStore::open(
            &database,
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        assert!(collected.artifact(task_id).await.unwrap().is_none());
    }
}
