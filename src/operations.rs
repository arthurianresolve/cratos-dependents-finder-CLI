//! Self-hosted coordinator, worker, job, and availability operations.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, BufWriter, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand, ValueEnum};
use futures::{StreamExt as _, stream};
use reqwest::{RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    advisory::DataSnapshotV1,
    cargo_evidence::PackageIdentityV1,
    coordinator::{
        AgentAuthorizationV1, AgentRecordV1, BackupManifestV1, JobEventKindV1, JobId,
        RepositoryScopeV1, RepositoryTaskStateV1, RepositoryTaskV1, RetentionPolicyV1,
        SCHEMA_VERSION_V1, ScanBoundsV1, ScanJobStateV1, ScanJobV1, ScanSpecV1, ScanTargetV1,
        TaskId, TursoCoordinatorStore,
    },
    coordinator_api::{
        CoordinatorServerConfig, EVIDENCE_MEDIA_TYPE_V1, JobEventPageV1, RepositoryTaskPageV1,
        SubmitScanRequestV1, SubmitScanResponseV1,
    },
    distributed::{AgentRunConfig, run_agent},
    evidence::{EvidenceBundleV1, LimitationV1, RepositoryEvidenceV1},
    explain::{
        EvidenceShardRecordV1, EvidenceShardV1, SHARDED_EXPORT_MANIFEST,
        SHARDED_EXPORT_SCHEMA_VERSION_V1, ShardedEvidenceManifestV1,
    },
    secure_cache::{EnvelopeKey, sha256_hex},
};

const ENVELOPE_KEY_ID: &str = "coordinator-journal-v1";
const MAX_REPOSITORIES_PER_JOB: u64 = 10_000;
const DEFAULT_PROVIDER_REQUEST_LIMIT: u64 = 250_000;
const DEFAULT_DOWNLOAD_BYTE_LIMIT: u64 = 50 * 1024 * 1024 * 1024;
const DEFAULT_ARTIFACT_BYTE_LIMIT: u64 = 25 * 1024 * 1024 * 1024;
const MAX_REPOSITORY_LIST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_API_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVIDENCE_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVIDENCE_EXPORT_BYTES: u64 = 128 * 1024 * 1024;
const EVIDENCE_EXPORT_CONCURRENCY: usize = 8;
const COORDINATOR_PAGE_SIZE: usize = 1_000;
const EVIDENCE_SHARD_TARGET_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Args)]
pub struct CoordinatorArgs {
    #[command(subcommand)]
    command: CoordinatorCommand,
}

#[derive(Debug, Subcommand)]
enum CoordinatorCommand {
    /// Initialize a non-overwriting coordinator state directory and local CA.
    Init(CoordinatorInitArgs),
    /// Serve the authenticated coordinator API as the sole database owner.
    Serve(CoordinatorServeArgs),
    /// Checkpoint and copy the embedded database with an integrity manifest.
    Backup(CoordinatorBackupArgs),
    /// Verify and restore a database backup without overwriting a destination.
    Restore(CoordinatorRestoreArgs),
}

#[derive(Debug, Args)]
struct CoordinatorInitArgs {
    /// New or empty coordinator state directory.
    #[arg(long)]
    directory: PathBuf,
    /// DNS name or IP address used by agents to reach the coordinator.
    #[arg(long)]
    server_name: String,
    /// Emit the deployment manifest as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CoordinatorServeArgs {
    /// Initialized coordinator state directory.
    #[arg(long)]
    directory: PathBuf,
    /// LAN address on which to accept mutual-TLS connections.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// Emit structured JSON logs.
    #[arg(long)]
    json_logs: bool,
    /// Raw repository-content retention in days.
    #[arg(long, default_value_t = 30, value_parser = parse_positive_u32)]
    raw_content_retention_days: u32,
    /// Derived evidence retention in days.
    #[arg(long, default_value_t = 365, value_parser = parse_positive_u32)]
    evidence_retention_days: u32,
}

#[derive(Debug, Args)]
struct CoordinatorBackupArgs {
    /// Initialized coordinator state directory.
    #[arg(long)]
    directory: PathBuf,
    /// New database backup path. Existing files are never overwritten.
    #[arg(long)]
    output: PathBuf,
    /// New JSON integrity-manifest path.
    #[arg(long)]
    manifest: PathBuf,
}

#[derive(Debug, Args)]
struct CoordinatorRestoreArgs {
    /// Database backup produced by `coordinator backup`.
    #[arg(long)]
    backup: PathBuf,
    /// JSON integrity manifest produced with the backup.
    #[arg(long)]
    manifest: PathBuf,
    /// New destination database path. Existing files are never overwritten.
    #[arg(long)]
    database: PathBuf,
}

#[derive(Debug, Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Issue and register a mutual-TLS worker identity.
    Enroll(AgentEnrollArgs),
    /// Revoke a registered worker identity.
    Revoke(AgentRevokeArgs),
    /// Lease and execute repository tasks for one durable job.
    Run(Box<AgentRunArgs>),
}

#[derive(Debug, Args)]
struct AgentEnrollArgs {
    /// Initialized coordinator state directory.
    #[arg(long)]
    directory: PathBuf,
    /// Stable worker identifier recorded in leases and audit events.
    #[arg(long)]
    agent_id: String,
    /// New directory that will receive the worker certificate, key, CA, and manifest.
    #[arg(long)]
    output: PathBuf,
    /// Private credential profile this worker may use. Repeat for multiple profiles.
    /// Without this option, the worker can process public jobs only.
    #[arg(long = "allow-credential-profile", value_name = "PROFILE")]
    private_credential_profiles: Vec<String>,
}

#[derive(Debug, Args)]
struct AgentRevokeArgs {
    /// Initialized coordinator state directory.
    #[arg(long)]
    directory: PathBuf,
    /// Enrolled worker identifier to revoke.
    agent_id: String,
}

#[derive(Debug, Args)]
struct AgentRunArgs {
    #[command(flatten)]
    connection: AgentConnectionArgs,
    /// Durable job from which this worker should lease tasks.
    #[arg(long)]
    job_id: String,
    /// Lease duration requested from the coordinator.
    #[arg(long, default_value_t = 120, value_parser = parse_lease_seconds)]
    lease_seconds: u64,
    /// Delay before polling again when no task is available.
    #[arg(long, default_value_t = 5, value_parser = parse_positive_u64)]
    idle_poll_seconds: u64,
    /// Exit after one lease attempt, including an empty attempt.
    #[arg(long)]
    once: bool,
    /// Directory for recoverable local copies of worker evidence artifacts.
    #[arg(long, default_value = "agent-artifacts")]
    artifact_directory: PathBuf,
    /// Maximum Cargo manifest or lockfile blob downloaded per repository.
    #[arg(long, default_value_t = 10 * 1024 * 1024, value_parser = parse_positive_u64)]
    max_file_bytes: u64,
    /// Emit structured JSON logs.
    #[arg(long)]
    json_logs: bool,
}

#[derive(Debug, Args)]
struct AgentConnectionArgs {
    /// HTTPS base URL of the coordinator.
    #[arg(long)]
    coordinator: Url,
    /// Coordinator certificate-authority PEM.
    #[arg(long)]
    ca: PathBuf,
    /// Worker client-certificate PEM.
    #[arg(long)]
    certificate: PathBuf,
    /// Worker client private-key PEM.
    #[arg(long)]
    private_key: PathBuf,
    /// Enrolled worker identifier matching the certificate.
    #[arg(long)]
    agent_id: String,
}

#[derive(Debug, Args)]
pub struct JobArgs {
    #[command(subcommand)]
    command: JobCommand,
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    /// Submit and start an idempotent bounded repository scan.
    Submit(JobSubmitArgs),
    /// Read the current durable status of a job.
    Status(JobReadArgs),
    /// Read the append-only event stream for a job.
    Events(JobReadArgs),
    /// Merge completed task artifacts into one deterministic evidence export.
    Export(JobExportArgs),
    /// Resume a paused, failed, or partial job.
    Resume(JobMutationArgs),
    /// Cancel a non-terminal job and its outstanding tasks.
    Cancel(JobMutationArgs),
}

#[derive(Clone, Debug, Args)]
struct OperatorConnectionArgs {
    /// HTTPS base URL of the coordinator.
    #[arg(long)]
    coordinator: Url,
    /// Coordinator certificate-authority PEM.
    #[arg(long)]
    ca: PathBuf,
    /// Operator client-certificate PEM.
    #[arg(long)]
    certificate: PathBuf,
    /// Operator client private-key PEM.
    #[arg(long)]
    private_key: PathBuf,
}

#[derive(Debug, Args)]
struct JobSubmitArgs {
    #[command(flatten)]
    connection: OperatorConnectionArgs,
    /// Exact Cargo crate name to analyze.
    #[arg(long)]
    crate_name: String,
    /// Exact Cargo package version whose resolution should be confirmed.
    #[arg(long)]
    version: semver::Version,
    /// JSON array or newline-delimited owner/name repository file.
    #[arg(long)]
    repositories: PathBuf,
    /// Stable retry key. By default, one is derived from the normalized request.
    #[arg(long)]
    idempotency_key: Option<String>,
    /// Caller-selected job ID. The coordinator generates a UUID by default.
    #[arg(long)]
    job_id: Option<String>,
    /// Credential-principal namespace required by all-visible scans.
    #[arg(long)]
    credential_profile: Option<String>,
    /// Maximum repositories admitted to the job.
    #[arg(long, default_value_t = MAX_REPOSITORIES_PER_JOB, value_parser = parse_repository_limit)]
    repository_limit: u64,
    /// Maximum provider requests admitted to the job.
    #[arg(long, default_value_t = DEFAULT_PROVIDER_REQUEST_LIMIT, value_parser = parse_positive_u64)]
    provider_request_limit: u64,
    /// Maximum downloaded bytes admitted to the job.
    #[arg(long, default_value_t = DEFAULT_DOWNLOAD_BYTE_LIMIT, value_parser = parse_positive_u64)]
    download_byte_limit: u64,
    /// Maximum persisted artifact bytes admitted to the job.
    #[arg(long, default_value_t = DEFAULT_ARTIFACT_BYTE_LIMIT, value_parser = parse_positive_u64)]
    artifact_byte_limit: u64,
    /// Emit the submission response as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct JobReadArgs {
    #[command(flatten)]
    connection: OperatorConnectionArgs,
    /// Durable job identifier.
    job_id: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct JobMutationArgs {
    #[command(flatten)]
    connection: OperatorConnectionArgs,
    /// Durable job identifier.
    job_id: String,
}

#[derive(Debug, Args)]
struct JobExportArgs {
    #[command(flatten)]
    connection: OperatorConnectionArgs,
    /// Durable job identifier.
    job_id: String,
    /// Evidence output representation.
    #[arg(long, value_enum, default_value_t = JobExportFormat::Json)]
    format: JobExportFormat,
    /// Output path, or '-' for stdout.
    #[arg(short, long)]
    output: PathBuf,
    /// Canonical TOML policy evaluated against the merged evidence bundle.
    #[arg(long, value_name = "TOML", requires = "policy_report")]
    policy: Option<PathBuf>,
    /// Pinned license, RustSec, and OSV snapshot applied before policy evaluation.
    #[arg(long, value_name = "JSON", requires = "policy")]
    data_snapshot: Option<PathBuf>,
    /// Deterministic JSON policy report. Required when --policy is supplied.
    #[arg(long, value_name = "JSON", requires = "policy")]
    policy_report: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum JobExportFormat {
    Json,
    Markdown,
    /// Bounded-memory directory containing NDJSON shards and manifest.json.
    Ndjson,
}

#[derive(Debug, Args)]
pub struct SlaArgs {
    #[command(subcommand)]
    command: SlaCommand,
}

#[derive(Debug, Subcommand)]
enum SlaCommand {
    /// Calculate availability from a versioned, non-overlapping observation ledger.
    Report(SlaReportArgs),
}

#[derive(Debug, Args)]
struct SlaReportArgs {
    /// Versioned JSON observation ledger.
    input: PathBuf,
    /// Availability objective as a percentage.
    #[arg(long, default_value_t = 99.5, value_parser = parse_percentage)]
    objective: f64,
    /// Emit machine-readable JSON instead of Markdown.
    #[arg(long)]
    json: bool,
    /// Output path, or '-' for stdout.
    #[arg(short, long, default_value = "-")]
    output: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlaObservationLedgerV1 {
    pub schema_version: u16,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    /// False when monitoring has gaps; the report result is then indeterminate.
    pub complete: bool,
    #[serde(default)]
    pub intervals: Vec<SlaIntervalV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlaIntervalV1 {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub classification: SlaIntervalClassV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaIntervalClassV1 {
    PlatformUnavailable,
    UpstreamProviderWait,
    UserLimit,
    QuotaWait,
    Cancelled,
}

#[derive(Clone, Debug, Serialize)]
pub struct SlaReportV1 {
    pub schema_version: u16,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub objective_percent: f64,
    pub observation_complete: bool,
    pub status: SlaStatusV1,
    pub availability_percent: Option<f64>,
    pub window_seconds: f64,
    pub eligible_seconds: f64,
    pub platform_unavailable_seconds: f64,
    pub excluded_upstream_provider_wait_seconds: f64,
    pub excluded_user_limit_seconds: f64,
    pub excluded_quota_wait_seconds: f64,
    pub excluded_cancelled_seconds: f64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaStatusV1 {
    Met,
    Missed,
    Indeterminate,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CoordinatorDeploymentV1 {
    schema_version: u16,
    created_at: DateTime<Utc>,
    server_name: String,
    database: String,
    envelope_key: String,
    pki_directory: String,
}

#[derive(Clone, Debug, Serialize)]
struct AgentEnrollmentV1 {
    schema_version: u16,
    enrolled_at: DateTime<Utc>,
    agent_id: String,
    certificate: String,
    private_key: String,
    ca_certificate: String,
    certificate_sha256: String,
    authorization: AgentAuthorizationV1,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    code: String,
    message: String,
}

struct OperatorClient {
    base: Url,
    client: reqwest::Client,
}

pub async fn run_coordinator(args: CoordinatorArgs) -> Result<()> {
    match args.command {
        CoordinatorCommand::Init(args) => initialize_coordinator(args).await,
        CoordinatorCommand::Serve(args) => serve_coordinator(args).await,
        CoordinatorCommand::Backup(args) => backup_coordinator(args).await,
        CoordinatorCommand::Restore(args) => restore_coordinator(args),
    }
}

pub async fn run_agent_command(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Enroll(args) => enroll_agent(args).await,
        AgentCommand::Revoke(args) => revoke_agent(args).await,
        AgentCommand::Run(args) => {
            let _telemetry = crate::telemetry::initialize(args.json_logs)?;
            let config = AgentRunConfig {
                coordinator: validate_coordinator_url(args.connection.coordinator)?,
                ca_certificate: args.connection.ca,
                client_certificate: args.connection.certificate,
                client_private_key: args.connection.private_key,
                agent_id: args.connection.agent_id,
                job_id: JobId(args.job_id),
                lease_seconds: args.lease_seconds,
                idle_poll: Duration::from_secs(args.idle_poll_seconds),
                once: args.once,
                artifact_directory: args.artifact_directory,
                max_file_bytes: args.max_file_bytes,
            };
            run_agent(config).await
        }
    }
}

pub async fn run_job(args: JobArgs, include_private: bool) -> Result<i32> {
    let exit_code = match args.command {
        JobCommand::Submit(args) => {
            submit_job(args, include_private).await?;
            0
        }
        JobCommand::Status(args) => {
            read_job(args).await?;
            0
        }
        JobCommand::Events(args) => {
            read_events(args).await?;
            0
        }
        JobCommand::Export(args) => export_job(args).await?,
        JobCommand::Resume(args) => {
            mutate_job(args, "resume").await?;
            0
        }
        JobCommand::Cancel(args) => {
            mutate_job(args, "cancel").await?;
            0
        }
    };
    Ok(exit_code)
}

pub fn run_sla(args: SlaArgs) -> Result<()> {
    match args.command {
        SlaCommand::Report(args) => {
            ensure!(
                args.output == Path::new("-") || !paths_conflict(&args.input, &args.output)?,
                "SLA --output must be different from the input ledger"
            );
            let input = fs::read_to_string(&args.input)
                .with_context(|| format!("reading SLA observations {}", args.input.display()))?;
            let ledger: SlaObservationLedgerV1 = serde_json::from_str(&input)
                .with_context(|| format!("parsing SLA observations {}", args.input.display()))?;
            let report = calculate_sla(&ledger, args.objective)?;
            if args.json {
                crate::output::write_json(&args.output, &report)
            } else {
                write_text(&args.output, &render_sla_markdown(&report))
            }
        }
    }
}

async fn initialize_coordinator(args: CoordinatorInitArgs) -> Result<()> {
    ensure_empty_or_missing_directory(&args.directory)?;
    fs::create_dir_all(&args.directory).with_context(|| {
        format!(
            "creating coordinator directory {}",
            args.directory.display()
        )
    })?;
    let paths = StatePaths::new(&args.directory);
    let pki_manifest = crate::pki::initialize(&paths.pki_directory, &args.server_name)?;
    let key = EnvelopeKey::generate(ENVELOPE_KEY_ID);
    key.persist_new(&paths.envelope_key)?;
    let store = TursoCoordinatorStore::open(&paths.database, key).await?;
    store
        .register_agent(AgentRecordV1 {
            agent_id: "operator".to_owned(),
            certificate_sha256: pki_manifest.operator_certificate_sha256,
            enrolled_at: Utc::now(),
            revoked_at: None,
            authorization: AgentAuthorizationV1::default(),
        })
        .await?;
    let manifest = CoordinatorDeploymentV1 {
        schema_version: 1,
        created_at: Utc::now(),
        server_name: args.server_name,
        database: paths.database.display().to_string(),
        envelope_key: paths.envelope_key.display().to_string(),
        pki_directory: paths.pki_directory.display().to_string(),
    };
    write_json_new(&paths.deployment_manifest, &manifest)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        println!("initialized coordinator at {}", args.directory.display());
        println!("server name: {}", manifest.server_name);
        println!(
            "operator certificate: {}",
            paths.operator_certificate.display()
        );
    }
    Ok(())
}

async fn serve_coordinator(args: CoordinatorServeArgs) -> Result<()> {
    let _telemetry = crate::telemetry::initialize(args.json_logs)?;
    let paths = StatePaths::new(&args.directory);
    require_initialized(&paths)?;
    let store = open_store(&paths).await?;
    crate::coordinator_api::serve(
        CoordinatorServerConfig {
            listen: args.listen,
            ca_certificate: paths.ca_certificate,
            server_certificate: paths.server_certificate,
            server_private_key: paths.server_private_key,
            artifact_cache_directory: paths.artifact_cache,
            envelope_key: paths.envelope_key,
            envelope_key_id: ENVELOPE_KEY_ID.to_owned(),
            retention_policy: RetentionPolicyV1 {
                raw_content_days: args.raw_content_retention_days,
                derived_evidence_days: args.evidence_retention_days,
            },
        },
        store,
        crate::telemetry::CoordinatorMetrics::new(),
    )
    .await
}

async fn backup_coordinator(args: CoordinatorBackupArgs) -> Result<()> {
    ensure!(
        !paths_conflict(&args.output, &args.manifest)?,
        "--output and --manifest must refer to different files"
    );
    ensure!(
        !args.manifest.exists(),
        "backup manifest {} already exists",
        args.manifest.display()
    );
    let paths = StatePaths::new(&args.directory);
    require_initialized(&paths)?;
    let store = open_store(&paths).await?;
    let manifest = store.backup(&args.output).await?;
    if let Err(error) = write_json_new(&args.manifest, &manifest) {
        bail!(
            "database backup {} was created, but writing manifest {} failed: {error:#}",
            args.output.display(),
            args.manifest.display()
        );
    }
    println!(
        "backed up {} bytes and {} commands to {}",
        manifest.database_bytes,
        manifest.journal_commands,
        args.output.display()
    );
    Ok(())
}

fn restore_coordinator(args: CoordinatorRestoreArgs) -> Result<()> {
    let input = fs::read_to_string(&args.manifest)
        .with_context(|| format!("reading backup manifest {}", args.manifest.display()))?;
    let manifest: BackupManifestV1 = serde_json::from_str(&input)
        .with_context(|| format!("parsing backup manifest {}", args.manifest.display()))?;
    TursoCoordinatorStore::restore(&args.backup, &manifest, &args.database)?;
    println!("restored verified database to {}", args.database.display());
    Ok(())
}

async fn enroll_agent(args: AgentEnrollArgs) -> Result<()> {
    let paths = StatePaths::new(&args.directory);
    require_initialized(&paths)?;
    ensure!(
        !paths_conflict(&args.output, &paths.pki_directory)?,
        "agent output must be separate from the coordinator PKI directory"
    );
    ensure!(
        !args.output.join("ca.pem").exists() && !args.output.join("manifest.json").exists(),
        "agent output contains a CA or manifest and will not be overwritten"
    );
    let authorization = AgentAuthorizationV1 {
        private_credential_profiles: args
            .private_credential_profiles
            .into_iter()
            .map(|profile| profile.trim().to_owned())
            .collect(),
    };
    authorization.validate()?;
    let identity = crate::pki::issue_agent(&paths.pki_directory, &args.agent_id, &args.output)?;
    copy_new(&paths.ca_certificate, &args.output.join("ca.pem"))?;
    let enrolled_at = Utc::now();
    let store = open_store(&paths).await?;
    store
        .register_agent(AgentRecordV1 {
            agent_id: identity.agent_id.clone(),
            certificate_sha256: identity.certificate_sha256.clone(),
            enrolled_at,
            revoked_at: None,
            authorization: authorization.clone(),
        })
        .await?;
    let manifest = AgentEnrollmentV1 {
        schema_version: 1,
        enrolled_at,
        agent_id: identity.agent_id,
        certificate: identity.certificate_path.display().to_string(),
        private_key: identity.private_key_path.display().to_string(),
        ca_certificate: args.output.join("ca.pem").display().to_string(),
        certificate_sha256: identity.certificate_sha256,
        authorization,
    };
    write_json_new(&args.output.join("manifest.json"), &manifest)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

async fn revoke_agent(args: AgentRevokeArgs) -> Result<()> {
    let paths = StatePaths::new(&args.directory);
    require_initialized(&paths)?;
    open_store(&paths)
        .await?
        .revoke_agent(&args.agent_id, Utc::now())
        .await?;
    println!("revoked agent {}", args.agent_id);
    Ok(())
}

async fn submit_job(args: JobSubmitArgs, include_private: bool) -> Result<()> {
    ensure!(
        !args.crate_name.trim().is_empty(),
        "--crate-name must not be empty"
    );
    let repositories = load_repositories(&args.repositories)?;
    ensure!(
        repositories.len() as u64 <= args.repository_limit,
        "repository file contains {} repositories, exceeding the configured limit {}",
        repositories.len(),
        args.repository_limit
    );
    let credential_profile_id = args
        .credential_profile
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if include_private {
        ensure!(
            credential_profile_id.is_some(),
            "--include-private requires --credential-profile for cache isolation"
        );
    } else {
        ensure!(
            credential_profile_id.is_none(),
            "--credential-profile is only valid with --include-private"
        );
    }
    let spec = ScanSpecV1 {
        schema_version: SCHEMA_VERSION_V1,
        target: ScanTargetV1 {
            crate_name: args.crate_name.trim().to_owned(),
            version_spec: format!("={}", args.version),
        },
        repository_scope: if include_private {
            RepositoryScopeV1::AllVisible
        } else {
            RepositoryScopeV1::PublicOnly
        },
        credential_profile_id,
        bounds: ScanBoundsV1 {
            repository_limit: args.repository_limit,
            provider_request_limit: args.provider_request_limit,
            download_byte_limit: args.download_byte_limit,
            artifact_byte_limit: args.artifact_byte_limit,
        },
        analyzer_versions: BTreeMap::from([(
            "crate-dependent-repos".to_owned(),
            env!("CARGO_PKG_VERSION").to_owned(),
        )]),
    };
    spec.validate()?;
    let idempotency_key = args.idempotency_key.unwrap_or_else(|| {
        let material = serde_json::to_vec(&(&spec, &repositories))
            .expect("serializing validated scan request cannot fail");
        format!("sha256:{}", sha256_hex(&material))
    });
    ensure!(
        !idempotency_key.trim().is_empty(),
        "--idempotency-key must not be empty"
    );
    let request = SubmitScanRequestV1 {
        idempotency_key,
        job_id: args.job_id.map(JobId),
        spec,
        repositories,
    };
    crate::coordinator_api::validate_submit_request(&request)?;
    let client = OperatorClient::new(args.connection)?;
    let response: SubmitScanResponseV1 =
        client.json(client.post("v1/jobs")?.json(&request)).await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "job {} {}",
            response.job_id.0,
            if response.created {
                "created"
            } else {
                "already exists"
            }
        );
    }
    Ok(())
}

async fn read_job(args: JobReadArgs) -> Result<()> {
    let client = OperatorClient::new(args.connection)?;
    let job: ScanJobV1 = client
        .json(client.get(&format!("v1/jobs/{}", path_segment(&args.job_id)?))?)
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&job)?);
    } else {
        println!("# Job `{}`", job.id.0);
        println!();
        println!("- State: `{:?}`", job.state);
        println!("- Created: {}", job.created_at.to_rfc3339());
        println!("- Updated: {}", job.updated_at.to_rfc3339());
        println!(
            "- Tasks: {} total, {} pending, {} leased, {} succeeded, {} failed",
            job.progress.tasks_total,
            job.progress.tasks_pending,
            job.progress.tasks_leased,
            job.progress.tasks_succeeded,
            job.progress.tasks_failed
        );
        println!("- Partial reasons: {}", display_set(&job.partial_reasons));
    }
    Ok(())
}

async fn read_events(args: JobReadArgs) -> Result<()> {
    let client = OperatorClient::new(args.connection)?;
    if args.json {
        let mut first = true;
        print!("[");
        let mut after = None;
        loop {
            let page = client.event_page(&args.job_id, after).await?;
            for event in page.items {
                if !first {
                    print!(",");
                }
                print!("{}", serde_json::to_string(&event)?);
                first = false;
            }
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        println!("]");
    } else {
        println!("| Sequence | Time | Event | Task |");
        println!("|---:|---|---|---|");
        let mut after = None;
        loop {
            let page = client.event_page(&args.job_id, after).await?;
            for event in page.items {
                println!(
                    "| {} | {} | {} | {} |",
                    event.sequence,
                    event.occurred_at.to_rfc3339(),
                    event_kind(&event.kind),
                    event.task_id.map_or_else(|| "-".to_owned(), |id| id.0)
                );
            }
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
    }
    Ok(())
}

async fn export_job(args: JobExportArgs) -> Result<i32> {
    let JobExportArgs {
        connection,
        job_id,
        format,
        output,
        policy,
        data_snapshot,
        policy_report,
    } = args;
    ensure!(
        policy.is_some() == policy_report.is_some(),
        "--policy and --policy-report must be supplied together"
    );
    ensure!(
        data_snapshot.is_none() || policy.is_some(),
        "--data-snapshot requires --policy"
    );
    ensure!(
        policy.is_none() || format != JobExportFormat::Ndjson,
        "policy evaluation requires a merged JSON or Markdown export"
    );
    if output != Path::new("-") {
        for credential in [
            &connection.ca,
            &connection.certificate,
            &connection.private_key,
        ] {
            ensure!(
                !paths_conflict(&output, credential)?,
                "job export output must not overwrite a credential file"
            );
        }
    }
    for input in policy.iter().chain(data_snapshot.iter()) {
        ensure!(
            output == Path::new("-") || !paths_conflict(&output, input)?,
            "job export output must not overwrite a policy input"
        );
    }
    if let Some(report_path) = &policy_report {
        ensure!(
            !paths_conflict(&output, report_path)?,
            "evidence and policy report outputs must refer to different paths"
        );
        for input in policy.iter().chain(data_snapshot.iter()).chain([
            &connection.ca,
            &connection.certificate,
            &connection.private_key,
        ]) {
            ensure!(
                report_path == Path::new("-") || !paths_conflict(report_path, input)?,
                "policy report output must not overwrite an input or credential file"
            );
        }
    }

    let policy = policy.as_deref().map(load_policy_document).transpose()?;
    let data_snapshot = data_snapshot
        .as_deref()
        .map(DataSnapshotV1::load)
        .transpose()?;

    let job_path = path_segment(&job_id)?;
    let client = OperatorClient::new(connection)?;
    let job: ScanJobV1 = client
        .json(client.get(&format!("v1/jobs/{job_path}"))?)
        .await?;
    ensure!(job.id.0 == job_id, "coordinator returned a different job");
    ensure!(
        job_is_exportable(&job),
        "job is still active and has no partial result to export"
    );

    if format == JobExportFormat::Ndjson {
        ensure!(
            output != Path::new("-"),
            "NDJSON export requires a new output directory"
        );
        export_job_sharded(&client, &job, &output).await?;
        return Ok(0);
    }

    let tasks = client.succeeded_tasks(&job.id).await?;
    ensure!(
        tasks.len() as u64 == job.progress.tasks_succeeded,
        "job task enumeration does not match the durable success count"
    );
    let requests = tasks.into_iter().map(|task| {
        let client = &client;
        async move {
            let bytes = client.task_artifact(&task.id).await?;
            Ok::<_, anyhow::Error>((task, bytes))
        }
    });
    let mut responses = stream::iter(requests).buffer_unordered(EVIDENCE_EXPORT_CONCURRENCY);
    let mut total_bytes = 0_u64;
    let mut bundles = Vec::new();
    let mut missing = BTreeSet::new();
    while let Some(response) = responses.next().await {
        let (task, bytes) = response?;
        let Some(bytes) = bytes else {
            missing.insert(task.id);
            continue;
        };
        validate_downloaded_artifact(&task, &bytes)?;
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("evidence export byte count overflowed"))?;
        ensure!(
            total_bytes <= MAX_EVIDENCE_EXPORT_BYTES,
            "evidence artifacts exceed the {MAX_EVIDENCE_EXPORT_BYTES}-byte aggregate limit"
        );
        let bundle: EvidenceBundleV1 = serde_json::from_slice(&bytes)
            .with_context(|| format!("decoding evidence artifact for task {}", task.id.0))?;
        ensure!(
            bundle.schema_is_supported(),
            "task {} uses unsupported evidence schema {}",
            task.id.0,
            bundle.schema_version
        );
        bundles.push((task.id, bundle.normalized()));
    }

    let (bundle, report) = prepare_policy_export(
        merge_job_evidence(&job, bundles, &missing)?,
        data_snapshot.as_ref(),
        policy.as_ref(),
        job.updated_at,
    );
    let rendered = match format {
        JobExportFormat::Json => serde_json::to_vec(&bundle)?,
        JobExportFormat::Markdown => crate::explain::render_bundle_markdown(&bundle).into_bytes(),
        JobExportFormat::Ndjson => unreachable!("handled before bounded merge"),
    };
    ensure!(
        rendered.len() as u64 <= MAX_EVIDENCE_EXPORT_BYTES,
        "rendered evidence exceeds the {MAX_EVIDENCE_EXPORT_BYTES}-byte output limit"
    );
    write_bytes(&output, &rendered)?;
    let exit_code = report
        .as_ref()
        .map_or(0, |report| report.exit_status.code());
    if let (Some(report), Some(report_path)) = (&report, &policy_report) {
        crate::output::write_json(report_path, report)?;
    }
    Ok(exit_code)
}

fn load_policy_document(path: &Path) -> Result<crate::policy::PolicyDocumentV1> {
    let input =
        fs::read_to_string(path).with_context(|| format!("reading policy {}", path.display()))?;
    crate::policy::PolicyDocumentV1::from_toml(&input)
        .with_context(|| format!("parsing policy {}", path.display()))
}

fn prepare_policy_export(
    mut bundle: EvidenceBundleV1,
    data_snapshot: Option<&DataSnapshotV1>,
    policy: Option<&crate::policy::PolicyDocumentV1>,
    evaluated_at: DateTime<Utc>,
) -> (EvidenceBundleV1, Option<crate::policy::PolicyReportV1>) {
    if let Some(snapshot) = data_snapshot {
        snapshot.apply(&mut bundle);
        bundle = bundle.normalized();
    }
    let report = policy.map(|document| {
        crate::policy::evaluate(
            &bundle,
            document,
            &crate::policy::EvaluationContext { evaluated_at },
        )
    });
    (bundle, report)
}

async fn export_job_sharded(client: &OperatorClient, job: &ScanJobV1, output: &Path) -> Result<()> {
    ensure!(!output.exists(), "NDJSON export directory already exists");
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("creating export parent {}", parent.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".evidence-export-")
        .tempdir_in(parent)
        .with_context(|| format!("creating staged export beside {}", output.display()))?;
    let mut writer = EvidenceShardWriter::new(staging.path(), EVIDENCE_SHARD_TARGET_BYTES);
    let target = job_target(job)?;
    let mut after = None;
    let mut tasks_succeeded = 0_u64;
    let mut artifacts_exported = 0_u64;
    let mut repositories_exported = 0_u64;
    let mut input_artifact_bytes = 0_u64;
    let mut missing_task_ids = Vec::new();
    let mut generated_at = job.updated_at;

    loop {
        let page = client.task_page(&job.id, after.as_deref()).await?;
        let succeeded = page
            .items
            .into_iter()
            .filter(|task| task.state == RepositoryTaskStateV1::Succeeded)
            .collect::<Vec<_>>();
        tasks_succeeded = tasks_succeeded
            .checked_add(succeeded.len() as u64)
            .context("succeeded task count overflowed")?;
        let requests = succeeded.into_iter().map(|task| async move {
            let bytes = client.task_artifact(&task.id).await?;
            Ok::<_, anyhow::Error>((task, bytes))
        });
        let mut responses = stream::iter(requests).buffered(EVIDENCE_EXPORT_CONCURRENCY);
        while let Some(response) = responses.next().await {
            let (task, bytes) = response?;
            let Some(bytes) = bytes else {
                missing_task_ids.push(task.id);
                continue;
            };
            validate_downloaded_artifact(&task, &bytes)?;
            input_artifact_bytes = input_artifact_bytes
                .checked_add(bytes.len() as u64)
                .context("evidence export byte count overflowed")?;
            ensure!(
                input_artifact_bytes <= job.spec.bounds.artifact_byte_limit,
                "evidence artifacts exceed the job artifact quota"
            );
            let bundle: EvidenceBundleV1 = serde_json::from_slice(&bytes)
                .with_context(|| format!("decoding evidence artifact for task {}", task.id.0))?;
            ensure!(
                bundle.schema_is_supported() && bundle.target == target,
                "task {} evidence schema or target does not match the job",
                task.id.0
            );
            let bundle = bundle.normalized();
            generated_at = generated_at.max(bundle.generated_at);
            let repository_count = bundle.repositories.len() as u64;
            repositories_exported = repositories_exported
                .checked_add(repository_count)
                .context("repository export count overflowed")?;
            writer.write_record(
                &EvidenceShardRecordV1 {
                    task_id: task.id,
                    evidence: bundle,
                },
                repository_count,
            )?;
            artifacts_exported += 1;
        }
        let Some(cursor) = page.next_cursor else {
            break;
        };
        after = Some(cursor);
    }

    ensure!(
        tasks_succeeded == job.progress.tasks_succeeded,
        "job task enumeration does not match the durable success count"
    );
    let (shards, output_shard_bytes) = writer.finish()?;
    let manifest = ShardedEvidenceManifestV1 {
        schema_version: SHARDED_EXPORT_SCHEMA_VERSION_V1,
        created_at: generated_at,
        job_id: job.id.clone(),
        job_state: job.state,
        target,
        tasks_total: job.progress.tasks_total,
        tasks_succeeded,
        artifacts_exported,
        artifacts_missing: missing_task_ids.len() as u64,
        repositories_exported,
        input_artifact_bytes,
        output_shard_bytes,
        shard_target_bytes: EVIDENCE_SHARD_TARGET_BYTES,
        shards,
        missing_task_ids,
    };
    write_json_new(&staging.path().join(SHARDED_EXPORT_MANIFEST), &manifest)?;
    let staged_path = staging.keep();
    fs::rename(&staged_path, output)
        .with_context(|| format!("atomically publishing export {}", output.display()))?;
    Ok(())
}

fn job_target(job: &ScanJobV1) -> Result<PackageIdentityV1> {
    let version = job
        .spec
        .target
        .version_spec
        .strip_prefix('=')
        .context("job target is not an exact version")?;
    Ok(PackageIdentityV1 {
        name: job.spec.target.crate_name.clone(),
        version: semver::Version::parse(version).context("job target version is invalid")?,
        source: None,
    })
}

fn validate_downloaded_artifact(task: &RepositoryTaskV1, bytes: &[u8]) -> Result<()> {
    let reference = task
        .result
        .as_ref()
        .context("succeeded task has no artifact reference")?;
    ensure!(
        bytes.len() as u64 == reference.stored_bytes
            && bytes.len() as u64 <= MAX_EVIDENCE_ARTIFACT_BYTES,
        "task {} artifact length does not match its durable reference",
        task.id.0
    );
    ensure!(
        sha256_hex(bytes) == reference.digest.as_str(),
        "task {} artifact digest does not match its durable reference",
        task.id.0
    );
    Ok(())
}

struct EvidenceShardWriter {
    root: PathBuf,
    target_bytes: u64,
    current: Option<OpenEvidenceShard>,
    shards: Vec<EvidenceShardV1>,
    total_bytes: u64,
}

struct OpenEvidenceShard {
    file_name: String,
    writer: BufWriter<fs::File>,
    hasher: Sha256,
    bytes: u64,
    records: u64,
    repositories: u64,
}

impl EvidenceShardWriter {
    fn new(root: &Path, target_bytes: u64) -> Self {
        Self {
            root: root.to_owned(),
            target_bytes,
            current: None,
            shards: Vec::new(),
            total_bytes: 0,
        }
    }

    fn write_record(&mut self, record: &EvidenceShardRecordV1, repositories: u64) -> Result<()> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        ensure!(
            line.len() as u64 <= MAX_EVIDENCE_ARTIFACT_BYTES + 1024,
            "serialized evidence shard record exceeds the supported bound"
        );
        if self.current.as_ref().is_some_and(|shard| {
            shard.records > 0 && shard.bytes.saturating_add(line.len() as u64) > self.target_bytes
        }) {
            self.finish_current()?;
        }
        if self.current.is_none() {
            self.open_next()?;
        }
        let shard = self.current.as_mut().expect("shard was opened");
        shard.writer.write_all(&line)?;
        shard.hasher.update(&line);
        shard.bytes += line.len() as u64;
        shard.records += 1;
        shard.repositories = shard
            .repositories
            .checked_add(repositories)
            .context("evidence shard repository count overflowed")?;
        Ok(())
    }

    fn open_next(&mut self) -> Result<()> {
        let file_name = format!("evidence-{:05}.ndjson", self.shards.len() + 1);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(self.root.join(&file_name))?;
        self.current = Some(OpenEvidenceShard {
            file_name,
            writer: BufWriter::new(file),
            hasher: Sha256::new(),
            bytes: 0,
            records: 0,
            repositories: 0,
        });
        Ok(())
    }

    fn finish_current(&mut self) -> Result<()> {
        let Some(mut shard) = self.current.take() else {
            return Ok(());
        };
        shard.writer.flush()?;
        shard.writer.get_ref().sync_all()?;
        self.total_bytes = self
            .total_bytes
            .checked_add(shard.bytes)
            .context("evidence shard byte total overflowed")?;
        self.shards.push(EvidenceShardV1 {
            file: shard.file_name,
            sha256: hex_digest(&shard.hasher.finalize()),
            bytes: shard.bytes,
            records: shard.records,
            repositories: shard.repositories,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<(Vec<EvidenceShardV1>, u64)> {
        self.finish_current()?;
        Ok((self.shards, self.total_bytes))
    }
}

fn job_is_exportable(job: &ScanJobV1) -> bool {
    job.state.is_terminal()
        || (job.state == ScanJobStateV1::Paused && !job.partial_reasons.is_empty())
}

fn merge_job_evidence(
    job: &ScanJobV1,
    bundles: Vec<(TaskId, EvidenceBundleV1)>,
    missing: &BTreeSet<TaskId>,
) -> Result<EvidenceBundleV1> {
    let version = job
        .spec
        .target
        .version_spec
        .strip_prefix('=')
        .context("job target is not an exact version")?;
    let target = PackageIdentityV1 {
        name: job.spec.target.crate_name.clone(),
        version: semver::Version::parse(version).context("job target version is invalid")?,
        source: None,
    };
    let generated_at = bundles
        .iter()
        .map(|(_, bundle)| bundle.generated_at)
        .max()
        .unwrap_or(job.updated_at);
    let mut globally_exhaustive =
        job.state == ScanJobStateV1::Completed && missing.is_empty() && !bundles.is_empty();
    let mut repositories = BTreeMap::<(String, Option<String>), RepositoryEvidenceV1>::new();
    let mut advisory_snapshots = BTreeSet::new();
    let mut limitations = BTreeSet::new();

    for (task_id, bundle) in bundles {
        ensure!(
            bundle.target == target,
            "task {} evidence target does not match the job target",
            task_id.0
        );
        globally_exhaustive &= bundle.globally_exhaustive;
        advisory_snapshots.extend(bundle.advisory_snapshots);
        limitations.extend(bundle.limitations);
        for repository in bundle.repositories {
            let key = (
                repository.repository.to_ascii_lowercase(),
                repository.repository_id.clone(),
            );
            if let Some(existing) = repositories.get(&key) {
                ensure!(
                    existing == &repository,
                    "conflicting evidence artifacts describe repository {}",
                    repository.repository
                );
            } else {
                repositories.insert(key, repository);
            }
        }
    }

    if job.state != ScanJobStateV1::Completed {
        limitations.insert(LimitationV1 {
            code: "job_not_complete".to_owned(),
            message: format!("job ended or paused in state {:?}", job.state),
        });
    }
    for reason in &job.partial_reasons {
        limitations.insert(LimitationV1 {
            code: "job_partial".to_owned(),
            message: reason.clone(),
        });
    }
    if let Some(failure) = &job.failure {
        limitations.insert(LimitationV1 {
            code: "job_failure".to_owned(),
            message: failure.clone(),
        });
    }
    for task_id in missing {
        limitations.insert(LimitationV1 {
            code: "artifact_unavailable".to_owned(),
            message: format!(
                "evidence artifact for succeeded task {} is unavailable",
                task_id.0
            ),
        });
    }

    Ok(EvidenceBundleV1 {
        schema_version: EvidenceBundleV1::SCHEMA_VERSION,
        generated_at,
        target,
        globally_exhaustive,
        repositories: repositories.into_values().collect(),
        advisory_snapshots: advisory_snapshots.into_iter().collect(),
        limitations: limitations.into_iter().collect(),
    }
    .normalized())
}

async fn mutate_job(args: JobMutationArgs, action: &str) -> Result<()> {
    let client = OperatorClient::new(args.connection)?;
    client
        .empty(client.post(&format!(
            "v1/jobs/{}/{}",
            path_segment(&args.job_id)?,
            action
        ))?)
        .await?;
    println!("job {} {} requested", args.job_id, action);
    Ok(())
}

pub fn calculate_sla(ledger: &SlaObservationLedgerV1, objective: f64) -> Result<SlaReportV1> {
    ensure!(ledger.schema_version == 1, "unsupported SLA schema version");
    ensure!(
        ledger.window_end > ledger.window_start,
        "SLA observation window must have positive duration"
    );
    ensure!(
        objective.is_finite() && (0.0..=100.0).contains(&objective),
        "SLA objective must be between 0 and 100"
    );
    let mut intervals = ledger.intervals.iter().collect::<Vec<_>>();
    intervals.sort_by_key(|interval| interval.start);
    let mut previous_end = ledger.window_start;
    let mut platform_unavailable = 0.0;
    let mut provider_wait = 0.0;
    let mut user_limit = 0.0;
    let mut quota_wait = 0.0;
    let mut cancelled = 0.0;
    for interval in intervals {
        ensure!(
            interval.start >= ledger.window_start && interval.end <= ledger.window_end,
            "SLA interval lies outside the observation window"
        );
        ensure!(
            interval.end > interval.start,
            "SLA interval must have positive duration"
        );
        ensure!(
            interval.start >= previous_end,
            "SLA intervals overlap; classifications must be mutually exclusive"
        );
        previous_end = interval.end;
        let seconds = duration_seconds(interval.start, interval.end)?;
        match interval.classification {
            SlaIntervalClassV1::PlatformUnavailable => platform_unavailable += seconds,
            SlaIntervalClassV1::UpstreamProviderWait => provider_wait += seconds,
            SlaIntervalClassV1::UserLimit => user_limit += seconds,
            SlaIntervalClassV1::QuotaWait => quota_wait += seconds,
            SlaIntervalClassV1::Cancelled => cancelled += seconds,
        }
    }
    let window_seconds = duration_seconds(ledger.window_start, ledger.window_end)?;
    let excluded = provider_wait + user_limit + quota_wait + cancelled;
    let eligible_seconds = window_seconds - excluded;
    ensure!(
        eligible_seconds >= platform_unavailable,
        "classified time exceeds SLA window"
    );
    let availability_percent = (eligible_seconds > 0.0)
        .then(|| 100.0 * (eligible_seconds - platform_unavailable) / eligible_seconds);
    let status = if !ledger.complete || availability_percent.is_none() {
        SlaStatusV1::Indeterminate
    } else if availability_percent.is_some_and(|actual| actual + f64::EPSILON >= objective) {
        SlaStatusV1::Met
    } else {
        SlaStatusV1::Missed
    };
    Ok(SlaReportV1 {
        schema_version: 1,
        window_start: ledger.window_start,
        window_end: ledger.window_end,
        objective_percent: objective,
        observation_complete: ledger.complete,
        status,
        availability_percent,
        window_seconds,
        eligible_seconds,
        platform_unavailable_seconds: platform_unavailable,
        excluded_upstream_provider_wait_seconds: provider_wait,
        excluded_user_limit_seconds: user_limit,
        excluded_quota_wait_seconds: quota_wait,
        excluded_cancelled_seconds: cancelled,
    })
}

fn render_sla_markdown(report: &SlaReportV1) -> String {
    let availability = report.availability_percent.map_or_else(
        || "not measurable".to_owned(),
        |value| format!("{value:.5}%"),
    );
    format!(
        "# Availability report\n\n\
         - Window: {} to {}\n\
         - Objective: {:.3}%\n\
         - Status: `{:?}`\n\
         - Observation complete: {}\n\
         - Availability: {}\n\
         - Eligible time: {:.3} seconds\n\
         - Platform unavailable: {:.3} seconds\n\
         - Excluded upstream-provider wait: {:.3} seconds\n\
         - Excluded user-limit time: {:.3} seconds\n\
         - Excluded quota wait: {:.3} seconds\n\
         - Excluded cancellation time: {:.3} seconds\n",
        report.window_start.to_rfc3339(),
        report.window_end.to_rfc3339(),
        report.objective_percent,
        report.status,
        report.observation_complete,
        availability,
        report.eligible_seconds,
        report.platform_unavailable_seconds,
        report.excluded_upstream_provider_wait_seconds,
        report.excluded_user_limit_seconds,
        report.excluded_quota_wait_seconds,
        report.excluded_cancelled_seconds,
    )
}

impl OperatorClient {
    fn new(args: OperatorConnectionArgs) -> Result<Self> {
        Ok(Self {
            base: validate_coordinator_url(args.coordinator)?,
            client: crate::pki::authenticated_client(
                &args.ca,
                &args.certificate,
                &args.private_key,
            )?,
        })
    }

    fn get(&self, path: &str) -> Result<RequestBuilder> {
        Ok(self.authenticated(self.client.get(self.base.join(path)?)))
    }

    fn post(&self, path: &str) -> Result<RequestBuilder> {
        Ok(self.authenticated(self.client.post(self.base.join(path)?)))
    }

    fn authenticated(&self, request: RequestBuilder) -> RequestBuilder {
        request.header("x-agent-id", "operator")
    }

    async fn json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let response = request.send().await.context("calling coordinator")?;
        let status = response.status();
        let bytes = read_bounded_body(response, MAX_API_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).context("decoding coordinator JSON response")
    }

    async fn empty(&self, request: RequestBuilder) -> Result<()> {
        let response = request.send().await.context("calling coordinator")?;
        let status = response.status();
        let bytes = read_bounded_body(response, MAX_API_RESPONSE_BYTES).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(api_error(status, &bytes))
        }
    }

    async fn event_page(&self, job_id: &str, after: Option<u64>) -> Result<JobEventPageV1> {
        let mut query = vec![("limit", COORDINATOR_PAGE_SIZE.to_string())];
        if let Some(after) = after {
            query.push(("after", after.to_string()));
        }
        self.json(
            self.get(&format!("v1/jobs/{}/events", path_segment(job_id)?))?
                .query(&query),
        )
        .await
    }

    async fn task_page(&self, job_id: &JobId, after: Option<&str>) -> Result<RepositoryTaskPageV1> {
        let mut query = vec![("limit", COORDINATOR_PAGE_SIZE.to_string())];
        if let Some(after) = after {
            query.push(("after", after.to_owned()));
        }
        let page: RepositoryTaskPageV1 = self
            .json(
                self.get(&format!("v1/jobs/{}/tasks", path_segment(&job_id.0)?))?
                    .query(&query),
            )
            .await?;
        let mut previous = after;
        for task in &page.items {
            ensure!(
                task.schema_version == SCHEMA_VERSION_V1
                    && task.job_id == *job_id
                    && previous.is_none_or(|value| task.repository_id.as_str() > value),
                "coordinator returned an invalid or unordered task page"
            );
            previous = Some(&task.repository_id);
        }
        if let Some(cursor) = page.next_cursor.as_deref() {
            ensure!(
                page.items
                    .last()
                    .is_some_and(|task| task.repository_id == cursor),
                "coordinator returned an invalid task-page cursor"
            );
        }
        Ok(page)
    }

    async fn succeeded_tasks(&self, job_id: &JobId) -> Result<Vec<RepositoryTaskV1>> {
        let mut tasks = Vec::new();
        let mut after = None;
        loop {
            let page = self.task_page(job_id, after.as_deref()).await?;
            tasks.extend(
                page.items
                    .into_iter()
                    .filter(|task| task.state == RepositoryTaskStateV1::Succeeded),
            );
            ensure!(
                tasks.len() as u64 <= MAX_REPOSITORIES_PER_JOB,
                "coordinator returned too many succeeded tasks"
            );
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        Ok(tasks)
    }

    async fn task_artifact(&self, task_id: &TaskId) -> Result<Option<Vec<u8>>> {
        let task_id = path_segment(&task_id.0)?;
        let response = self
            .get(&format!("v1/tasks/{task_id}/artifact"))?
            .send()
            .await
            .context("calling coordinator")?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = read_bounded_body(response, MAX_EVIDENCE_ARTIFACT_BYTES).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        ensure!(
            content_type
                .as_deref()
                .and_then(|value| value.split(';').next())
                .is_some_and(|value| value.trim() == EVIDENCE_MEDIA_TYPE_V1),
            "coordinator returned an unexpected artifact media type"
        );
        Ok(Some(bytes))
    }
}

fn api_error(status: StatusCode, bytes: &[u8]) -> anyhow::Error {
    if let Ok(error) = serde_json::from_slice::<ApiErrorResponse>(bytes) {
        anyhow::anyhow!(
            "coordinator returned HTTP {} ({}): {}",
            status.as_u16(),
            error.code,
            error.message
        )
    } else {
        anyhow::anyhow!("coordinator returned HTTP {}", status.as_u16())
    }
}

async fn read_bounded_body(response: reqwest::Response, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= limit),
        "coordinator response exceeds {limit} bytes"
    );
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default();
    let mut bytes = Vec::with_capacity(capacity);
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.context("reading coordinator response")?;
        let next_len = bytes
            .len()
            .checked_add(chunk.len())
            .context("coordinator response size overflowed")?;
        ensure!(
            next_len as u64 <= limit,
            "coordinator response exceeds {limit} bytes"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_coordinator_url(mut url: Url) -> Result<Url> {
    ensure!(url.scheme() == "https", "coordinator URL must use HTTPS");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "coordinator URL must not contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "coordinator URL must not contain a query or fragment"
    );
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

fn path_segment(value: &str) -> Result<&str> {
    ensure!(
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "job ID contains unsupported characters"
    );
    Ok(value)
}

fn load_repositories(path: &Path) -> Result<Vec<String>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading repository-list metadata {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_REPOSITORY_LIST_BYTES,
        "repository list exceeds {MAX_REPOSITORY_LIST_BYTES} bytes"
    );
    let input = fs::read_to_string(path)
        .with_context(|| format!("reading repository list {}", path.display()))?;
    let input = input.trim_start_matches('\u{feff}');
    let values = if input.trim_start().starts_with('[') {
        serde_json::from_str::<Vec<String>>(input)
            .with_context(|| format!("parsing repository JSON {}", path.display()))?
    } else {
        input
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect()
    };
    let mut repositories = BTreeSet::new();
    for value in values {
        let normalized = value.trim().to_ascii_lowercase();
        ensure!(
            valid_repository_name(&normalized),
            "invalid owner/name repository identifier in {}",
            path.display()
        );
        repositories.insert(normalized);
        ensure!(
            repositories.len() as u64 <= MAX_REPOSITORIES_PER_JOB,
            "repository list exceeds the supported {}-repository capacity",
            MAX_REPOSITORIES_PER_JOB
        );
    }
    ensure!(!repositories.is_empty(), "repository list is empty");
    Ok(repositories.into_iter().collect())
}

fn valid_repository_name(value: &str) -> bool {
    let Some((owner, repository)) = value.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !repository.is_empty()
        && !repository.contains('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

fn event_kind(kind: &JobEventKindV1) -> &'static str {
    match kind {
        JobEventKindV1::Submitted => "submitted",
        JobEventKindV1::Started => "started",
        JobEventKindV1::Paused => "paused",
        JobEventKindV1::Resumed => "resumed",
        JobEventKindV1::Cancelled => "cancelled",
        JobEventKindV1::Completed => "completed",
        JobEventKindV1::CompletedPartial => "completed_partial",
        JobEventKindV1::Failed => "failed",
        JobEventKindV1::TaskQueued => "task_queued",
        JobEventKindV1::TaskLeased => "task_leased",
        JobEventKindV1::TaskHeartbeat => "task_heartbeat",
        JobEventKindV1::TaskReclaimed => "task_reclaimed",
        JobEventKindV1::TaskSucceeded => "task_succeeded",
        JobEventKindV1::TaskFailed => "task_failed",
        JobEventKindV1::QuotaReserved => "quota_reserved",
        JobEventKindV1::QuotaReconciled => "quota_reconciled",
        JobEventKindV1::QuotaReleased => "quota_released",
        JobEventKindV1::ProviderPermitGranted => "provider_permit_granted",
        JobEventKindV1::ProviderRequestFinished => "provider_request_finished",
    }
}

fn display_set(values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn duration_seconds(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<f64> {
    let microseconds = (end - start)
        .num_microseconds()
        .ok_or_else(|| anyhow::anyhow!("SLA duration exceeds supported range"))?;
    Ok(microseconds as f64 / 1_000_000.0)
}

fn write_text(path: &Path, value: &str) -> Result<()> {
    write_bytes(path, value.as_bytes())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn write_bytes(path: &Path, value: &[u8]) -> Result<()> {
    if path == Path::new("-") {
        let mut stdout = io::stdout().lock();
        stdout.write_all(value)?;
        stdout.flush()?;
        return Ok(());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(value)?;
    temp.as_file_mut().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)?;
    }
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary JSON beside {}", path.display()))?;
    serde_json::to_writer_pretty(&mut temp, value)
        .with_context(|| format!("serializing JSON for {}", path.display()))?;
    temp.write_all(b"\n")?;
    temp.as_file_mut().sync_all()?;
    temp.persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("creating {} without overwrite", path.display()))?;
    Ok(())
}

fn copy_new(source: &Path, destination: &Path) -> Result<()> {
    let bytes = fs::read(source).with_context(|| format!("reading {}", source.display()))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .with_context(|| format!("creating {}", destination.display()))?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

fn ensure_empty_or_missing_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    ensure!(path.is_dir(), "{} is not a directory", path.display());
    ensure!(
        fs::read_dir(path)?.next().is_none(),
        "coordinator directory {} is not empty",
        path.display()
    );
    Ok(())
}

fn paths_conflict(left: &Path, right: &Path) -> Result<bool> {
    Ok(lexical_path_identity(left)? == lexical_path_identity(right)?)
}

fn lexical_path_identity(path: &Path) -> Result<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("determining current directory for path validation")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    let identity = normalized.to_string_lossy().into_owned();
    #[cfg(windows)]
    let identity = identity.to_ascii_lowercase();
    Ok(identity)
}

fn require_initialized(paths: &StatePaths) -> Result<()> {
    for path in [
        &paths.deployment_manifest,
        &paths.database,
        &paths.envelope_key,
        &paths.ca_certificate,
        &paths.server_certificate,
        &paths.server_private_key,
        &paths.operator_certificate,
    ] {
        ensure!(
            path.is_file(),
            "coordinator state is missing {}",
            path.display()
        );
    }
    Ok(())
}

async fn open_store(paths: &StatePaths) -> Result<TursoCoordinatorStore> {
    TursoCoordinatorStore::open(
        &paths.database,
        EnvelopeKey::load(&paths.envelope_key, ENVELOPE_KEY_ID)?,
    )
    .await
}

struct StatePaths {
    deployment_manifest: PathBuf,
    database: PathBuf,
    envelope_key: PathBuf,
    pki_directory: PathBuf,
    ca_certificate: PathBuf,
    server_certificate: PathBuf,
    server_private_key: PathBuf,
    operator_certificate: PathBuf,
    artifact_cache: PathBuf,
}

impl StatePaths {
    fn new(directory: &Path) -> Self {
        let pki_directory = directory.join("pki");
        Self {
            deployment_manifest: directory.join("manifest.json"),
            database: directory.join("coordinator.db"),
            envelope_key: directory.join("envelope.key"),
            ca_certificate: pki_directory.join("ca.pem"),
            server_certificate: pki_directory.join("server.pem"),
            server_private_key: pki_directory.join("server.key"),
            operator_certificate: pki_directory.join("operator.pem"),
            artifact_cache: directory.join("artifacts"),
            pki_directory,
        }
    }
}

fn parse_positive_u64(value: &str) -> std::result::Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid integer `{value}`: {error}"))?;
    (parsed > 0)
        .then_some(parsed)
        .ok_or_else(|| "value must be greater than zero".to_owned())
}

fn parse_positive_u32(value: &str) -> std::result::Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|error| format!("invalid integer `{value}`: {error}"))?;
    (parsed > 0)
        .then_some(parsed)
        .ok_or_else(|| "value must be greater than zero".to_owned())
}

fn parse_repository_limit(value: &str) -> std::result::Result<u64, String> {
    let parsed = parse_positive_u64(value)?;
    (parsed <= MAX_REPOSITORIES_PER_JOB)
        .then_some(parsed)
        .ok_or_else(|| format!("value must be at most {MAX_REPOSITORIES_PER_JOB}"))
}

fn parse_lease_seconds(value: &str) -> std::result::Result<u64, String> {
    let parsed = parse_positive_u64(value)?;
    (parsed <= 600)
        .then_some(parsed)
        .ok_or_else(|| "value must be at most 600".to_owned())
}

fn parse_percentage(value: &str) -> std::result::Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|error| format!("invalid percentage `{value}`: {error}"))?;
    (parsed.is_finite() && (0.0..=100.0).contains(&parsed))
        .then_some(parsed)
        .ok_or_else(|| "value must be between 0 and 100".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(state: ScanJobStateV1, partial_reasons: BTreeSet<String>) -> ScanJobV1 {
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
                repository_scope: RepositoryScopeV1::PublicOnly,
                credential_profile_id: None,
                bounds: ScanBoundsV1::default(),
                analyzer_versions: BTreeMap::new(),
            },
            state,
            created_at: timestamp(10),
            updated_at: timestamp(20),
            progress: Default::default(),
            quota_usage: Default::default(),
            partial_reasons,
            failure: None,
        }
    }

    fn empty_bundle(version: semver::Version, generated_at: DateTime<Utc>) -> EvidenceBundleV1 {
        EvidenceBundleV1 {
            schema_version: EvidenceBundleV1::SCHEMA_VERSION,
            generated_at,
            target: PackageIdentityV1 {
                name: "fs2".to_owned(),
                version,
                source: None,
            },
            globally_exhaustive: true,
            repositories: Vec::new(),
            advisory_snapshots: Vec::new(),
            limitations: Vec::new(),
        }
    }

    #[test]
    fn ten_thousand_records_are_written_as_bounded_ndjson_shards() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = EvidenceShardWriter::new(directory.path(), 16 * 1024);
        let bundle = empty_bundle(semver::Version::new(0, 4, 3), timestamp(20));
        for value in 0..10_000 {
            writer
                .write_record(
                    &EvidenceShardRecordV1 {
                        task_id: TaskId(format!("task-{value:05}")),
                        evidence: bundle.clone(),
                    },
                    0,
                )
                .unwrap();
        }
        let (shards, total_bytes) = writer.finish().unwrap();

        assert!(shards.len() > 1);
        assert_eq!(
            shards.iter().map(|shard| shard.records).sum::<u64>(),
            10_000
        );
        assert_eq!(
            shards.iter().map(|shard| shard.bytes).sum::<u64>(),
            total_bytes
        );
        assert!(shards.iter().all(|shard| shard.bytes <= 16 * 1024));
        for shard in shards {
            assert_eq!(
                fs::metadata(directory.path().join(shard.file))
                    .unwrap()
                    .len(),
                shard.bytes
            );
        }
    }

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    #[test]
    fn sla_separates_platform_failure_from_excluded_time() {
        let ledger = SlaObservationLedgerV1 {
            schema_version: 1,
            window_start: timestamp(0),
            window_end: timestamp(1_000),
            complete: true,
            intervals: vec![
                SlaIntervalV1 {
                    start: timestamp(100),
                    end: timestamp(110),
                    classification: SlaIntervalClassV1::PlatformUnavailable,
                },
                SlaIntervalV1 {
                    start: timestamp(200),
                    end: timestamp(300),
                    classification: SlaIntervalClassV1::UpstreamProviderWait,
                },
            ],
        };
        let report = calculate_sla(&ledger, 99.0).unwrap();
        assert_eq!(report.eligible_seconds, 900.0);
        assert_eq!(report.platform_unavailable_seconds, 10.0);
        assert_eq!(report.excluded_upstream_provider_wait_seconds, 100.0);
        assert!(matches!(report.status, SlaStatusV1::Missed));
    }

    #[test]
    fn incomplete_monitoring_is_indeterminate() {
        let ledger = SlaObservationLedgerV1 {
            schema_version: 1,
            window_start: timestamp(0),
            window_end: timestamp(100),
            complete: false,
            intervals: Vec::new(),
        };
        let report = calculate_sla(&ledger, 99.5).unwrap();
        assert!(matches!(report.status, SlaStatusV1::Indeterminate));
    }

    #[test]
    fn overlapping_sla_classifications_are_rejected() {
        let ledger = SlaObservationLedgerV1 {
            schema_version: 1,
            window_start: timestamp(0),
            window_end: timestamp(100),
            complete: true,
            intervals: vec![
                SlaIntervalV1 {
                    start: timestamp(10),
                    end: timestamp(30),
                    classification: SlaIntervalClassV1::PlatformUnavailable,
                },
                SlaIntervalV1 {
                    start: timestamp(20),
                    end: timestamp(40),
                    classification: SlaIntervalClassV1::QuotaWait,
                },
            ],
        };
        assert!(calculate_sla(&ledger, 99.5).is_err());
    }

    #[test]
    fn repository_input_is_normalized_and_deduplicated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("repositories.txt");
        fs::write(&path, "# candidates\nOwner/Repo\nowner/repo\nOther/App\n").unwrap();
        assert_eq!(
            load_repositories(&path).unwrap(),
            vec!["other/app".to_owned(), "owner/repo".to_owned()]
        );
    }

    #[test]
    fn coordinator_url_requires_clean_https_origin() {
        assert!(validate_coordinator_url(Url::parse("http://localhost:8443").unwrap()).is_err());
        assert!(
            validate_coordinator_url(Url::parse("https://user@localhost:8443").unwrap()).is_err()
        );
        assert_eq!(
            validate_coordinator_url(Url::parse("https://localhost:8443").unwrap())
                .unwrap()
                .as_str(),
            "https://localhost:8443/"
        );
    }

    #[test]
    fn lexical_path_aliases_conflict() {
        assert!(paths_conflict(Path::new("backup.db"), Path::new("./backup.db")).unwrap());
        assert!(!paths_conflict(Path::new("backup.db"), Path::new("backup.json")).unwrap());
    }

    #[test]
    fn export_accepts_terminal_jobs_and_paused_partial_jobs() {
        assert!(job_is_exportable(&job(
            ScanJobStateV1::Completed,
            BTreeSet::new()
        )));
        assert!(job_is_exportable(&job(
            ScanJobStateV1::Paused,
            BTreeSet::from(["quota_exhausted".to_owned()])
        )));
        assert!(!job_is_exportable(&job(
            ScanJobStateV1::Running,
            BTreeSet::new()
        )));
        assert!(!job_is_exportable(&job(
            ScanJobStateV1::Running,
            BTreeSet::from(["prior_partial_result".to_owned()])
        )));
    }

    #[test]
    fn evidence_merge_is_order_independent_and_records_missing_artifacts() {
        let job = job(ScanJobStateV1::CompletedPartial, BTreeSet::new());
        let first = (
            TaskId("task-b".to_owned()),
            empty_bundle(semver::Version::new(0, 4, 3), timestamp(30)),
        );
        let second = (
            TaskId("task-a".to_owned()),
            empty_bundle(semver::Version::new(0, 4, 3), timestamp(40)),
        );
        let missing = BTreeSet::from([TaskId("task-c".to_owned())]);

        let forward =
            merge_job_evidence(&job, vec![first.clone(), second.clone()], &missing).unwrap();
        let reverse = merge_job_evidence(&job, vec![second, first], &missing).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.generated_at, timestamp(40));
        assert!(!forward.globally_exhaustive);
        assert!(forward.limitations.iter().any(|limitation| {
            limitation.code == "artifact_unavailable" && limitation.message.contains("task-c")
        }));
    }

    #[test]
    fn evidence_merge_rejects_a_different_target() {
        let job = job(ScanJobStateV1::Completed, BTreeSet::new());
        let bundle = empty_bundle(semver::Version::new(0, 4, 2), timestamp(30));
        assert!(
            merge_job_evidence(
                &job,
                vec![(TaskId("task-a".to_owned()), bundle)],
                &BTreeSet::new()
            )
            .is_err()
        );
    }

    #[test]
    fn distributed_policy_report_uses_the_durable_job_time() {
        let policy = crate::policy::PolicyDocumentV1::from_toml(
            r#"
[[rules]]
id = "exact-resolution"
type = "exact_resolution"
"#,
        )
        .unwrap();
        let bundle = empty_bundle(semver::Version::new(0, 4, 3), timestamp(10));

        let (_, first) = prepare_policy_export(bundle.clone(), None, Some(&policy), timestamp(20));
        let (_, second) = prepare_policy_export(bundle, None, Some(&policy), timestamp(20));

        assert_eq!(first, second);
        let report = first.unwrap();
        assert_eq!(report.evaluated_at, timestamp(20));
        assert_eq!(report.exit_status.code(), 4);
    }
}
