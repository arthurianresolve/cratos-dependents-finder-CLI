use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{
    advisory::{DataSnapshotV1, SnapshotInputs, create_snapshot},
    crates_io::CratesIoClient,
    github::{GitHubClient, RepositoryScope, preferred_token_from_environment},
    inventory::{ScanOptions, scan},
    links::build_links,
    operations::{AgentArgs, CoordinatorArgs, JobArgs, SlaArgs},
    report,
    resolve::{ResolveOptions, resolve_target},
};

const PARTIAL_RESULTS_EXIT_CODE: i32 = 4;
const REQUIRED_MATCH_NOT_FOUND_EXIT_CODE: i32 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "crate-dependent-repos",
    version,
    about = "Find published declarations and exact default-branch Cargo.lock resolutions",
    long_about = "Evidence-oriented inventory of repositories that declare or resolve a Cargo crate version. Results are bounded by public registry and GitHub coverage and are never represented as exhaustive."
)]
pub struct Cli {
    /// Maximum concurrent repository inspections and GitHub requests.
    #[arg(long, global = true, default_value_t = 4, value_parser = parse_jobs)]
    jobs: usize,

    /// Include all private and internal repositories visible to the GitHub credential.
    #[arg(long, global = true)]
    include_private: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Resolve an exact crate or rank the closest crates.io matches.
    Resolve(ResolveArgs),
    /// Print the bounded discovery links for a crate and exact version.
    Links(LinksArgs),
    /// Build a CSV inventory and verify immutable default-branch snapshots.
    Scan(ScanArgs),
    /// Read a previous CSV inventory and emit an offline summary.
    Report(ReportArgs),
    /// Validate or evaluate organization policy as code.
    Policy(PolicyArgs),
    /// Explain why repositories were retained in a canonical evidence bundle.
    Explain(ExplainArgs),
    /// Create reproducible offline license and advisory snapshots.
    Data(DataArgs),
    /// Operate the single-owner self-hosted coordinator.
    Coordinator(CoordinatorArgs),
    /// Enroll, revoke, or run authenticated LAN workers.
    Agent(AgentArgs),
    /// Submit and operate durable coordinator jobs.
    Job(JobArgs),
    /// Calculate a categorized availability objective report.
    Sla(SlaArgs),
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Parse and structurally validate a versioned TOML policy.
    Validate { policy: PathBuf },
    /// Evaluate a policy against a previously written evidence bundle.
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        data_snapshot: Option<PathBuf>,
        /// JSON report path, or '-' for stdout.
        #[arg(long, default_value = "-")]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Canonical evidence JSON, or an NDJSON export directory.
    evidence: PathBuf,
    /// Select a repository by canonical name or immutable GitHub ID.
    #[arg(long)]
    repository: Option<String>,
    /// Emit the selected explanation records as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DataArgs {
    #[command(subcommand)]
    command: DataCommand,
}

#[derive(Debug, Subcommand)]
enum DataCommand {
    /// Normalize pinned RustSec, OSV, and crates metadata into one snapshot.
    Sync(DataSyncArgs),
}

#[derive(Debug, Args)]
struct DataSyncArgs {
    #[arg(long, requires = "rustsec_revision")]
    rustsec: Option<PathBuf>,
    #[arg(long, requires = "rustsec")]
    rustsec_revision: Option<String>,
    #[arg(long, requires = "osv_revision")]
    osv: Option<PathBuf>,
    #[arg(long, requires = "osv")]
    osv_revision: Option<String>,
    #[arg(long, requires = "crates_revision")]
    crates: Option<PathBuf>,
    #[arg(long, requires = "crates")]
    crates_revision: Option<String>,
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    /// crates.io crate name, GitHub owner/repo, repository name, or GitHub URL.
    query: String,

    /// Maximum number of ranked alternatives to show.
    #[arg(long, default_value_t = 10, value_parser = parse_limit_100)]
    limit: usize,

    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LinksArgs {
    /// Crate name or GitHub repository identifier.
    query: String,

    /// Exact version whose resolution/declarations should be searched.
    #[arg(long)]
    version: semver::Version,

    /// Select this exact crate when QUERY is a repository or fuzzy name.
    #[arg(long)]
    crate_name: Option<String>,

    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// crates.io crate name, GitHub owner/repo, repository name, or GitHub URL.
    query: String,

    /// Exact version to test in requirements and lockfiles.
    #[arg(long)]
    version: semver::Version,

    /// Select this exact crate when QUERY is a repository or fuzzy name.
    #[arg(long)]
    crate_name: Option<String>,

    /// Permit a high-confidence fuzzy result to be scanned.
    #[arg(long)]
    accept_closest: bool,

    /// Which published Cargo requirements should seed candidate repositories.
    #[arg(long, value_enum, default_value_t = RequirementFilter::Accepts)]
    requirement_filter: RequirementFilter,

    /// Candidate sources. GitHub code search is supplemental and bounded.
    #[arg(long, value_enum, default_value_t = Discovery::CratesIo)]
    discovery: Discovery,

    /// Dependency kinds retained from crates.io metadata.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "normal,build,dev"
    )]
    dependency_kind: Vec<DependencyKind>,

    /// How optional published dependency declarations are filtered.
    #[arg(long, value_enum, default_value_t = OptionalFilter::Include)]
    optional: OptionalFilter,

    /// Include repositories GitHub reports as forks.
    #[arg(long)]
    include_forks: bool,

    /// Exclude repositories GitHub reports as archived.
    #[arg(long)]
    exclude_archived: bool,

    /// Days since the default-branch HEAD commit at which a repo is stale.
    #[arg(long, default_value_t = 365)]
    stale_after_days: u64,

    /// Filter by computed activity class.
    #[arg(long, value_enum, default_value_t = ActivityFilter::All)]
    activity: ActivityFilter,

    /// Keep repos whose default-branch HEAD commit is on/after this UTC date.
    #[arg(long, value_name = "YYYY-MM-DD")]
    committed_since: Option<chrono::NaiveDate>,

    /// Keep repos whose default-branch HEAD commit is before this UTC date.
    #[arg(long, value_name = "YYYY-MM-DD")]
    committed_before: Option<chrono::NaiveDate>,

    /// Maximum reverse-dependency release records to process.
    #[arg(long)]
    max_candidates: Option<usize>,

    /// Maximum distinct repositories to inspect after discovery.
    #[arg(long)]
    max_repositories: Option<usize>,

    /// Maximum results requested from each bounded GitHub code search.
    #[arg(long, default_value_t = 100, value_parser = parse_limit_1000)]
    github_search_limit: usize,

    /// Maximum Cargo.lock or Cargo.toml blob size downloaded.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    max_file_bytes: u64,

    /// CSV output path, or '-' for stdout.
    #[arg(short, long, default_value = "-")]
    output: PathBuf,

    /// Also write a run summary as JSON at this path.
    #[arg(long)]
    summary_json: Option<PathBuf>,

    /// Write the canonical versioned evidence bundle as JSON.
    #[arg(long)]
    evidence_json: Option<PathBuf>,

    /// Evaluate this versioned TOML policy against the completed evidence.
    #[arg(long, requires = "policy_report")]
    policy: Option<PathBuf>,

    /// Write the deterministic policy report as JSON.
    #[arg(long, requires = "policy")]
    policy_report: Option<PathBuf>,

    /// Enrich evidence from a pinned offline license/advisory snapshot.
    #[arg(long)]
    data_snapshot: Option<PathBuf>,

    /// Return success even when some repository evidence is partial or failed.
    #[arg(long)]
    allow_partial: bool,

    /// Return a non-zero exit when no exact lockfile match is confirmed.
    #[arg(long)]
    require_match: bool,
}

#[derive(Debug, Args)]
struct ReportArgs {
    /// CSV file produced by `scan`.
    input: PathBuf,

    /// Sort rows by the selected field.
    #[arg(long, value_enum, default_value_t = ReportSort::LastCommitDesc)]
    sort: ReportSort,

    /// Group rows before sorting within each group.
    #[arg(long, value_enum)]
    group_by: Option<ReportGroupBy>,

    /// Emit machine-readable JSON instead of Markdown.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ReportSort {
    LastCommitDesc,
    LastCommitAsc,
    MsrvAsc,
    MsrvDesc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ReportGroupBy {
    Msrv,
    Os,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum RequirementFilter {
    Any,
    Accepts,
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Discovery {
    CratesIo,
    GithubCode,
    Both,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DependencyKind {
    Normal,
    Build,
    Dev,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OptionalFilter {
    Include,
    Exclude,
    Only,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ActivityFilter {
    All,
    Active,
    Stale,
}

pub async fn run(cli: Cli) -> Result<()> {
    let command = match cli.command {
        Command::Report(args) => {
            return report::run_report(&args.input, args.sort, args.group_by, args.json);
        }
        Command::Explain(args) => {
            return crate::explain::render(&args.evidence, args.repository.as_deref(), args.json);
        }
        Command::Policy(args) => {
            return run_policy(args);
        }
        Command::Data(args) => {
            return run_data(args);
        }
        Command::Coordinator(args) => {
            return crate::operations::run_coordinator(args).await;
        }
        Command::Agent(args) => {
            return crate::operations::run_agent_command(args).await;
        }
        Command::Job(args) => {
            let exit_code = crate::operations::run_job(args, cli.include_private).await?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
            return Ok(());
        }
        Command::Sla(args) => {
            return crate::operations::run_sla(args);
        }
        command => command,
    };

    let github_token = preferred_token_from_environment();
    if cli.include_private && github_token.is_none() {
        anyhow::bail!("--include-private requires GITHUB_APP_TOKEN, GITHUB_TOKEN, or GH_TOKEN");
    }
    let repository_scope = if cli.include_private {
        RepositoryScope::AllVisible
    } else {
        RepositoryScope::PublicOnly
    };
    let crates_io = CratesIoClient::new()?;
    let github = GitHubClient::new(github_token)?;

    match command {
        Command::Resolve(args) => {
            let result = resolve_target(
                &crates_io,
                &github,
                &args.query,
                ResolveOptions {
                    limit: args.limit,
                    explicit_crate: None,
                    accept_closest: false,
                    repository_scope,
                },
            )
            .await?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print!("{result}");
            }
        }
        Command::Links(args) => {
            let resolved = resolve_target(
                &crates_io,
                &github,
                &args.query,
                ResolveOptions {
                    limit: 10,
                    explicit_crate: args.crate_name,
                    accept_closest: false,
                    repository_scope,
                },
            )
            .await?;
            let links = build_links(
                resolved.selected_name()?,
                &args.version,
                resolved.repository(),
            );
            if args.json {
                println!("{}", serde_json::to_string_pretty(&links)?);
            } else {
                print!("{links}");
            }
        }
        Command::Scan(args) => {
            let outcome = scan(
                &crates_io,
                &github,
                args.into_options(cli.jobs, repository_scope),
            )
            .await?;
            if let Some(code @ (4 | 5)) = outcome.policy_exit_code {
                std::process::exit(code);
            }
            if outcome.partial && !outcome.allow_partial {
                std::process::exit(PARTIAL_RESULTS_EXIT_CODE);
            }
            if outcome.no_match && outcome.require_match {
                std::process::exit(REQUIRED_MATCH_NOT_FOUND_EXIT_CODE);
            }
        }
        Command::Report(args) => {
            report::run_report(&args.input, args.sort, args.group_by, args.json)?
        }
        Command::Policy(_)
        | Command::Explain(_)
        | Command::Data(_)
        | Command::Coordinator(_)
        | Command::Agent(_)
        | Command::Job(_)
        | Command::Sla(_) => {
            unreachable!("offline commands returned before client initialization")
        }
    }

    Ok(())
}

fn run_policy(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Validate { policy } => {
            let document = load_policy(&policy)?;
            let diagnostics = document.validate();
            if !diagnostics.is_empty() {
                anyhow::bail!("{}", serde_json::to_string_pretty(&diagnostics)?);
            }
            println!(
                "policy schema {} is valid; {} rules; {} exceptions",
                document.schema_version,
                document.rules.len(),
                document.exceptions.len()
            );
        }
        PolicyCommand::Check {
            policy,
            evidence,
            data_snapshot,
            output,
        } => {
            let document = load_policy(&policy)?;
            let mut bundle = crate::explain::load_bundle(&evidence)?;
            if let Some(path) = data_snapshot {
                DataSnapshotV1::load(&path)?.apply(&mut bundle);
            }
            let report = crate::policy::evaluate(
                &bundle,
                &document,
                &crate::policy::EvaluationContext {
                    evaluated_at: chrono::Utc::now(),
                },
            );
            crate::output::write_json(&output, &report)?;
            if report.exit_status.code() != 0 {
                std::process::exit(report.exit_status.code());
            }
        }
    }
    Ok(())
}

fn load_policy(path: &std::path::Path) -> Result<crate::policy::PolicyDocumentV1> {
    let input = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;
    crate::policy::PolicyDocumentV1::from_toml(&input)
        .with_context(|| format!("parsing policy {}", path.display()))
}

fn run_data(args: DataArgs) -> Result<()> {
    match args.command {
        DataCommand::Sync(args) => {
            let inputs = SnapshotInputs {
                rustsec: args
                    .rustsec
                    .as_deref()
                    .zip(args.rustsec_revision.as_deref()),
                osv: args.osv.as_deref().zip(args.osv_revision.as_deref()),
                crates: args.crates.as_deref().zip(args.crates_revision.as_deref()),
            };
            let snapshot = create_snapshot(inputs, &args.output)?;
            eprintln!(
                "wrote {} licenses and {} advisories from {} pinned sources",
                snapshot.licenses.len(),
                snapshot.advisories.len(),
                snapshot.sources.len()
            );
        }
    }
    Ok(())
}

fn parse_jobs(value: &str) -> std::result::Result<usize, String> {
    parse_bounded_usize(value, 1, 64)
}

fn parse_limit_100(value: &str) -> std::result::Result<usize, String> {
    parse_bounded_usize(value, 1, 100)
}

fn parse_limit_1000(value: &str) -> std::result::Result<usize, String> {
    parse_bounded_usize(value, 1, 1_000)
}

fn parse_bounded_usize(
    value: &str,
    minimum: usize,
    maximum: usize,
) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|error| format!("invalid integer `{value}`: {error}"))?;
    if (minimum..=maximum).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(format!("value must be between {minimum} and {maximum}"))
    }
}

impl ScanArgs {
    fn into_options(self, jobs: usize, repository_scope: RepositoryScope) -> ScanOptions {
        ScanOptions {
            query: self.query,
            version: self.version,
            explicit_crate: self.crate_name,
            accept_closest: self.accept_closest,
            requirement_filter: self.requirement_filter,
            discovery: self.discovery,
            dependency_kinds: self.dependency_kind,
            optional: self.optional,
            include_forks: self.include_forks,
            exclude_archived: self.exclude_archived,
            stale_after_days: self.stale_after_days,
            activity: self.activity,
            committed_since: self.committed_since,
            committed_before: self.committed_before,
            max_candidates: self.max_candidates,
            max_repositories: self.max_repositories,
            github_search_limit: self.github_search_limit,
            max_file_bytes: self.max_file_bytes,
            output: self.output,
            summary_json: self.summary_json,
            evidence_json: self.evidence_json,
            policy_file: self.policy,
            policy_report: self.policy_report,
            data_snapshot: self.data_snapshot,
            allow_partial: self.allow_partial,
            require_match: self.require_match,
            jobs,
            repository_scope,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_self_hosted_operations_without_affecting_scan_syntax() {
        let coordinator = Cli::try_parse_from([
            "crate-dependent-repos",
            "coordinator",
            "init",
            "--directory",
            "state",
            "--server-name",
            "coordinator.lan",
        ])
        .unwrap();
        assert!(matches!(coordinator.command, Command::Coordinator(_)));

        let scan =
            Cli::try_parse_from(["crate-dependent-repos", "scan", "fs2", "--version", "0.4.3"])
                .unwrap();
        assert!(matches!(scan.command, Command::Scan(_)));
    }

    #[test]
    fn rejects_worker_leases_above_coordinator_protocol_limit() {
        let result = Cli::try_parse_from([
            "crate-dependent-repos",
            "agent",
            "run",
            "--coordinator",
            "https://coordinator.lan:8443",
            "--ca",
            "ca.pem",
            "--certificate",
            "agent.pem",
            "--private-key",
            "agent.key",
            "--agent-id",
            "worker-1",
            "--job-id",
            "job-1",
            "--lease-seconds",
            "601",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parses_job_and_sla_subcommands() {
        let status = Cli::try_parse_from([
            "crate-dependent-repos",
            "job",
            "status",
            "--coordinator",
            "https://coordinator.lan:8443",
            "--ca",
            "ca.pem",
            "--certificate",
            "operator.pem",
            "--private-key",
            "operator.key",
            "job-1",
            "--json",
        ])
        .unwrap();
        assert!(matches!(status.command, Command::Job(_)));

        let sla = Cli::try_parse_from([
            "crate-dependent-repos",
            "sla",
            "report",
            "observations.json",
            "--objective",
            "99.5",
        ])
        .unwrap();
        assert!(matches!(sla.command, Command::Sla(_)));
    }

    #[test]
    fn remote_jobs_reject_version_ranges_before_submission() {
        let result = Cli::try_parse_from([
            "crate-dependent-repos",
            "job",
            "submit",
            "--coordinator",
            "https://coordinator.lan:8443",
            "--ca",
            "ca.pem",
            "--certificate",
            "operator.pem",
            "--private-key",
            "operator.key",
            "--crate-name",
            "fs2",
            "--version",
            "^0.4",
            "--repositories",
            "repositories.txt",
        ]);
        assert!(result.is_err());
    }
}
