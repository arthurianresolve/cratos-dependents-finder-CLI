use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{
    crates_io::CratesIoClient,
    github::GitHubClient,
    inventory::{ScanOptions, scan},
    links::build_links,
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

    /// Return success even when some repository evidence is partial or failed.
    #[arg(long)]
    allow_partial: bool,

    /// Return a non-zero exit when no exact lockfile match is confirmed.
    #[arg(long)]
    require_match: bool,
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
    let github_token = std::env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GH_TOKEN").ok());
    let crates_io = CratesIoClient::new()?;
    let github = GitHubClient::new(github_token)?;

    match cli.command {
        Command::Resolve(args) => {
            let result = resolve_target(
                &crates_io,
                &github,
                &args.query,
                ResolveOptions {
                    limit: args.limit,
                    explicit_crate: None,
                    accept_closest: false,
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
            let outcome = scan(&crates_io, &github, args.into_options(cli.jobs)).await?;
            if outcome.partial && !outcome.allow_partial {
                std::process::exit(PARTIAL_RESULTS_EXIT_CODE);
            }
            if outcome.no_match && outcome.require_match {
                std::process::exit(REQUIRED_MATCH_NOT_FOUND_EXIT_CODE);
            }
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
    fn into_options(self, jobs: usize) -> ScanOptions {
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
            allow_partial: self.allow_partial,
            require_match: self.require_match,
            jobs,
        }
    }
}
