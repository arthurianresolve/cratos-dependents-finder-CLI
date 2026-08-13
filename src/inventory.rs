use std::{
    collections::{BTreeMap, HashSet},
    io::IsTerminal,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use futures::{StreamExt, stream};
use indicatif::{ProgressBar, ProgressStyle};
use semver::Version;
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::{
    cargo_evidence::ManifestEvidence,
    cli::{ActivityFilter, DependencyKind, Discovery, OptionalFilter, RequirementFilter},
    crates_io::{CratesIoClient, REVERSE_DEPENDENCY_SCOPE},
    github::{GitHubClient, GitHubTreeEntry},
    output::{write_csv, write_json},
    resolve::{ResolveOptions, resolve_target},
};

mod discovery;
mod projection;
mod repository;
use discovery::{
    CandidateGroup, ResolvedGroup, add_github_code_candidates, add_published_candidate,
    filter_candidate, resolve_repository_groups,
};
#[cfg(test)]
use discovery::{github_code_queries, repository_resolution_budget};
#[cfg(test)]
use projection::relation_confirms_dependency;
use projection::{
    LockEvidence, RepositoryEvidence, append_error, base_row, finalize_completeness, json_cell,
    project_lock_evidence, repository_row, repository_row_for_evidence, sanitize_row,
};
use repository::inspect_repository;

const REPOSITORY_MATCHED_FILE_LIMIT: usize = 2_000;
const REPOSITORY_MATCHED_FILE_BYTE_BUDGET: u64 = 128 * 1024 * 1024;
const REPOSITORY_RESOLUTION_OVERSCAN_FACTOR: usize = 4;

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub query: String,
    pub version: Version,
    pub explicit_crate: Option<String>,
    pub accept_closest: bool,
    pub requirement_filter: RequirementFilter,
    pub discovery: Discovery,
    pub dependency_kinds: Vec<DependencyKind>,
    pub optional: OptionalFilter,
    pub include_forks: bool,
    pub exclude_archived: bool,
    pub stale_after_days: u64,
    pub activity: ActivityFilter,
    pub committed_since: Option<NaiveDate>,
    pub committed_before: Option<NaiveDate>,
    pub max_candidates: Option<usize>,
    pub max_repositories: Option<usize>,
    pub github_search_limit: usize,
    pub max_file_bytes: u64,
    pub output: PathBuf,
    pub summary_json: Option<PathBuf>,
    pub allow_partial: bool,
    pub require_match: bool,
    pub jobs: usize,
}

#[derive(Clone, Debug)]
pub struct ScanOutcome {
    pub partial: bool,
    pub no_match: bool,
    pub allow_partial: bool,
    pub require_match: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanSummary {
    pub observed_at_utc: String,
    pub input_query: String,
    pub target_crate: String,
    pub target_version: String,
    pub globally_exhaustive: bool,
    pub candidate_scope: String,
    pub policy: ScanPolicy,
    pub candidate_limit_reached: bool,
    pub repository_limit_reached: bool,
    pub repository_resolution_budget_exhausted: bool,
    pub candidate_release_records: usize,
    pub candidate_crates: usize,
    pub candidate_repositories: usize,
    pub repositories_scanned: usize,
    pub repositories_filtered_by_activity: usize,
    pub repositories_filtered_as_forks: usize,
    pub repositories_filtered_as_archived: usize,
    pub repositories_filtered_as_private: usize,
    pub repositories_unsupported: usize,
    pub repositories_partial: usize,
    pub repositories_failed: usize,
    pub lockfiles_found: usize,
    pub lockfiles_parsed: usize,
    pub repositories_exact_confirmed: usize,
    pub exact_occurrences: usize,
    pub matched_cargo_files: usize,
    pub matched_cargo_file_bytes_downloaded: u64,
    pub repositories_file_limit_exceeded: usize,
    pub repositories_byte_budget_exceeded: usize,
    pub github_search_results_returned: usize,
    pub github_search_total_count: usize,
    pub github_search_incomplete: bool,
    pub github_search_private_results_discarded: usize,
    pub output_rows: usize,
    pub partial: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanPolicy {
    pub requirement_filter: String,
    pub discovery: String,
    pub dependency_kinds: Vec<String>,
    pub optional: String,
    pub include_forks: bool,
    pub exclude_archived: bool,
    pub stale_after_days: u64,
    pub activity: String,
    pub committed_since: Option<String>,
    pub committed_before: Option<String>,
    pub max_candidates: Option<usize>,
    pub max_repositories: Option<usize>,
    pub github_search_limit: usize,
    pub max_file_bytes: u64,
    pub repository_matched_file_limit: usize,
    pub repository_matched_file_byte_budget: u64,
    pub repository_byte_budget_priority: String,
    pub repository_resolution_overscan_factor: usize,
    pub jobs: usize,
    pub allow_partial: bool,
    pub require_match: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsvRow {
    pub observed_at_utc: String,
    pub input_query: String,
    pub target_crate: String,
    pub target_version: String,
    pub target_repository_url: String,
    pub globally_exhaustive: bool,
    pub candidate_scope: String,
    pub scan_policy_json: String,
    pub candidate_sources_json: String,
    pub dependent_crates_json: String,
    pub dependent_versions_json: String,
    pub published_requirements_json: String,
    pub dependency_kinds_json: String,
    pub dependency_targets_json: String,
    pub optional_declarations: String,
    pub published_direct_status: String,
    pub any_requirement_accepts: String,
    pub any_exact_pin: String,
    pub original_repository_urls_json: String,
    pub repository_url: String,
    pub github_repository_id: String,
    pub github_full_name: String,
    pub default_branch: String,
    pub head_sha: String,
    pub tree_sha: String,
    pub head_committed_at: String,
    pub repo_pushed_at: String,
    pub archived: String,
    pub fork: String,
    pub disabled: String,
    pub stale: String,
    pub inventory_status: String,
    pub tree_truncated: String,
    pub repository_matched_cargo_file_count: usize,
    pub repository_matched_file_limit: usize,
    pub repository_matched_file_bytes_downloaded: u64,
    pub repository_matched_file_byte_budget: u64,
    pub cargo_lock_path: String,
    pub cargo_lock_blob_sha: String,
    pub lock_status: String,
    pub resolved_target_versions_json: String,
    pub resolved_target_sources_json: String,
    pub exact_resolution_status: String,
    pub exact_occurrence_count: usize,
    pub exact_crates_io_occurrence_count: usize,
    pub manifest_paths_json: String,
    pub current_direct_status: String,
    pub current_direct_requirements_json: String,
    pub msrv_effective: String,
    pub msrv_source: String,
    pub msrv_observations_json: String,
    pub os_observed_targets_json: String,
    pub os_has_unconditional_declaration: String,
    pub recorded_relation: String,
    pub shortest_dependency_depth: String,
    pub evidence_completeness: String,
    pub error_code: String,
    pub error_message: String,
}

impl CsvRow {
    pub const HEADERS: &'static [&'static str] = &[
        "observed_at_utc",
        "input_query",
        "target_crate",
        "target_version",
        "target_repository_url",
        "globally_exhaustive",
        "candidate_scope",
        "scan_policy_json",
        "candidate_sources_json",
        "dependent_crates_json",
        "dependent_versions_json",
        "published_requirements_json",
        "dependency_kinds_json",
        "dependency_targets_json",
        "optional_declarations",
        "published_direct_status",
        "any_requirement_accepts",
        "any_exact_pin",
        "original_repository_urls_json",
        "repository_url",
        "github_repository_id",
        "github_full_name",
        "default_branch",
        "head_sha",
        "tree_sha",
        "head_committed_at",
        "repo_pushed_at",
        "archived",
        "fork",
        "disabled",
        "stale",
        "inventory_status",
        "tree_truncated",
        "repository_matched_cargo_file_count",
        "repository_matched_file_limit",
        "repository_matched_file_bytes_downloaded",
        "repository_matched_file_byte_budget",
        "cargo_lock_path",
        "cargo_lock_blob_sha",
        "lock_status",
        "resolved_target_versions_json",
        "resolved_target_sources_json",
        "exact_resolution_status",
        "exact_occurrence_count",
        "exact_crates_io_occurrence_count",
        "manifest_paths_json",
        "current_direct_status",
        "current_direct_requirements_json",
        "msrv_effective",
        "msrv_source",
        "msrv_observations_json",
        "os_observed_targets_json",
        "os_has_unconditional_declaration",
        "recorded_relation",
        "shortest_dependency_depth",
        "evidence_completeness",
        "error_code",
        "error_message",
    ];
}

#[derive(Clone, Debug)]
struct RunContext {
    observed_at: DateTime<Utc>,
    input_query: String,
    target_crate: String,
    target_version: Version,
    target_repository_url: Option<String>,
    globally_exhaustive: bool,
    candidate_scope: String,
    scan_policy_json: String,
}

#[derive(Debug, Default)]
struct InspectionResult {
    rows: Vec<CsvRow>,
    scanned: usize,
    filtered_activity: usize,
    filtered_fork: usize,
    filtered_archived: usize,
    partial_repositories: usize,
    failed_repositories: usize,
    lockfiles_found: usize,
    lockfiles_parsed: usize,
    exact_occurrences: usize,
    exact_confirmed_repositories: usize,
    matched_cargo_files: usize,
    matched_cargo_file_bytes_downloaded: u64,
    file_limit_exceeded: usize,
    byte_budget_exceeded: usize,
}

impl InspectionResult {
    fn absorb(&mut self, other: Self) {
        self.rows.extend(other.rows);
        self.scanned += other.scanned;
        self.filtered_activity += other.filtered_activity;
        self.filtered_fork += other.filtered_fork;
        self.filtered_archived += other.filtered_archived;
        self.partial_repositories += other.partial_repositories;
        self.failed_repositories += other.failed_repositories;
        self.lockfiles_found += other.lockfiles_found;
        self.lockfiles_parsed += other.lockfiles_parsed;
        self.exact_occurrences += other.exact_occurrences;
        self.exact_confirmed_repositories += other.exact_confirmed_repositories;
        self.matched_cargo_files += other.matched_cargo_files;
        self.matched_cargo_file_bytes_downloaded += other.matched_cargo_file_bytes_downloaded;
        self.file_limit_exceeded += other.file_limit_exceeded;
        self.byte_budget_exceeded += other.byte_budget_exceeded;
    }
}

/// Owns scan-phase rows and counters so each phase updates accounting in one
/// place. Inspection results are absorbed by move; request scheduling and row
/// ordering stay unchanged.
#[derive(Debug)]
struct ScanAccumulator {
    summary: ScanSummary,
    rows: Vec<CsvRow>,
}

impl ScanAccumulator {
    fn new(summary: ScanSummary) -> Self {
        Self {
            summary,
            rows: Vec::new(),
        }
    }

    fn record_unsupported(&mut self, context: &RunContext, group: &CandidateGroup) {
        self.summary.repositories_unsupported += 1;
        self.summary.partial = true;
        let mut row = base_row(context, group);
        row.inventory_status = "unsupported_repository".to_owned();
        row.lock_status = "not_scanned".to_owned();
        row.exact_resolution_status = "unknown".to_owned();
        row.current_direct_status = "unknown".to_owned();
        row.recorded_relation = "unknown".to_owned();
        row.evidence_completeness = "unavailable".to_owned();
        row.error_code = "unsupported_repository".to_owned();
        row.error_message = group
            .unsupported_reason
            .clone()
            .unwrap_or_else(|| "candidate has no GitHub repository URL".to_owned());
        self.rows.push(sanitize_row(row));
    }

    fn record_resolution_failure(
        &mut self,
        context: &RunContext,
        group: &CandidateGroup,
        error: &anyhow::Error,
    ) {
        self.summary.repositories_failed += 1;
        self.summary.partial = true;
        let mut row = base_row(context, group);
        row.inventory_status = "failed".to_owned();
        row.lock_status = "not_scanned".to_owned();
        row.exact_resolution_status = "unknown".to_owned();
        row.current_direct_status = "unknown".to_owned();
        row.recorded_relation = "unknown".to_owned();
        row.evidence_completeness = "failed".to_owned();
        row.error_code = "repository_resolution_failed".to_owned();
        row.error_message = format!("{error:#}");
        self.rows.push(sanitize_row(row));
    }

    fn absorb_inspection(&mut self, aggregate: InspectionResult) {
        self.summary.repositories_scanned = aggregate.scanned;
        self.summary.repositories_filtered_by_activity = aggregate.filtered_activity;
        self.summary.repositories_filtered_as_forks = aggregate.filtered_fork;
        self.summary.repositories_filtered_as_archived = aggregate.filtered_archived;
        self.summary.repositories_partial += aggregate.partial_repositories;
        self.summary.repositories_failed += aggregate.failed_repositories;
        self.summary.lockfiles_found = aggregate.lockfiles_found;
        self.summary.lockfiles_parsed = aggregate.lockfiles_parsed;
        self.summary.exact_occurrences = aggregate.exact_occurrences;
        self.summary.matched_cargo_files = aggregate.matched_cargo_files;
        self.summary.matched_cargo_file_bytes_downloaded =
            aggregate.matched_cargo_file_bytes_downloaded;
        self.summary.repositories_file_limit_exceeded = aggregate.file_limit_exceeded;
        self.summary.repositories_byte_budget_exceeded = aggregate.byte_budget_exceeded;
        self.summary.repositories_exact_confirmed = aggregate.exact_confirmed_repositories;
        self.summary.partial |= self.summary.repositories_partial > 0
            || self.summary.repositories_failed > 0
            || self.summary.repository_resolution_budget_exhausted
            || self.summary.github_search_incomplete;
        self.rows.extend(aggregate.rows);
    }

    fn finish(mut self) -> (ScanSummary, Vec<CsvRow>) {
        self.rows.sort_by(|left, right| {
            (
                &left.github_full_name,
                &left.repository_url,
                &left.cargo_lock_path,
            )
                .cmp(&(
                    &right.github_full_name,
                    &right.repository_url,
                    &right.cargo_lock_path,
                ))
        });
        self.summary.output_rows = self.rows.len();
        (self.summary, self.rows)
    }
}

#[derive(Debug)]
struct ManifestScan {
    evidence: ManifestEvidence,
    paths: Vec<String>,
    complete: bool,
    diagnostics: Vec<String>,
}

struct ManifestScanConfig<'a> {
    selected_count: usize,
    target_crate: &'a str,
    target_version: &'a Version,
    max_file_bytes: u64,
    tree_complete: bool,
    byte_ceiling: u64,
    request_permits: &'a Semaphore,
    max_in_flight: usize,
}

#[derive(Debug)]
struct RepositoryByteBudget {
    limit: u64,
    consumed: u64,
    limit_hit: bool,
}

impl RepositoryByteBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            consumed: 0,
            limit_hit: false,
        }
    }

    fn remaining_below(&self, ceiling: u64) -> u64 {
        ceiling.saturating_sub(self.consumed)
    }

    fn can_fetch_below(&mut self, declared_size: Option<u64>, ceiling: u64) -> bool {
        let remaining = self.remaining_below(ceiling.min(self.limit));
        if declared_size.is_some_and(|size| size <= remaining) {
            return true;
        }
        if declared_size.is_none() && remaining > 0 {
            return true;
        }
        self.limit_hit = true;
        false
    }

    fn record(&mut self, bytes: usize) {
        self.consumed = self.consumed.saturating_add(bytes as u64);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivityDecision {
    Keep { stale: bool },
    Filter,
}

fn activity_decision(
    committed_at: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    stale_after_days: u64,
    filter: ActivityFilter,
    committed_since: Option<NaiveDate>,
    committed_before: Option<NaiveDate>,
) -> ActivityDecision {
    if committed_since.is_some_and(|cutoff| committed_at.date_naive() < cutoff)
        || committed_before.is_some_and(|cutoff| committed_at.date_naive() >= cutoff)
    {
        return ActivityDecision::Filter;
    }

    let threshold_seconds = stale_after_days.saturating_mul(24 * 60 * 60);
    let age_seconds = observed_at
        .signed_duration_since(committed_at)
        .num_seconds()
        .max(0) as u64;
    let stale = age_seconds >= threshold_seconds;
    let keep = match filter {
        ActivityFilter::All => true,
        ActivityFilter::Active => !stale,
        ActivityFilter::Stale => stale,
    };
    if keep {
        ActivityDecision::Keep { stale }
    } else {
        ActivityDecision::Filter
    }
}

fn candidate_scope(discovery: Discovery) -> String {
    match discovery {
        Discovery::CratesIo => REVERSE_DEPENDENCY_SCOPE.to_owned(),
        Discovery::GithubCode => {
            "bounded public GitHub REST code-search seeds verified against current default branches"
                .to_owned()
        }
        Discovery::Both => {
            format!("{REVERSE_DEPENDENCY_SCOPE}, plus bounded public GitHub REST code-search seeds")
        }
    }
}

fn scan_policy(options: &ScanOptions) -> ScanPolicy {
    ScanPolicy {
        requirement_filter: requirement_filter_name(options.requirement_filter).to_owned(),
        discovery: discovery_name(options.discovery).to_owned(),
        dependency_kinds: options
            .dependency_kinds
            .iter()
            .map(|kind| dependency_kind_name(*kind).to_owned())
            .collect(),
        optional: optional_filter_name(options.optional).to_owned(),
        include_forks: options.include_forks,
        exclude_archived: options.exclude_archived,
        stale_after_days: options.stale_after_days,
        activity: activity_filter_name(options.activity).to_owned(),
        committed_since: options.committed_since.map(|date| date.to_string()),
        committed_before: options.committed_before.map(|date| date.to_string()),
        max_candidates: options.max_candidates,
        max_repositories: options.max_repositories,
        github_search_limit: options.github_search_limit,
        max_file_bytes: options.max_file_bytes,
        repository_matched_file_limit: REPOSITORY_MATCHED_FILE_LIMIT,
        repository_matched_file_byte_budget: REPOSITORY_MATCHED_FILE_BYTE_BUDGET,
        repository_byte_budget_priority: "Cargo.lock before Cargo.toml".to_owned(),
        repository_resolution_overscan_factor: REPOSITORY_RESOLUTION_OVERSCAN_FACTOR,
        jobs: options.jobs,
        allow_partial: options.allow_partial,
        require_match: options.require_match,
    }
}

fn requirement_filter_name(filter: RequirementFilter) -> &'static str {
    match filter {
        RequirementFilter::Any => "any",
        RequirementFilter::Accepts => "accepts",
        RequirementFilter::Exact => "exact",
    }
}

fn discovery_name(discovery: Discovery) -> &'static str {
    match discovery {
        Discovery::CratesIo => "crates-io",
        Discovery::GithubCode => "github-code",
        Discovery::Both => "both",
    }
}

fn dependency_kind_name(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Normal => "normal",
        DependencyKind::Build => "build",
        DependencyKind::Dev => "dev",
    }
}

fn optional_filter_name(filter: OptionalFilter) -> &'static str {
    match filter {
        OptionalFilter::Include => "include",
        OptionalFilter::Exclude => "exclude",
        OptionalFilter::Only => "only",
    }
}

fn activity_filter_name(filter: ActivityFilter) -> &'static str {
    match filter {
        ActivityFilter::All => "all",
        ActivityFilter::Active => "active",
        ActivityFilter::Stale => "stale",
    }
}

fn lexical_output_identity(path: &Path) -> Result<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("determining current directory for output validation")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        use std::path::Component;
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(part) => normalized.push(part),
        }
    }
    let identity = normalized.to_string_lossy().into_owned();
    #[cfg(windows)]
    let identity = identity.to_ascii_lowercase();
    Ok(identity)
}

fn output_paths_conflict(output: &Path, summary: &Path) -> Result<bool> {
    if output == Path::new("-") || summary == Path::new("-") {
        return Ok(false);
    }
    Ok(lexical_output_identity(output)? == lexical_output_identity(summary)?)
}

pub async fn scan(
    crates_io: &CratesIoClient,
    github: &GitHubClient,
    options: ScanOptions,
) -> Result<ScanOutcome> {
    if options.jobs == 0 {
        bail!("--jobs must be at least 1");
    }
    if options.summary_json.as_deref() == Some(Path::new("-")) {
        bail!("--summary-json requires a file path; '-' would corrupt CSV stdout");
    }
    if let Some(summary_path) = options.summary_json.as_deref()
        && output_paths_conflict(&options.output, summary_path)?
    {
        bail!("--output and --summary-json must refer to different files");
    }

    let observed_at = Utc::now();
    let candidate_scope = candidate_scope(options.discovery);
    let policy = scan_policy(&options);
    let policy_json = json_cell(&policy);
    let resolution = resolve_target(
        crates_io,
        github,
        &options.query,
        ResolveOptions {
            limit: 20,
            explicit_crate: options.explicit_crate.clone(),
            accept_closest: options.accept_closest,
        },
    )
    .await?;
    let target_crate = resolution.selected_name()?.to_owned();
    let context = RunContext {
        observed_at,
        input_query: options.query.clone(),
        target_crate: target_crate.clone(),
        target_version: options.version.clone(),
        target_repository_url: resolution.repository().map(str::to_owned),
        globally_exhaustive: false,
        candidate_scope: candidate_scope.clone(),
        scan_policy_json: policy_json,
    };

    let summary = ScanSummary {
        observed_at_utc: observed_at.to_rfc3339(),
        input_query: options.query.clone(),
        target_crate: target_crate.clone(),
        target_version: options.version.to_string(),
        globally_exhaustive: false,
        candidate_scope,
        policy,
        notes: vec![
            "GitHub code search and dependents data are bounded and non-exhaustive.".to_owned(),
            "A lock entry records a resolution; it does not prove a feature/target-specific build or runtime use.".to_owned(),
            "An exact dependency confirmation requires a direct or transitive path from a recorded lock-graph root; unclassified presence is retained but not confirmed.".to_owned(),
        ],
        ..ScanSummary::default()
    };
    let mut accounting = ScanAccumulator::new(summary);

    let mut groups = BTreeMap::<String, CandidateGroup>::new();
    let mut candidate_crates = HashSet::new();
    if matches!(options.discovery, Discovery::CratesIo | Discovery::Both) {
        let candidates = crates_io
            .reverse_dependencies_limited(&target_crate, options.max_candidates)
            .await?;
        accounting.summary.candidate_limit_reached = options
            .max_candidates
            .is_some_and(|maximum| candidates.len() >= maximum);
        for candidate in candidates {
            if let Some(candidate) = filter_candidate(candidate, &options) {
                accounting.summary.candidate_release_records += 1;
                candidate_crates.insert(candidate.dependent_name.clone());
                add_published_candidate(&mut groups, candidate);
            }
        }
    }

    accounting.summary.candidate_crates = candidate_crates.len();

    if matches!(options.discovery, Discovery::GithubCode | Discovery::Both) {
        add_github_code_candidates(
            github,
            &target_crate,
            &options.version,
            options.github_search_limit,
            &mut groups,
            &mut accounting.summary,
        )
        .await?;
    }

    accounting.summary.candidate_repositories = groups.len();

    let mut github_groups = Vec::new();
    for group in groups.into_values() {
        if group.repository_hint.is_some() {
            github_groups.push(group);
        } else {
            accounting.record_unsupported(&context, &group);
        }
    }

    let resolution = resolve_repository_groups(
        github,
        github_groups,
        options.jobs,
        options.max_repositories,
    )
    .await;
    accounting.summary.repositories_filtered_as_private = resolution.filtered_private;
    accounting.summary.repository_limit_reached = resolution.limit_reached;
    accounting.summary.repository_resolution_budget_exhausted = resolution.budget_exhausted;
    if resolution.budget_exhausted {
        accounting.summary.notes.push(format!(
            "repository resolution stopped after the bounded {}x redirect/private overscan budget before filling --max-repositories",
            REPOSITORY_RESOLUTION_OVERSCAN_FACTOR
        ));
    }
    for (group, error) in resolution.failures {
        accounting.record_resolution_failure(&context, &group, &error);
    }

    let github_requests = Arc::new(Semaphore::new(options.jobs));
    let progress = if std::io::stderr().is_terminal() {
        let progress = ProgressBar::new(resolution.resolved.len() as u64);
        let style = ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} repos {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar());
        progress.set_style(style);
        progress
    } else {
        ProgressBar::hidden()
    };
    let work = resolution.resolved.into_iter().map(|resolved| {
        let client = github.clone();
        let context = context.clone();
        let options = options.clone();
        let requests = Arc::clone(&github_requests);
        let repository_name = resolved.repository.full_name.clone();
        async move {
            (
                repository_name,
                inspect_repository(&client, &context, resolved, &options, &requests).await,
            )
        }
    });
    let mut inspections = stream::iter(work).buffer_unordered(options.jobs);
    let mut aggregate = InspectionResult::default();
    while let Some((repository_name, inspection)) = inspections.next().await {
        progress.set_message(repository_name);
        progress.inc(1);
        aggregate.absorb(inspection);
    }
    progress.finish_with_message("scan complete");
    accounting.absorb_inspection(aggregate);
    let (summary, rows) = accounting.finish();

    write_csv(&options.output, CsvRow::HEADERS, &rows)?;
    if let Some(path) = &options.summary_json {
        write_json(path, &summary)?;
    }
    eprintln!(
        "scanned {} repositories; parsed {} lockfiles; confirmed {} repositories; partial={}",
        summary.repositories_scanned,
        summary.lockfiles_parsed,
        summary.repositories_exact_confirmed,
        summary.partial
    );

    Ok(ScanOutcome {
        partial: summary.partial,
        no_match: summary.repositories_exact_confirmed == 0,
        allow_partial: options.allow_partial,
        require_match: options.require_match,
    })
}

fn reserved_lock_bytes(
    entries: &[GitHubTreeEntry],
    selected_count: usize,
    max_file_bytes: u64,
    repository_budget: u64,
) -> u64 {
    entries
        .iter()
        .take(selected_count)
        .filter(|entry| entry.mode != "120000")
        .filter(|entry| !entry.size.is_some_and(|size| size > max_file_bytes))
        .map(|entry| entry.size.unwrap_or(max_file_bytes))
        .fold(0u64, u64::saturating_add)
        .min(repository_budget)
}

fn final_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    use super::repository::{CargoBlobFetch, CargoBlobFetchConfig, fetch_cargo_blobs};
    use super::*;
    use crate::{
        cargo_evidence::RecordedRelation,
        crates_io::{DependencyDeclaration, RepresentativeDependency, ReverseDependencyCandidate},
        github::GitHubRepo,
    };

    fn scan_options(requirement_filter: RequirementFilter) -> ScanOptions {
        ScanOptions {
            query: "fs2".to_owned(),
            version: Version::parse("0.4.3").unwrap(),
            explicit_crate: None,
            accept_closest: false,
            requirement_filter,
            discovery: Discovery::CratesIo,
            dependency_kinds: vec![
                DependencyKind::Normal,
                DependencyKind::Build,
                DependencyKind::Dev,
            ],
            optional: OptionalFilter::Include,
            include_forks: false,
            exclude_archived: false,
            stale_after_days: 365,
            activity: ActivityFilter::All,
            committed_since: None,
            committed_before: None,
            max_candidates: None,
            max_repositories: None,
            github_search_limit: 100,
            max_file_bytes: 10 * 1024 * 1024,
            output: PathBuf::from("-"),
            summary_json: None,
            allow_partial: false,
            require_match: false,
            jobs: 1,
        }
    }

    fn reverse_candidate(
        requirement: &str,
        kind: &str,
        optional: bool,
        enrichment_error: Option<&str>,
    ) -> ReverseDependencyCandidate {
        ReverseDependencyCandidate {
            version_id: 10,
            dependent_name: "consumer".to_owned(),
            dependent_version: "1.0.0".to_owned(),
            dependent_yanked: false,
            repository: Some("https://github.com/example/consumer".to_owned()),
            dependent_downloads: 100,
            representative: RepresentativeDependency {
                id: 1,
                version_id: 10,
                crate_id: "fs2".to_owned(),
                req: requirement.to_owned(),
                optional,
                default_features: true,
                features: Vec::new(),
                target: None,
                kind: kind.to_owned(),
                downloads: 100,
            },
            declarations: vec![DependencyDeclaration {
                dependency_name: "fs2".to_owned(),
                package_name: "fs2".to_owned(),
                req: requirement.to_owned(),
                kind: kind.to_owned(),
                optional,
                target: None,
                registry: None,
            }],
            declaration_enrichment_error: enrichment_error.map(str::to_owned),
        }
    }

    fn tree_entry(path: &str, mode: &str, size: Option<u64>) -> GitHubTreeEntry {
        GitHubTreeEntry {
            path: path.to_owned(),
            mode: mode.to_owned(),
            kind: "blob".to_owned(),
            sha: format!("sha-{path}"),
            size,
            url: None,
        }
    }

    #[test]
    fn activity_cutoffs_are_inclusive_since_and_exclusive_before() {
        let observed = Utc.with_ymd_and_hms(2026, 8, 9, 0, 0, 0).unwrap();
        let committed = Utc.with_ymd_and_hms(2024, 1, 1, 23, 59, 0).unwrap();
        assert_eq!(
            activity_decision(
                committed,
                observed,
                365,
                ActivityFilter::All,
                Some(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap()),
                Some(NaiveDate::from_ymd_opt(2024, 1, 2).unwrap()),
            ),
            ActivityDecision::Keep { stale: true }
        );
        assert_eq!(
            activity_decision(
                committed,
                observed,
                365,
                ActivityFilter::All,
                None,
                Some(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap()),
            ),
            ActivityDecision::Filter
        );
    }

    #[test]
    fn activity_class_filter_uses_default_branch_commit_age() {
        let observed = Utc.with_ymd_and_hms(2026, 8, 9, 0, 0, 0).unwrap();
        let committed = Utc.with_ymd_and_hms(2025, 8, 8, 0, 0, 0).unwrap();
        assert_eq!(
            activity_decision(committed, observed, 365, ActivityFilter::Stale, None, None,),
            ActivityDecision::Keep { stale: true }
        );
        assert_eq!(
            activity_decision(committed, observed, 365, ActivityFilter::Active, None, None,),
            ActivityDecision::Filter
        );
    }

    #[test]
    fn requirement_filters_distinguish_caret_acceptance_and_exact_pins() {
        assert!(
            filter_candidate(
                reverse_candidate("^0.4.3", "normal", false, None),
                &scan_options(RequirementFilter::Accepts),
            )
            .is_some()
        );
        assert!(
            filter_candidate(
                reverse_candidate("^0.4.3", "normal", false, None),
                &scan_options(RequirementFilter::Exact),
            )
            .is_none()
        );
        assert!(
            filter_candidate(
                reverse_candidate("=0.4.3", "normal", false, None),
                &scan_options(RequirementFilter::Exact),
            )
            .is_some()
        );
    }

    #[test]
    fn unknown_enrichment_is_retained_instead_of_becoming_a_false_negative() {
        let candidate = filter_candidate(
            reverse_candidate("^0.5", "normal", false, Some("index unavailable")),
            &scan_options(RequirementFilter::Exact),
        )
        .unwrap();
        let mut group = CandidateGroup::default();
        group.published.push(candidate);
        let context = RunContext {
            observed_at: Utc::now(),
            input_query: "fs2".to_owned(),
            target_crate: "fs2".to_owned(),
            target_version: Version::parse("0.4.3").unwrap(),
            target_repository_url: None,
            globally_exhaustive: false,
            candidate_scope: "test scope".to_owned(),
            scan_policy_json: "{}".to_owned(),
        };
        let row = base_row(&context, &group);
        assert_eq!(row.any_requirement_accepts, "unknown");
        assert_eq!(row.any_exact_pin, "unknown");
        assert!(!row.globally_exhaustive);
        assert_eq!(row.candidate_scope, "test scope");
    }

    #[test]
    fn unknown_enrichment_survives_kind_and_optional_filters() {
        let mut options = scan_options(RequirementFilter::Exact);
        options.dependency_kinds = vec![DependencyKind::Normal];
        options.optional = OptionalFilter::Exclude;
        let candidate = filter_candidate(
            reverse_candidate("^0.5", "build", true, Some("index unavailable")),
            &options,
        )
        .expect("unknown declarations must not become a false negative");
        assert!(candidate.declarations.is_empty());

        let mut group = CandidateGroup::default();
        group.published.push(candidate);
        let context = RunContext {
            observed_at: Utc::now(),
            input_query: "fs2".to_owned(),
            target_crate: "fs2".to_owned(),
            target_version: Version::parse("0.4.3").unwrap(),
            target_repository_url: None,
            globally_exhaustive: false,
            candidate_scope: "test scope".to_owned(),
            scan_policy_json: "{}".to_owned(),
        };
        let row = base_row(&context, &group);
        assert_eq!(row.any_requirement_accepts, "unknown");
        assert_eq!(row.any_exact_pin, "unknown");
        assert_eq!(row.optional_declarations, "unknown");
    }

    #[test]
    fn optional_and_kind_filters_are_applied_before_requirement_matching() {
        let mut options = scan_options(RequirementFilter::Accepts);
        options.dependency_kinds = vec![DependencyKind::Normal];
        options.optional = OptionalFilter::Exclude;
        assert!(
            filter_candidate(reverse_candidate("^0.4.3", "build", false, None), &options,)
                .is_none()
        );
        assert!(
            filter_candidate(reverse_candidate("^0.4.3", "normal", true, None), &options,)
                .is_none()
        );
    }

    #[test]
    fn cargo_file_names_are_exact_not_suffix_matches() {
        assert_eq!(final_component("nested/Cargo.lock"), "Cargo.lock");
        assert_ne!(final_component("nested/Cargo.lock.bak"), "Cargo.lock");
        assert_ne!(final_component("Cargo.toml.example"), "Cargo.toml");
    }

    #[test]
    fn output_paths_are_compared_lexically_before_writing() {
        assert!(
            output_paths_conflict(
                Path::new("inventory.csv"),
                Path::new("nested/../inventory.csv")
            )
            .unwrap()
        );
        assert!(
            !output_paths_conflict(Path::new("inventory.csv"), Path::new("summary.json")).unwrap()
        );
        assert!(!output_paths_conflict(Path::new("-"), Path::new("./-")).unwrap());
    }

    #[test]
    fn code_search_seeds_are_explicitly_public() {
        for (query, _, _) in github_code_queries("fs2", &Version::parse("0.4.3").unwrap()) {
            assert!(query.contains("is:public"));
        }
    }

    #[tokio::test]
    async fn supplemental_code_search_failures_preserve_other_candidates() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search/code"))
            .and(query_param("q", "fs2 0.4.3 filename:Cargo.lock is:public"))
            .respond_with(ResponseTemplate::new(422))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/search/code"))
            .and(query_param("q", "fs2 filename:Cargo.toml is:public"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_count": 0,
                "incomplete_results": false,
                "items": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let github = GitHubClient::with_api_base(
            Some("test-token".to_owned()),
            Url::parse(&format!("{}/", server.uri())).unwrap(),
        )
        .unwrap();
        let mut groups = BTreeMap::from([("existing".to_owned(), CandidateGroup::default())]);
        let mut summary = ScanSummary::default();

        add_github_code_candidates(
            &github,
            "fs2",
            &Version::parse("0.4.3").unwrap(),
            10,
            &mut groups,
            &mut summary,
        )
        .await
        .unwrap();

        assert!(groups.contains_key("existing"));
        assert!(summary.github_search_incomplete);
        assert!(summary.partial);
        assert!(
            summary
                .notes
                .iter()
                .any(|note| note.contains("github_rest_code_search_lock_seed"))
        );
        server.verify().await;
    }

    #[test]
    fn unclassified_presence_is_not_an_exact_dependency_confirmation() {
        assert!(relation_confirms_dependency(RecordedRelation::Direct));
        assert!(relation_confirms_dependency(RecordedRelation::Transitive));
        assert!(relation_confirms_dependency(
            RecordedRelation::DirectAndTransitive
        ));
        assert!(!relation_confirms_dependency(
            RecordedRelation::PresentUnclassified
        ));
    }

    #[test]
    fn repository_resolution_overscan_is_bounded_for_small_limits() {
        assert_eq!(repository_resolution_budget(10_000, Some(1)), 4);
        assert_eq!(repository_resolution_budget(10_000, Some(10)), 40);
        assert_eq!(repository_resolution_budget(3, Some(10)), 3);
        assert_eq!(repository_resolution_budget(3, None), 3);
    }

    #[test]
    fn lock_byte_reservation_prioritizes_selected_lockfiles() {
        let entries = vec![
            tree_entry("one/Cargo.lock", "100644", Some(5)),
            tree_entry("two/Cargo.lock", "100644", None),
            tree_entry("large/Cargo.lock", "100644", Some(11)),
            tree_entry("linked/Cargo.lock", "120000", Some(4)),
        ];
        assert_eq!(reserved_lock_bytes(&entries, 4, 10, 100), 15);
        assert_eq!(reserved_lock_bytes(&entries, 1, 10, 100), 5);
    }

    #[test]
    fn cumulative_byte_budget_records_partial_ceiling_hits() {
        let mut budget = RepositoryByteBudget::new(100);
        assert!(budget.can_fetch_below(Some(40), 60));
        budget.record(40);
        assert!(!budget.can_fetch_below(Some(30), 60));
        assert!(budget.limit_hit);
        assert_eq!(budget.remaining_below(budget.limit), 60);
    }

    #[tokio::test]
    async fn failed_blob_fetch_releases_budget_for_the_next_file() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/git/blobs/first"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/git/blobs/second"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"second"))
            .expect(1)
            .mount(&server)
            .await;
        let github =
            GitHubClient::with_api_base(None, Url::parse(&format!("{}/", server.uri())).unwrap())
                .unwrap();
        let repo = GitHubRepo::new("acme", "widget").unwrap();
        let mut first = tree_entry("first/Cargo.lock", "100644", Some(6));
        first.sha = "first".to_owned();
        let mut second = tree_entry("second/Cargo.lock", "100644", Some(6));
        second.sha = "second".to_owned();
        let entries = vec![first, second];
        let mut budget = RepositoryByteBudget::new(6);
        let permits = Semaphore::new(2);

        let outcomes = fetch_cargo_blobs(
            &github,
            &repo,
            &entries,
            &mut budget,
            CargoBlobFetchConfig {
                selected_count: 2,
                max_file_bytes: 10,
                byte_ceiling: 6,
                request_permits: &permits,
                max_in_flight: 2,
            },
        )
        .await;

        assert!(matches!(&outcomes[0], CargoBlobFetch::Failed(_)));
        assert!(matches!(
            &outcomes[1],
            CargoBlobFetch::Fetched(bytes) if bytes == b"second"
        ));
        assert_eq!(budget.consumed, 6);
        assert!(!budget.limit_hit);
        server.verify().await;
    }

    #[test]
    fn scan_policy_records_filters_and_repository_safety_caps() {
        let mut options = scan_options(RequirementFilter::Exact);
        options.stale_after_days = 730;
        options.max_candidates = Some(50);
        options.max_repositories = Some(10);
        let policy = scan_policy(&options);
        assert_eq!(policy.requirement_filter, "exact");
        assert_eq!(policy.stale_after_days, 730);
        assert_eq!(policy.max_candidates, Some(50));
        assert_eq!(policy.max_repositories, Some(10));
        assert_eq!(
            policy.repository_matched_file_byte_budget,
            REPOSITORY_MATCHED_FILE_BYTE_BUDGET
        );
        assert!(CsvRow::HEADERS.contains(&"globally_exhaustive"));
        assert!(CsvRow::HEADERS.contains(&"candidate_scope"));
        assert!(CsvRow::HEADERS.contains(&"scan_policy_json"));
    }
}
