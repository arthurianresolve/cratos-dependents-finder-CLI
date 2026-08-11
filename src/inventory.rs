use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use futures::{StreamExt, stream};
use semver::Version;
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::{
    cargo_evidence::{
        ManifestEvidence, RecordedRelation, analyze_cargo_lock, analyze_cargo_manifests,
        evaluate_cargo_requirement,
    },
    cli::{ActivityFilter, DependencyKind, Discovery, OptionalFilter, RequirementFilter},
    crates_io::{
        CratesIoClient, DependencyDeclaration, REVERSE_DEPENDENCY_SCOPE, ReverseDependencyCandidate,
    },
    github::{
        GitHubClient, GitHubHead, GitHubRepo, GitHubRepository, GitHubTreeEntry, parse_github_repo,
    },
    output::{csv_safe, write_csv, write_json},
    resolve::{ResolveOptions, resolve_target},
};

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

#[derive(Clone, Debug, Default)]
struct CandidateGroup {
    repository_hint: Option<GitHubRepo>,
    original_repository_urls: BTreeSet<String>,
    sources: BTreeSet<String>,
    published: Vec<ReverseDependencyCandidate>,
    unsupported_reason: Option<String>,
}

impl CandidateGroup {
    fn merge(&mut self, other: Self) {
        self.repository_hint = self.repository_hint.take().or(other.repository_hint);
        self.original_repository_urls
            .extend(other.original_repository_urls);
        self.sources.extend(other.sources);
        self.published.extend(other.published);
        self.unsupported_reason = self.unsupported_reason.take().or(other.unsupported_reason);
    }
}

#[derive(Clone, Debug)]
struct ResolvedGroup {
    group: CandidateGroup,
    repository: GitHubRepository,
}

#[derive(Debug, Default)]
struct RepositoryResolution {
    resolved: Vec<ResolvedGroup>,
    failures: Vec<(CandidateGroup, anyhow::Error)>,
    filtered_private: usize,
    limit_reached: bool,
    budget_exhausted: bool,
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

#[derive(Clone, Debug, Serialize)]
struct PublishedDeclarationCell {
    dependent_crate: String,
    dependent_version: String,
    dependent_version_id: u64,
    dependent_downloads: u64,
    dependency_alias: String,
    dependency_package: String,
    requirement: String,
    kind: String,
    optional: bool,
    target: Option<String>,
    registry: Option<String>,
    enrichment_error: Option<String>,
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

    let mut summary = ScanSummary {
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

    let mut groups = BTreeMap::<String, CandidateGroup>::new();
    let mut candidate_crates = HashSet::new();
    if matches!(options.discovery, Discovery::CratesIo | Discovery::Both) {
        let candidates = crates_io
            .reverse_dependencies_limited(&target_crate, options.max_candidates)
            .await?;
        summary.candidate_limit_reached = options
            .max_candidates
            .is_some_and(|maximum| candidates.len() >= maximum);
        for candidate in candidates {
            if let Some(candidate) = filter_candidate(candidate, &options) {
                summary.candidate_release_records += 1;
                candidate_crates.insert(candidate.dependent_name.clone());
                add_published_candidate(&mut groups, candidate);
            }
        }
    }

    summary.candidate_crates = candidate_crates.len();

    if matches!(options.discovery, Discovery::GithubCode | Discovery::Both) {
        add_github_code_candidates(
            github,
            &target_crate,
            &options.version,
            options.github_search_limit,
            &mut groups,
            &mut summary,
        )
        .await?;
    }

    summary.candidate_repositories = groups.len();

    let mut rows = Vec::new();
    let mut github_groups = Vec::new();
    for group in groups.into_values() {
        if group.repository_hint.is_some() {
            github_groups.push(group);
        } else {
            summary.repositories_unsupported += 1;
            summary.partial = true;
            let mut row = base_row(&context, &group);
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
            rows.push(sanitize_row(row));
        }
    }

    let resolution = resolve_repository_groups(
        github,
        github_groups,
        options.jobs,
        options.max_repositories,
    )
    .await;
    summary.repositories_filtered_as_private = resolution.filtered_private;
    summary.repository_limit_reached = resolution.limit_reached;
    summary.repository_resolution_budget_exhausted = resolution.budget_exhausted;
    if resolution.budget_exhausted {
        summary.notes.push(format!(
            "repository resolution stopped after the bounded {}x redirect/private overscan budget before filling --max-repositories",
            REPOSITORY_RESOLUTION_OVERSCAN_FACTOR
        ));
    }
    for (group, error) in resolution.failures {
        summary.repositories_failed += 1;
        summary.partial = true;
        let mut row = base_row(&context, &group);
        row.inventory_status = "failed".to_owned();
        row.lock_status = "not_scanned".to_owned();
        row.exact_resolution_status = "unknown".to_owned();
        row.current_direct_status = "unknown".to_owned();
        row.recorded_relation = "unknown".to_owned();
        row.evidence_completeness = "failed".to_owned();
        row.error_code = "repository_resolution_failed".to_owned();
        row.error_message = format!("{error:#}");
        rows.push(sanitize_row(row));
    }

    let github_requests = Arc::new(Semaphore::new(options.jobs));
    let work = resolution.resolved.into_iter().map(|resolved| {
        let client = github.clone();
        let context = context.clone();
        let options = options.clone();
        let requests = Arc::clone(&github_requests);
        async move { inspect_repository(&client, &context, resolved, &options, &requests).await }
    });
    let mut inspections = stream::iter(work).buffer_unordered(options.jobs);
    let mut aggregate = InspectionResult::default();
    while let Some(inspection) = inspections.next().await {
        aggregate.absorb(inspection);
    }
    rows.extend(aggregate.rows);

    summary.repositories_scanned = aggregate.scanned;
    summary.repositories_filtered_by_activity = aggregate.filtered_activity;
    summary.repositories_filtered_as_forks = aggregate.filtered_fork;
    summary.repositories_filtered_as_archived = aggregate.filtered_archived;
    summary.repositories_partial += aggregate.partial_repositories;
    summary.repositories_failed += aggregate.failed_repositories;
    summary.lockfiles_found = aggregate.lockfiles_found;
    summary.lockfiles_parsed = aggregate.lockfiles_parsed;
    summary.exact_occurrences = aggregate.exact_occurrences;
    summary.matched_cargo_files = aggregate.matched_cargo_files;
    summary.matched_cargo_file_bytes_downloaded = aggregate.matched_cargo_file_bytes_downloaded;
    summary.repositories_file_limit_exceeded = aggregate.file_limit_exceeded;
    summary.repositories_byte_budget_exceeded = aggregate.byte_budget_exceeded;
    summary.repositories_exact_confirmed = aggregate.exact_confirmed_repositories;
    summary.partial |= summary.repositories_partial > 0
        || summary.repositories_failed > 0
        || summary.repository_resolution_budget_exhausted
        || summary.github_search_incomplete;

    rows.sort_by(|left, right| {
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
    summary.output_rows = rows.len();

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

fn filter_candidate(
    mut candidate: ReverseDependencyCandidate,
    options: &ScanOptions,
) -> Option<ReverseDependencyCandidate> {
    if candidate.dependent_yanked {
        return None;
    }

    let enrichment_unknown = candidate.declaration_enrichment_error.is_some();
    candidate.declarations.retain(|declaration| {
        dependency_kind_selected(&declaration.kind, &options.dependency_kinds)
            && optional_selected(declaration.optional, options.optional)
    });
    if candidate.declarations.is_empty() {
        return enrichment_unknown.then_some(candidate);
    }

    let requirement_matches = match options.requirement_filter {
        RequirementFilter::Any => true,
        RequirementFilter::Accepts => candidate.declarations.iter().any(|declaration| {
            evaluate_cargo_requirement(&declaration.req, &options.version).accepts == Some(true)
        }),
        RequirementFilter::Exact => candidate.declarations.iter().any(|declaration| {
            evaluate_cargo_requirement(&declaration.req, &options.version).explicit_exact_pin
                == Some(true)
        }),
    };
    (requirement_matches || enrichment_unknown).then_some(candidate)
}

fn dependency_kind_selected(kind: &str, selected: &[DependencyKind]) -> bool {
    selected.iter().any(|candidate| match candidate {
        DependencyKind::Normal => kind.is_empty() || kind == "normal",
        DependencyKind::Build => kind == "build",
        DependencyKind::Dev => kind == "dev",
    })
}

fn optional_selected(optional: bool, filter: OptionalFilter) -> bool {
    match filter {
        OptionalFilter::Include => true,
        OptionalFilter::Exclude => !optional,
        OptionalFilter::Only => optional,
    }
}

fn add_published_candidate(
    groups: &mut BTreeMap<String, CandidateGroup>,
    candidate: ReverseDependencyCandidate,
) {
    let repository = candidate
        .repository
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (key, hint, reason) = match repository.and_then(parse_github_repo) {
        Some(repo) => (
            format!("github:{}", repo.full_name().to_ascii_lowercase()),
            Some(repo),
            None,
        ),
        None if repository.is_some() => (
            format!("unsupported:{}", repository.unwrap().to_ascii_lowercase()),
            None,
            Some("candidate repository is not a canonical github.com repository".to_owned()),
        ),
        None => (
            format!(
                "missing:{}@{}",
                candidate.dependent_name, candidate.dependent_version
            ),
            None,
            Some("dependent crate version has no repository URL".to_owned()),
        ),
    };
    let group = groups.entry(key).or_default();
    group.repository_hint = group.repository_hint.take().or(hint);
    if let Some(repository) = repository {
        group.original_repository_urls.insert(repository.to_owned());
    }
    group
        .sources
        .insert("crates_io_reverse_dependencies".to_owned());
    group.published.push(candidate);
    group.unsupported_reason = group.unsupported_reason.take().or(reason);
}

async fn add_github_code_candidates(
    github: &GitHubClient,
    target_crate: &str,
    target_version: &Version,
    limit: usize,
    groups: &mut BTreeMap<String, CandidateGroup>,
    summary: &mut ScanSummary,
) -> Result<()> {
    if !github.is_authenticated() {
        bail!("--discovery github-code/both requires GITHUB_TOKEN or GH_TOKEN");
    }
    let queries = github_code_queries(target_crate, target_version);

    for (query, exact_name, source) in queries {
        let result = match github.search_code(&query, limit).await {
            Ok(result) => result,
            Err(error) => {
                summary.github_search_incomplete = true;
                summary.partial = true;
                summary.notes.push(format!(
                    "supplemental GitHub code search `{source}` failed; retained other candidate sources: {error:#}"
                ));
                continue;
            }
        };
        summary.github_search_results_returned += result.items.len();
        summary.github_search_total_count = summary
            .github_search_total_count
            .saturating_add(result.total_count.min(usize::MAX as u64) as usize);
        summary.github_search_incomplete |= result.bounded();
        for item in result.items {
            if item.repository.private {
                summary.github_search_private_results_discarded += 1;
                continue;
            }
            if final_component(&item.path) != exact_name {
                continue;
            }
            let Some(repo) = parse_github_repo(&item.repository.full_name) else {
                continue;
            };
            let key = format!("github:{}", repo.full_name().to_ascii_lowercase());
            let group = groups.entry(key).or_default();
            group.repository_hint = group.repository_hint.take().or(Some(repo));
            group
                .original_repository_urls
                .insert(item.repository.html_url.to_string());
            group.sources.insert(source.to_owned());
        }
    }
    if summary.github_search_incomplete {
        summary.notes.push(
            "GitHub REST code-search candidates were capped or reported incomplete_results; they are supplemental only."
                .to_owned(),
        );
    }
    Ok(())
}

fn github_code_queries(
    target_crate: &str,
    target_version: &Version,
) -> [(String, &'static str, &'static str); 2] {
    [
        (
            format!("{target_crate} {target_version} filename:Cargo.lock is:public"),
            "Cargo.lock",
            "github_rest_code_search_lock_seed",
        ),
        (
            format!("{target_crate} filename:Cargo.toml is:public"),
            "Cargo.toml",
            "github_rest_code_search_manifest_seed",
        ),
    ]
}

async fn resolve_repository_groups(
    github: &GitHubClient,
    groups: Vec<CandidateGroup>,
    jobs: usize,
    maximum: Option<usize>,
) -> RepositoryResolution {
    let total = groups.len();
    let resolution_budget = repository_resolution_budget(total, maximum);
    let mut work =
        groups
            .into_iter()
            .take(resolution_budget)
            .enumerate()
            .map(|(position, group)| {
                let client = github.clone();
                async move {
                    let repository = match group.repository_hint.as_ref() {
                        Some(repo) => client.repository(repo).await,
                        None => unreachable!("GitHub group always has a repository hint"),
                    };
                    (position, group, repository)
                }
            });
    let mut by_id = HashMap::<u64, ResolvedGroup>::new();
    let mut failures = Vec::new();
    let mut private_ids = HashSet::new();
    let mut considered = 0usize;
    let mut skipped_due_limit = false;

    if maximum.is_none() {
        let mut results = stream::iter(work).buffer_unordered(jobs);
        while let Some((_, group, result)) = results.next().await {
            considered += 1;
            record_repository_resolution(
                &mut by_id,
                &mut failures,
                &mut private_ids,
                &mut skipped_due_limit,
                maximum,
                group,
                result,
            );
        }
    } else {
        while maximum.is_none_or(|maximum| by_id.len() < maximum) {
            let batch = work.by_ref().take(jobs).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            considered += batch.len();
            let mut results = stream::iter(batch)
                .buffer_unordered(jobs)
                .collect::<Vec<_>>()
                .await;
            results.sort_by_key(|(position, _, _)| *position);

            for (_, group, result) in results {
                record_repository_resolution(
                    &mut by_id,
                    &mut failures,
                    &mut private_ids,
                    &mut skipped_due_limit,
                    maximum,
                    group,
                    result,
                );
            }
        }
    }

    let mut resolved = by_id.into_values().collect::<Vec<_>>();
    resolved.sort_by(|left, right| left.repository.full_name.cmp(&right.repository.full_name));
    let limit_reached = maximum.is_some() && (considered < total || skipped_due_limit);
    let budget_exhausted = maximum.is_some_and(|maximum| {
        maximum > 0
            && resolved.len() < maximum
            && considered >= resolution_budget
            && considered < total
    });
    RepositoryResolution {
        resolved,
        failures,
        filtered_private: private_ids.len(),
        limit_reached,
        budget_exhausted,
    }
}

fn record_repository_resolution(
    by_id: &mut HashMap<u64, ResolvedGroup>,
    failures: &mut Vec<(CandidateGroup, anyhow::Error)>,
    private_ids: &mut HashSet<u64>,
    skipped_due_limit: &mut bool,
    maximum: Option<usize>,
    group: CandidateGroup,
    result: Result<GitHubRepository>,
) {
    match result {
        Ok(repository) if repository.private => {
            private_ids.insert(repository.id);
        }
        Ok(repository) => {
            if let Some(existing) = by_id.get_mut(&repository.id) {
                existing.group.merge(group);
            } else if maximum.is_none_or(|maximum| by_id.len() < maximum) {
                by_id.insert(repository.id, ResolvedGroup { group, repository });
            } else {
                *skipped_due_limit = true;
            }
        }
        Err(error) if maximum.is_none_or(|maximum| by_id.len() < maximum) => {
            failures.push((group, error));
        }
        Err(_) => *skipped_due_limit = true,
    }
}

fn repository_resolution_budget(total: usize, maximum: Option<usize>) -> usize {
    maximum.map_or(total, |maximum| {
        maximum
            .saturating_mul(REPOSITORY_RESOLUTION_OVERSCAN_FACTOR)
            .min(total)
    })
}

async fn limited_github_request<T>(
    request_permits: &Semaphore,
    request: impl Future<Output = Result<T>>,
) -> Result<T> {
    let _permit = request_permits
        .acquire()
        .await
        .context("GitHub request limiter closed unexpectedly")?;
    request.await
}

async fn inspect_repository(
    github: &GitHubClient,
    context: &RunContext,
    resolved: ResolvedGroup,
    options: &ScanOptions,
    request_permits: &Semaphore,
) -> InspectionResult {
    let mut result = InspectionResult::default();
    let repository = &resolved.repository;

    if repository.fork && !options.include_forks {
        result.filtered_fork = 1;
        return result;
    }
    if repository.archived && options.exclude_archived {
        result.filtered_archived = 1;
        return result;
    }

    let head = match limited_github_request(request_permits, github.default_branch_head(repository))
        .await
    {
        Ok(head) => head,
        Err(error) => {
            result.failed_repositories = 1;
            let mut row = repository_row(context, &resolved.group, repository, None, None);
            row.inventory_status = "failed".to_owned();
            row.lock_status = "not_scanned".to_owned();
            row.exact_resolution_status = "unknown".to_owned();
            row.current_direct_status = "unknown".to_owned();
            row.recorded_relation = "unknown".to_owned();
            row.evidence_completeness = "failed".to_owned();
            append_error(
                &mut row,
                "default_branch_head_failed",
                &format!("{error:#}"),
            );
            result.rows.push(sanitize_row(row));
            return result;
        }
    };

    let stale = match activity_decision(
        head.committed_at,
        context.observed_at,
        options.stale_after_days,
        options.activity,
        options.committed_since,
        options.committed_before,
    ) {
        ActivityDecision::Keep { stale } => stale,
        ActivityDecision::Filter => {
            result.filtered_activity = 1;
            return result;
        }
    };

    let repo = repository.repo();
    let tree = match limited_github_request(
        request_permits,
        github.recursive_tree(&repo, &head.tree_sha),
    )
    .await
    {
        Ok(tree) => tree,
        Err(error) => {
            result.failed_repositories = 1;
            let mut row = repository_row(
                context,
                &resolved.group,
                repository,
                Some(&head),
                Some(stale),
            );
            row.inventory_status = "failed".to_owned();
            row.lock_status = "not_scanned".to_owned();
            row.exact_resolution_status = "unknown".to_owned();
            row.current_direct_status = "unknown".to_owned();
            row.recorded_relation = "unknown".to_owned();
            row.evidence_completeness = "failed".to_owned();
            append_error(&mut row, "tree_fetch_failed", &format!("{error:#}"));
            result.rows.push(sanitize_row(row));
            return result;
        }
    };

    result.scanned = 1;
    let tree_truncated = tree.truncated;
    let mut manifest_entries = Vec::new();
    let mut lock_entries = Vec::new();
    for entry in tree.tree {
        if !entry.is_blob() {
            continue;
        }
        match final_component(&entry.path) {
            "Cargo.toml" => manifest_entries.push(entry),
            "Cargo.lock" => lock_entries.push(entry),
            _ => {}
        }
    }
    manifest_entries.sort_by(|left, right| left.path.cmp(&right.path));
    lock_entries.sort_by(|left, right| left.path.cmp(&right.path));
    result.lockfiles_found = lock_entries.len();

    let matched_file_count = manifest_entries.len().saturating_add(lock_entries.len());
    result.matched_cargo_files = matched_file_count;
    let selected_lock_count = lock_entries.len().min(REPOSITORY_MATCHED_FILE_LIMIT);
    let selected_manifest_count = manifest_entries
        .len()
        .min(REPOSITORY_MATCHED_FILE_LIMIT.saturating_sub(selected_lock_count));
    let file_limit_hit = matched_file_count > REPOSITORY_MATCHED_FILE_LIMIT;
    result.file_limit_exceeded = usize::from(file_limit_hit);
    let mut byte_budget = RepositoryByteBudget::new(REPOSITORY_MATCHED_FILE_BYTE_BUDGET);
    let reserved_lock_bytes = reserved_lock_bytes(
        &lock_entries,
        selected_lock_count,
        options.max_file_bytes,
        byte_budget.limit,
    );
    let manifest_byte_ceiling = byte_budget.limit.saturating_sub(reserved_lock_bytes);
    let manifest_scan = scan_manifests(
        github,
        &repo,
        &manifest_entries,
        &mut byte_budget,
        ManifestScanConfig {
            selected_count: selected_manifest_count,
            target_crate: &context.target_crate,
            target_version: &context.target_version,
            max_file_bytes: options.max_file_bytes,
            tree_complete: !tree_truncated,
            byte_ceiling: manifest_byte_ceiling,
            request_permits,
            max_in_flight: options.jobs,
        },
    )
    .await;

    let enrichment_partial = resolved
        .group
        .published
        .iter()
        .any(|candidate| candidate.declaration_enrichment_error.is_some());
    let repository_baseline_partial =
        tree_truncated || !manifest_scan.complete || enrichment_partial;
    let mut repository_became_partial = repository_baseline_partial || file_limit_hit;
    let mut row_template = repository_row(
        context,
        &resolved.group,
        repository,
        Some(&head),
        Some(stale),
    );
    apply_tree_and_manifest(
        &mut row_template,
        tree_truncated,
        &manifest_scan,
        enrichment_partial,
    );

    if lock_entries.is_empty() {
        let mut row = row_template;
        row.lock_status = if tree_truncated {
            "unknown_truncated"
        } else {
            "not_found"
        }
        .to_owned();
        row.exact_resolution_status = if tree_truncated {
            "unknown"
        } else {
            "not_observed"
        }
        .to_owned();
        row.recorded_relation = "unknown".to_owned();
        finalize_completeness(&mut row, repository_baseline_partial);
        result.rows.push(sanitize_row(row));
    } else {
        for (lock_index, entry) in lock_entries.into_iter().enumerate() {
            let mut row = row_template.clone();
            row.cargo_lock_path = entry.path.clone();
            row.cargo_lock_blob_sha = entry.sha.clone();

            if lock_index >= selected_lock_count {
                row.lock_status = "repository_file_limit_exceeded".to_owned();
                row.exact_resolution_status = "unknown".to_owned();
                row.recorded_relation = "unknown".to_owned();
                append_error(
                    &mut row,
                    "repository_matched_file_limit",
                    &format!(
                        "repository has {matched_file_count} matching Cargo files, exceeding the per-repository limit {REPOSITORY_MATCHED_FILE_LIMIT}"
                    ),
                );
                repository_became_partial = true;
                finalize_completeness(&mut row, true);
                result.rows.push(sanitize_row(row));
                continue;
            }

            if entry.mode == "120000" {
                row.lock_status = "symlink_not_followed".to_owned();
                row.exact_resolution_status = "unknown".to_owned();
                row.recorded_relation = "unknown".to_owned();
                append_error(
                    &mut row,
                    "lockfile_symlink",
                    "Cargo.lock is a symbolic link; the immutable blob is the link target path",
                );
                repository_became_partial = true;
                finalize_completeness(&mut row, true);
                result.rows.push(sanitize_row(row));
                continue;
            }
            if entry.size.is_some_and(|size| size > options.max_file_bytes) {
                row.lock_status = "too_large".to_owned();
                row.exact_resolution_status = "unknown".to_owned();
                row.recorded_relation = "unknown".to_owned();
                append_error(
                    &mut row,
                    "lockfile_too_large",
                    &format!(
                        "blob size {} exceeds --max-file-bytes {}",
                        entry.size.unwrap_or_default(),
                        options.max_file_bytes
                    ),
                );
                repository_became_partial = true;
                finalize_completeness(&mut row, true);
                result.rows.push(sanitize_row(row));
                continue;
            }
            let lock_byte_ceiling = byte_budget.limit;
            if !byte_budget.can_fetch_below(entry.size, lock_byte_ceiling) {
                row.lock_status = "repository_byte_budget_exceeded".to_owned();
                row.exact_resolution_status = "unknown".to_owned();
                row.recorded_relation = "unknown".to_owned();
                append_error(
                    &mut row,
                    "repository_matched_file_byte_budget",
                    &format!(
                        "Cargo file download would exceed the per-repository {}-byte budget",
                        byte_budget.limit
                    ),
                );
                repository_became_partial = true;
                finalize_completeness(&mut row, true);
                result.rows.push(sanitize_row(row));
                continue;
            }

            let max_bytes = options
                .max_file_bytes
                .min(byte_budget.remaining_below(lock_byte_ceiling));
            let bytes = match limited_github_request(
                request_permits,
                github.blob_by_sha(&repo, &entry.sha, max_bytes),
            )
            .await
            {
                Ok(bytes) => {
                    byte_budget.record(bytes.len());
                    bytes
                }
                Err(error) => {
                    row.lock_status = "fetch_failed".to_owned();
                    row.exact_resolution_status = "unknown".to_owned();
                    row.recorded_relation = "unknown".to_owned();
                    append_error(&mut row, "lockfile_fetch_failed", &format!("{error:#}"));
                    repository_became_partial = true;
                    finalize_completeness(&mut row, true);
                    result.rows.push(sanitize_row(row));
                    continue;
                }
            };
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => {
                    row.lock_status = "non_utf8".to_owned();
                    row.exact_resolution_status = "unknown".to_owned();
                    row.recorded_relation = "unknown".to_owned();
                    append_error(&mut row, "lockfile_non_utf8", &error.to_string());
                    repository_became_partial = true;
                    finalize_completeness(&mut row, true);
                    result.rows.push(sanitize_row(row));
                    continue;
                }
            };

            match analyze_cargo_lock(&text, &context.target_crate, &context.target_version) {
                Ok(evidence) => {
                    result.lockfiles_parsed += 1;
                    result.exact_occurrences += evidence.exact_occurrences;
                    if evidence.exact_occurrences > 0
                        && relation_confirms_dependency(evidence.recorded_relation)
                    {
                        result.exact_confirmed_repositories = 1;
                    }
                    row.lock_status = "parsed".to_owned();
                    row.resolved_target_versions_json = json_cell(&evidence.resolved_versions);
                    row.resolved_target_sources_json = json_cell(&evidence.occurrences);
                    row.exact_resolution_status = if evidence.exact_occurrences > 0 {
                        "present"
                    } else {
                        "absent"
                    }
                    .to_owned();
                    row.exact_occurrence_count = evidence.exact_occurrences;
                    row.exact_crates_io_occurrence_count = evidence.exact_crates_io_occurrences;
                    row.recorded_relation = relation_name(evidence.recorded_relation).to_owned();
                    row.shortest_dependency_depth = evidence
                        .shortest_depth
                        .map(|depth| depth.to_string())
                        .unwrap_or_default();

                    let graph_partial =
                        evidence.exact_occurrences > 0 && !evidence.graph_analysis_complete;
                    if graph_partial {
                        append_error(
                            &mut row,
                            "lock_graph_unclassified",
                            evidence
                                .graph_diagnostic
                                .as_deref()
                                .unwrap_or("lock graph could not be classified"),
                        );
                        repository_became_partial = true;
                    }
                    finalize_completeness(&mut row, repository_baseline_partial || graph_partial);
                }
                Err(error) => {
                    row.lock_status = "parse_failed".to_owned();
                    row.exact_resolution_status = "unknown".to_owned();
                    row.recorded_relation = "unknown".to_owned();
                    append_error(&mut row, "lockfile_parse_failed", &format!("{error:#}"));
                    repository_became_partial = true;
                    finalize_completeness(&mut row, true);
                }
            }
            result.rows.push(sanitize_row(row));
        }
    }

    result.matched_cargo_file_bytes_downloaded = byte_budget.consumed;
    if byte_budget.limit_hit {
        result.byte_budget_exceeded = 1;
        repository_became_partial = true;
    }
    for row in &mut result.rows {
        row.repository_matched_cargo_file_count = matched_file_count;
        row.repository_matched_file_limit = REPOSITORY_MATCHED_FILE_LIMIT;
        row.repository_matched_file_bytes_downloaded = byte_budget.consumed;
        row.repository_matched_file_byte_budget = byte_budget.limit;
    }
    if repository_became_partial {
        result.partial_repositories = 1;
    }
    result
}

#[derive(Debug)]
enum CargoBlobFetch {
    Symlink,
    TooLarge,
    ByteBudgetExceeded,
    Failed(String),
    Fetched(Vec<u8>),
}

struct CargoBlobFetchConfig<'a> {
    selected_count: usize,
    max_file_bytes: u64,
    byte_ceiling: u64,
    request_permits: &'a Semaphore,
    max_in_flight: usize,
}

async fn fetch_cargo_blobs(
    github: &GitHubClient,
    repo: &GitHubRepo,
    entries: &[GitHubTreeEntry],
    byte_budget: &mut RepositoryByteBudget,
    config: CargoBlobFetchConfig<'_>,
) -> Vec<CargoBlobFetch> {
    let selected_count = config.selected_count.min(entries.len());
    let mut outcomes = Vec::with_capacity(selected_count);
    outcomes.resize_with(selected_count, || None);
    let mut cursor = 0usize;

    while cursor < selected_count {
        let mut reserved = 0u64;
        let mut batch = Vec::new();
        while cursor < selected_count && batch.len() < config.max_in_flight {
            let entry = &entries[cursor];
            if entry.mode == "120000" {
                outcomes[cursor] = Some(CargoBlobFetch::Symlink);
                cursor += 1;
                continue;
            }
            if entry.size.is_some_and(|size| size > config.max_file_bytes) {
                outcomes[cursor] = Some(CargoBlobFetch::TooLarge);
                cursor += 1;
                continue;
            }

            let available = config
                .byte_ceiling
                .min(byte_budget.limit)
                .saturating_sub(byte_budget.consumed)
                .saturating_sub(reserved);
            match entry.size {
                Some(size) if size <= available => {
                    batch.push((cursor, entry, size));
                    reserved = reserved.saturating_add(size);
                    cursor += 1;
                }
                Some(_) if batch.is_empty() => {
                    let admitted = byte_budget.can_fetch_below(entry.size, config.byte_ceiling);
                    debug_assert!(!admitted);
                    outcomes[cursor] = Some(CargoBlobFetch::ByteBudgetExceeded);
                    cursor += 1;
                }
                Some(_) => break,
                None if available == 0 && batch.is_empty() => {
                    let admitted = byte_budget.can_fetch_below(None, config.byte_ceiling);
                    debug_assert!(!admitted);
                    outcomes[cursor] = Some(CargoBlobFetch::ByteBudgetExceeded);
                    cursor += 1;
                }
                None if batch.is_empty() => {
                    batch.push((cursor, entry, config.max_file_bytes.min(available)));
                    cursor += 1;
                    break;
                }
                None => break,
            }
        }

        if batch.is_empty() {
            continue;
        }
        let work = batch
            .into_iter()
            .map(|(position, entry, max_bytes)| async move {
                let result = limited_github_request(
                    config.request_permits,
                    github.blob_by_sha(repo, &entry.sha, max_bytes),
                )
                .await;
                (position, result)
            });
        let mut fetched = stream::iter(work)
            .buffer_unordered(config.max_in_flight)
            .collect::<Vec<_>>()
            .await;
        fetched.sort_by_key(|(position, _)| *position);
        for (position, result) in fetched {
            outcomes[position] = Some(match result {
                Ok(bytes) => {
                    byte_budget.record(bytes.len());
                    CargoBlobFetch::Fetched(bytes)
                }
                Err(error) => CargoBlobFetch::Failed(format!("{error:#}")),
            });
        }
    }

    outcomes
        .into_iter()
        .map(|outcome| outcome.expect("every selected Cargo blob has an outcome"))
        .collect()
}

async fn scan_manifests(
    github: &GitHubClient,
    repo: &GitHubRepo,
    entries: &[GitHubTreeEntry],
    byte_budget: &mut RepositoryByteBudget,
    config: ManifestScanConfig<'_>,
) -> ManifestScan {
    let paths = entries.iter().map(|entry| entry.path.clone()).collect();
    let mut manifests = Vec::new();
    let mut diagnostics = Vec::new();
    if entries.len() > config.selected_count {
        diagnostics.push(format!(
            "{} Cargo.toml files were not read because the repository matched-file limit is {}",
            entries.len() - config.selected_count,
            REPOSITORY_MATCHED_FILE_LIMIT
        ));
    }
    let fetches = fetch_cargo_blobs(
        github,
        repo,
        entries,
        byte_budget,
        CargoBlobFetchConfig {
            selected_count: config.selected_count,
            max_file_bytes: config.max_file_bytes,
            byte_ceiling: config.byte_ceiling,
            request_permits: config.request_permits,
            max_in_flight: config.max_in_flight,
        },
    )
    .await;
    for (entry, fetch) in entries.iter().take(config.selected_count).zip(fetches) {
        match fetch {
            CargoBlobFetch::Symlink => diagnostics.push(format!(
                "{}: symbolic-link Cargo.toml was not followed",
                entry.path
            )),
            CargoBlobFetch::TooLarge => diagnostics.push(format!(
                "{}: manifest size {} exceeds cap {}",
                entry.path,
                entry.size.unwrap_or_default(),
                config.max_file_bytes
            )),
            CargoBlobFetch::ByteBudgetExceeded => diagnostics.push(format!(
                "{}: manifest would exceed the per-repository {}-byte Cargo-file budget",
                entry.path, byte_budget.limit
            )),
            CargoBlobFetch::Failed(error) => {
                diagnostics.push(format!("{}: {error}", entry.path));
            }
            CargoBlobFetch::Fetched(bytes) => match String::from_utf8(bytes) {
                Ok(text) => manifests.push((entry.path.clone(), text)),
                Err(error) => diagnostics.push(format!("{}: {error}", entry.path)),
            },
        }
    }

    let evidence = analyze_cargo_manifests(manifests, config.target_crate, config.target_version);
    diagnostics.extend(evidence.diagnostics.iter().map(|diagnostic| {
        format!(
            "{}: {}: {}",
            diagnostic.manifest_path, diagnostic.code, diagnostic.message
        )
    }));
    let complete = config.tree_complete && diagnostics.is_empty() && evidence.analysis_complete;
    ManifestScan {
        evidence,
        paths,
        complete,
        diagnostics,
    }
}

fn apply_tree_and_manifest(
    row: &mut CsvRow,
    tree_truncated: bool,
    manifest_scan: &ManifestScan,
    enrichment_partial: bool,
) {
    row.tree_truncated = tree_truncated.to_string();
    row.manifest_paths_json = json_cell(&manifest_scan.paths);
    row.current_direct_requirements_json = json_cell(&manifest_scan.evidence.declarations);
    row.current_direct_status = if !manifest_scan.evidence.declarations.is_empty() {
        "present"
    } else if manifest_scan.complete {
        "absent"
    } else {
        "unknown"
    }
    .to_owned();

    if tree_truncated {
        append_error(
            row,
            "tree_truncated",
            "GitHub recursive tree was truncated; file absence is not proven",
        );
    }
    if !manifest_scan.complete {
        append_error(
            row,
            "manifest_inventory_partial",
            &manifest_scan.diagnostics.join(" | "),
        );
    }
    if enrichment_partial {
        append_error(
            row,
            "sparse_index_enrichment_partial",
            "one or more published candidates use representative fallback data",
        );
    }
}

fn finalize_completeness(row: &mut CsvRow, partial: bool) {
    if partial || !row.error_code.is_empty() {
        row.inventory_status = "partial".to_owned();
        row.evidence_completeness = "partial".to_owned();
    } else {
        row.inventory_status = "complete".to_owned();
        row.evidence_completeness = "complete".to_owned();
    }
}

fn base_row(context: &RunContext, group: &CandidateGroup) -> CsvRow {
    let mut declarations = group
        .published
        .iter()
        .flat_map(|candidate| {
            candidate
                .declarations
                .iter()
                .map(|declaration| published_cell(candidate, declaration))
        })
        .collect::<Vec<_>>();
    declarations.sort_by(|left, right| {
        (
            &left.dependent_crate,
            &left.dependent_version,
            &left.kind,
            &left.dependency_alias,
            &left.requirement,
            &left.target,
        )
            .cmp(&(
                &right.dependent_crate,
                &right.dependent_version,
                &right.kind,
                &right.dependency_alias,
                &right.requirement,
                &right.target,
            ))
    });

    let dependent_crates = group
        .published
        .iter()
        .map(|candidate| candidate.dependent_name.clone())
        .collect::<BTreeSet<_>>();
    let dependent_versions = group
        .published
        .iter()
        .map(|candidate| {
            format!(
                "{}@{}",
                candidate.dependent_name, candidate.dependent_version
            )
        })
        .collect::<BTreeSet<_>>();
    let kinds = declarations
        .iter()
        .map(|declaration| declaration.kind.clone())
        .collect::<BTreeSet<_>>();
    let targets = declarations
        .iter()
        .filter_map(|declaration| declaration.target.clone())
        .collect::<BTreeSet<_>>();
    let enrichment_unknown = group
        .published
        .iter()
        .any(|candidate| candidate.declaration_enrichment_error.is_some());
    let requirement_evaluations = declarations
        .iter()
        .map(|declaration| {
            evaluate_cargo_requirement(&declaration.requirement, &context.target_version)
        })
        .collect::<Vec<_>>();
    let accepts = tri_state(
        requirement_evaluations
            .iter()
            .map(|evaluation| evaluation.accepts),
        enrichment_unknown,
    );
    let exact_pin = tri_state(
        requirement_evaluations
            .iter()
            .map(|evaluation| evaluation.explicit_exact_pin),
        enrichment_unknown,
    );
    let observed_optional = declarations.iter().any(|declaration| declaration.optional);
    let observed_required = declarations.iter().any(|declaration| !declaration.optional);
    let optional_declarations = if declarations.is_empty()
        || (enrichment_unknown && !(observed_optional && observed_required))
    {
        "unknown"
    } else if observed_optional && !observed_required {
        "all"
    } else if observed_optional {
        "mixed"
    } else {
        "none"
    };

    CsvRow {
        observed_at_utc: context.observed_at.to_rfc3339(),
        input_query: context.input_query.clone(),
        target_crate: context.target_crate.clone(),
        target_version: context.target_version.to_string(),
        target_repository_url: context.target_repository_url.clone().unwrap_or_default(),
        globally_exhaustive: context.globally_exhaustive,
        candidate_scope: context.candidate_scope.clone(),
        scan_policy_json: context.scan_policy_json.clone(),
        candidate_sources_json: json_cell(&group.sources),
        dependent_crates_json: json_cell(&dependent_crates),
        dependent_versions_json: json_cell(&dependent_versions),
        published_requirements_json: json_cell(&declarations),
        dependency_kinds_json: json_cell(&kinds),
        dependency_targets_json: json_cell(&targets),
        optional_declarations: optional_declarations.to_owned(),
        published_direct_status: if group.published.is_empty() {
            "not_observed"
        } else {
            "present"
        }
        .to_owned(),
        any_requirement_accepts: accepts,
        any_exact_pin: exact_pin,
        original_repository_urls_json: json_cell(&group.original_repository_urls),
        repository_url: group
            .original_repository_urls
            .iter()
            .next()
            .cloned()
            .unwrap_or_default(),
        github_repository_id: String::new(),
        github_full_name: group
            .repository_hint
            .as_ref()
            .map(GitHubRepo::full_name)
            .unwrap_or_default(),
        default_branch: String::new(),
        head_sha: String::new(),
        tree_sha: String::new(),
        head_committed_at: String::new(),
        repo_pushed_at: String::new(),
        archived: "unknown".to_owned(),
        fork: "unknown".to_owned(),
        disabled: "unknown".to_owned(),
        stale: "unknown".to_owned(),
        inventory_status: "unknown".to_owned(),
        tree_truncated: "unknown".to_owned(),
        repository_matched_cargo_file_count: 0,
        repository_matched_file_limit: REPOSITORY_MATCHED_FILE_LIMIT,
        repository_matched_file_bytes_downloaded: 0,
        repository_matched_file_byte_budget: REPOSITORY_MATCHED_FILE_BYTE_BUDGET,
        cargo_lock_path: String::new(),
        cargo_lock_blob_sha: String::new(),
        lock_status: "unknown".to_owned(),
        resolved_target_versions_json: "[]".to_owned(),
        resolved_target_sources_json: "[]".to_owned(),
        exact_resolution_status: "unknown".to_owned(),
        exact_occurrence_count: 0,
        exact_crates_io_occurrence_count: 0,
        manifest_paths_json: "[]".to_owned(),
        current_direct_status: "unknown".to_owned(),
        current_direct_requirements_json: "[]".to_owned(),
        recorded_relation: "unknown".to_owned(),
        shortest_dependency_depth: String::new(),
        evidence_completeness: "unknown".to_owned(),
        error_code: String::new(),
        error_message: String::new(),
    }
}

fn published_cell(
    candidate: &ReverseDependencyCandidate,
    declaration: &DependencyDeclaration,
) -> PublishedDeclarationCell {
    PublishedDeclarationCell {
        dependent_crate: candidate.dependent_name.clone(),
        dependent_version: candidate.dependent_version.clone(),
        dependent_version_id: candidate.version_id,
        dependent_downloads: candidate.dependent_downloads,
        dependency_alias: declaration.dependency_name.clone(),
        dependency_package: declaration.package_name.clone(),
        requirement: declaration.req.clone(),
        kind: declaration.kind.clone(),
        optional: declaration.optional,
        target: declaration.target.clone(),
        registry: declaration.registry.clone(),
        enrichment_error: candidate.declaration_enrichment_error.clone(),
    }
}

fn repository_row(
    context: &RunContext,
    group: &CandidateGroup,
    repository: &GitHubRepository,
    head: Option<&GitHubHead>,
    stale: Option<bool>,
) -> CsvRow {
    let mut row = base_row(context, group);
    row.repository_url = repository.html_url.to_string();
    row.github_repository_id = repository.id.to_string();
    row.github_full_name = repository.full_name.clone();
    row.default_branch = repository.default_branch.clone().unwrap_or_default();
    row.repo_pushed_at = repository
        .pushed_at
        .map(|pushed| pushed.to_rfc3339())
        .unwrap_or_default();
    row.archived = repository.archived.to_string();
    row.fork = repository.fork.to_string();
    row.disabled = repository.disabled.to_string();
    if let Some(head) = head {
        row.head_sha = head.sha.clone();
        row.tree_sha = head.tree_sha.clone();
        row.head_committed_at = head.committed_at.to_rfc3339();
    }
    row.stale = stale
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    row
}

fn tri_state(
    values: impl IntoIterator<Item = Option<bool>>,
    force_unknown_if_no_match: bool,
) -> String {
    let mut saw_value = false;
    let mut saw_unknown = false;
    for value in values {
        saw_value = true;
        match value {
            Some(true) => return "true".to_owned(),
            Some(false) => {}
            None => saw_unknown = true,
        }
    }
    if force_unknown_if_no_match || !saw_value || saw_unknown {
        "unknown"
    } else {
        "false"
    }
    .to_owned()
}

fn relation_name(relation: RecordedRelation) -> &'static str {
    match relation {
        RecordedRelation::Direct => "recorded_direct",
        RecordedRelation::Transitive => "recorded_transitive",
        RecordedRelation::DirectAndTransitive => "recorded_direct_and_transitive",
        RecordedRelation::PresentUnclassified => "recorded_present_unclassified",
        RecordedRelation::NotRecorded => "not_recorded",
    }
}

fn relation_confirms_dependency(relation: RecordedRelation) -> bool {
    matches!(
        relation,
        RecordedRelation::Direct
            | RecordedRelation::Transitive
            | RecordedRelation::DirectAndTransitive
    )
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

fn json_cell<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|error| {
        serde_json::to_string(&format!("serialization error: {error}"))
            .unwrap_or_else(|_| "\"serialization error\"".to_owned())
    })
}

fn append_error(row: &mut CsvRow, code: &str, message: &str) {
    if !row.error_code.is_empty() {
        row.error_code.push(';');
        row.error_message.push_str(" | ");
    }
    row.error_code.push_str(code);
    row.error_message.push_str(message);
}

fn sanitize_row(mut row: CsvRow) -> CsvRow {
    row.input_query = csv_safe(row.input_query);
    row.target_crate = csv_safe(row.target_crate);
    row.target_version = csv_safe(row.target_version);
    row.target_repository_url = csv_safe(row.target_repository_url);
    row.repository_url = csv_safe(row.repository_url);
    row.github_full_name = csv_safe(row.github_full_name);
    row.default_branch = csv_safe(row.default_branch);
    row.head_sha = csv_safe(row.head_sha);
    row.tree_sha = csv_safe(row.tree_sha);
    row.cargo_lock_path = csv_safe(row.cargo_lock_path);
    row.cargo_lock_blob_sha = csv_safe(row.cargo_lock_blob_sha);
    row.error_code = csv_safe(row.error_code);
    row.error_message = csv_safe(row.error_message);
    row
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    use super::*;
    use crate::crates_io::RepresentativeDependency;

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
