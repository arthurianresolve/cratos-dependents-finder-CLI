use std::future::Future;

use anyhow::{Context, Result};
use futures::{StreamExt, stream};
use tokio::sync::Semaphore;

use crate::{
    cargo_evidence::{analyze_cargo_lock, analyze_cargo_manifests},
    github::{GitHubClient, GitHubHead, GitHubRepo, GitHubRepository, GitHubTree, GitHubTreeEntry},
};

use super::{
    ActivityDecision, CandidateGroup, CsvRow, InspectionResult, ManifestScan, ManifestScanConfig,
    REPOSITORY_MATCHED_FILE_BYTE_BUDGET, REPOSITORY_MATCHED_FILE_LIMIT, RepositoryByteBudget,
    ResolvedGroup, RunContext, ScanOptions, activity_decision, append_error,
    apply_tree_and_manifest, final_component, finalize_completeness, json_cell,
    relation_confirms_dependency, relation_name, repository_row, reserved_lock_bytes, sanitize_row,
};
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

fn failed_repository_row(
    context: &RunContext,
    group: &CandidateGroup,
    repository: &GitHubRepository,
    head: Option<&GitHubHead>,
    stale: Option<bool>,
    code: &str,
    message: &str,
) -> CsvRow {
    let mut row = repository_row(context, group, repository, head, stale);
    row.inventory_status = "failed".to_owned();
    row.lock_status = "not_scanned".to_owned();
    row.exact_resolution_status = "unknown".to_owned();
    row.current_direct_status = "unknown".to_owned();
    row.recorded_relation = "unknown".to_owned();
    row.evidence_completeness = "failed".to_owned();
    append_error(&mut row, code, message);
    sanitize_row(row)
}

fn mark_lock_unclassified(row: &mut CsvRow, status: &str, code: &str, message: &str) {
    row.lock_status = status.to_owned();
    row.exact_resolution_status = "unknown".to_owned();
    row.recorded_relation = "unknown".to_owned();
    append_error(row, code, message);
}

struct RepositorySnapshot {
    tree_truncated: bool,
    lock_entries: Vec<GitHubTreeEntry>,
    matched_file_count: usize,
    selected_lock_count: usize,
    file_limit_hit: bool,
    byte_budget: RepositoryByteBudget,
    manifest_scan: ManifestScan,
}

async fn load_repository_snapshot(
    github: &GitHubClient,
    repo: &GitHubRepo,
    tree: GitHubTree,
    context: &RunContext,
    options: &ScanOptions,
    request_permits: &Semaphore,
) -> RepositorySnapshot {
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

    let matched_file_count = manifest_entries.len().saturating_add(lock_entries.len());
    let selected_lock_count = lock_entries.len().min(REPOSITORY_MATCHED_FILE_LIMIT);
    let selected_manifest_count = manifest_entries
        .len()
        .min(REPOSITORY_MATCHED_FILE_LIMIT.saturating_sub(selected_lock_count));
    let file_limit_hit = matched_file_count > REPOSITORY_MATCHED_FILE_LIMIT;
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
        repo,
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

    RepositorySnapshot {
        tree_truncated,
        lock_entries,
        matched_file_count,
        selected_lock_count,
        file_limit_hit,
        byte_budget,
        manifest_scan,
    }
}

pub(super) async fn inspect_repository(
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
            result.rows.push(failed_repository_row(
                context,
                &resolved.group,
                repository,
                None,
                None,
                "default_branch_head_failed",
                &format!("{error:#}"),
            ));
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
            result.rows.push(failed_repository_row(
                context,
                &resolved.group,
                repository,
                Some(&head),
                Some(stale),
                "tree_fetch_failed",
                &format!("{error:#}"),
            ));
            return result;
        }
    };

    result.scanned = 1;
    let snapshot =
        load_repository_snapshot(github, &repo, tree, context, options, request_permits).await;
    let RepositorySnapshot {
        tree_truncated,
        lock_entries,
        matched_file_count,
        selected_lock_count,
        file_limit_hit,
        mut byte_budget,
        manifest_scan,
    } = snapshot;
    result.lockfiles_found = lock_entries.len();
    result.matched_cargo_files = matched_file_count;
    result.file_limit_exceeded = usize::from(file_limit_hit);

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
                mark_lock_unclassified(
                    &mut row,
                    "repository_file_limit_exceeded",
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
                mark_lock_unclassified(
                    &mut row,
                    "symlink_not_followed",
                    "lockfile_symlink",
                    "Cargo.lock is a symbolic link; the immutable blob is the link target path",
                );
                repository_became_partial = true;
                finalize_completeness(&mut row, true);
                result.rows.push(sanitize_row(row));
                continue;
            }
            if entry.size.is_some_and(|size| size > options.max_file_bytes) {
                mark_lock_unclassified(
                    &mut row,
                    "too_large",
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
                mark_lock_unclassified(
                    &mut row,
                    "repository_byte_budget_exceeded",
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
                    mark_lock_unclassified(
                        &mut row,
                        "fetch_failed",
                        "lockfile_fetch_failed",
                        &format!("{error:#}"),
                    );
                    repository_became_partial = true;
                    finalize_completeness(&mut row, true);
                    result.rows.push(sanitize_row(row));
                    continue;
                }
            };
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => {
                    mark_lock_unclassified(
                        &mut row,
                        "non_utf8",
                        "lockfile_non_utf8",
                        &error.to_string(),
                    );
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
                    mark_lock_unclassified(
                        &mut row,
                        "parse_failed",
                        "lockfile_parse_failed",
                        &format!("{error:#}"),
                    );
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
pub(super) enum CargoBlobFetch {
    Symlink,
    TooLarge,
    ByteBudgetExceeded,
    Failed(String),
    Fetched(Vec<u8>),
}

pub(super) struct CargoBlobFetchConfig<'a> {
    pub(super) selected_count: usize,
    pub(super) max_file_bytes: u64,
    pub(super) byte_ceiling: u64,
    pub(super) request_permits: &'a Semaphore,
    pub(super) max_in_flight: usize,
}

pub(super) async fn fetch_cargo_blobs(
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
        .map(|outcome| match outcome {
            Some(outcome) => outcome,
            None => {
                CargoBlobFetch::Failed("internal Cargo blob scheduling invariant failed".to_owned())
            }
        })
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
