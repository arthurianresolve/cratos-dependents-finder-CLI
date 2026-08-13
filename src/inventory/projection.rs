use std::collections::BTreeSet;

use serde::Serialize;

use crate::{
    cargo_evidence::{
        MsrvSource, RecordedRelation, aggregate_os_support, evaluate_cargo_requirement,
    },
    crates_io::{DependencyDeclaration, ReverseDependencyCandidate},
    github::{GitHubHead, GitHubRepo, GitHubRepository},
    output::csv_safe,
};

use super::{
    CandidateGroup, CsvRow, ManifestScan, REPOSITORY_MATCHED_FILE_BYTE_BUDGET,
    REPOSITORY_MATCHED_FILE_LIMIT, RunContext,
};

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

pub(super) fn apply_tree_and_manifest(
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

    row.msrv_effective = manifest_scan
        .evidence
        .effective_msrv
        .clone()
        .or_else(|| manifest_scan.complete.then(|| "not_declared".to_owned()))
        .unwrap_or_else(|| "unknown".to_owned());
    row.msrv_source = match (
        manifest_scan.evidence.effective_msrv_source,
        manifest_scan.complete,
    ) {
        (MsrvSource::PackageField, _) => "package_field",
        (MsrvSource::WorkspaceInherited, _) => "workspace_inherited",
        (MsrvSource::NotDeclared, true) => "not_declared",
        (MsrvSource::NotDeclared, false) => "unknown",
    }
    .to_owned();
    row.msrv_observations_json = json_cell(&manifest_scan.evidence.msrv_observations);

    let os_support = aggregate_os_support(&manifest_scan.evidence.declarations);
    row.os_observed_targets_json = json_cell(&os_support.observed_targets);
    row.os_has_unconditional_declaration =
        if manifest_scan.evidence.declarations.is_empty() && !manifest_scan.complete {
            "unknown".to_owned()
        } else {
            os_support.has_unconditional_declaration.to_string()
        };

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

pub(super) fn finalize_completeness(row: &mut CsvRow, partial: bool) {
    if partial || !row.error_code.is_empty() {
        row.inventory_status = "partial".to_owned();
        row.evidence_completeness = "partial".to_owned();
    } else {
        row.inventory_status = "complete".to_owned();
        row.evidence_completeness = "complete".to_owned();
    }
}

pub(super) fn base_row(context: &RunContext, group: &CandidateGroup) -> CsvRow {
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
        msrv_effective: String::new(),
        msrv_source: String::new(),
        msrv_observations_json: "[]".to_owned(),
        os_observed_targets_json: "[]".to_owned(),
        os_has_unconditional_declaration: "unknown".to_owned(),
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

pub(super) fn repository_row(
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

pub(super) fn relation_name(relation: RecordedRelation) -> &'static str {
    match relation {
        RecordedRelation::Direct => "recorded_direct",
        RecordedRelation::Transitive => "recorded_transitive",
        RecordedRelation::DirectAndTransitive => "recorded_direct_and_transitive",
        RecordedRelation::PresentUnclassified => "recorded_present_unclassified",
        RecordedRelation::NotRecorded => "not_recorded",
    }
}

pub(super) fn relation_confirms_dependency(relation: RecordedRelation) -> bool {
    matches!(
        relation,
        RecordedRelation::Direct
            | RecordedRelation::Transitive
            | RecordedRelation::DirectAndTransitive
    )
}

pub(super) fn json_cell<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|error| {
        serde_json::to_string(&format!("serialization error: {error}"))
            .unwrap_or_else(|_| "\"serialization error\"".to_owned())
    })
}

pub(super) fn append_error(row: &mut CsvRow, code: &str, message: &str) {
    if !row.error_code.is_empty() {
        row.error_code.push(';');
        row.error_message.push_str(" | ");
    }
    row.error_code.push_str(code);
    row.error_message.push_str(message);
}

pub(super) fn sanitize_row(mut row: CsvRow) -> CsvRow {
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
    row.msrv_effective = csv_safe(row.msrv_effective);
    row.msrv_source = csv_safe(row.msrv_source);
    row.error_code = csv_safe(row.error_code);
    row.error_message = csv_safe(row.error_message);
    row
}
