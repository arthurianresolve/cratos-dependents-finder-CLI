use std::collections::BTreeSet;

use serde::Serialize;

use crate::{
    cargo_evidence::{
        CargoLockEvidence, CargoLockRangeEvidence, MsrvSource, RecordedRelation,
        aggregate_os_support, aggregate_os_support_from_targets, evaluate_cargo_requirement,
    },
    crates_io::{DependencyDeclaration, ReverseDependencyCandidate},
    evidence::EvidenceStrengthV1,
    github::{GitHubHead, GitHubRepo, GitHubRepository},
    output::csv_safe,
    version_selector::VersionSelector,
};

use super::{
    CandidateGroup, CsvRow, ManifestAnalysis, ManifestScan, REPOSITORY_MATCHED_FILE_BYTE_BUDGET,
    REPOSITORY_MATCHED_FILE_LIMIT, RunContext,
};

/// Typed repository observations consumed by the CSV adapter.
///
/// Keeping the snapshot state separate from serialized cells lets inspection
/// remain about evidence collection while this module owns CSV spelling and
/// completeness projection. Borrowing keeps manifest evidence out of
/// per-lockfile clones.
pub(super) struct RepositoryEvidence<'a> {
    pub(super) tree_truncated: bool,
    pub(super) tree_inventory_complete: bool,
    pub(super) manifest_scan: &'a ManifestScan,
    pub(super) enrichment_partial: bool,
}

pub(super) enum LockEvidence {
    Unclassified {
        status: &'static str,
        code: &'static str,
        message: String,
    },
    Parsed(CargoLockEvidence),
    ParsedRange(CargoLockRangeEvidence),
}

#[derive(Default)]
pub(super) struct LockProjection {
    pub(super) parsed: bool,
    pub(super) exact_occurrences: usize,
    pub(super) matching_occurrences: usize,
    pub(super) confirmed: bool,
    pub(super) partial: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    requirement_intersects: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intersection_witness: Option<crate::version_selector::PublishedVersionV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exact_pin_matches_selector: Option<bool>,
}

pub(super) fn apply_tree_and_manifest(
    row: &mut CsvRow,
    tree_truncated: bool,
    tree_inventory_complete: bool,
    manifest_scan: &ManifestScan,
    enrichment_partial: bool,
) {
    row.tree_truncated = tree_truncated.to_string();
    row.tree_inventory_complete = tree_inventory_complete.to_string();
    row.manifest_paths_json = json_cell(&manifest_scan.paths);
    let (
        declarations_present,
        declarations_json,
        effective_msrv,
        effective_msrv_source,
        msrv_observations_json,
        os_support,
    ) = match &manifest_scan.evidence {
        ManifestAnalysis::Exact(evidence) => (
            !evidence.declarations.is_empty(),
            json_cell(&evidence.declarations),
            evidence.effective_msrv.clone(),
            evidence.effective_msrv_source,
            json_cell(&evidence.msrv_observations),
            aggregate_os_support(&evidence.declarations),
        ),
        ManifestAnalysis::Range(evidence) => (
            !evidence.declarations.is_empty(),
            json_cell(&evidence.declarations),
            evidence.effective_msrv.clone(),
            evidence.effective_msrv_source,
            json_cell(&evidence.msrv_observations),
            aggregate_os_support_from_targets(
                evidence
                    .declarations
                    .iter()
                    .map(|declaration| declaration.target.as_deref()),
            ),
        ),
    };
    row.current_direct_requirements_json = declarations_json;
    row.current_direct_status = if declarations_present {
        "present"
    } else if manifest_scan.complete {
        "absent"
    } else {
        "unknown"
    }
    .to_owned();

    row.msrv_effective = effective_msrv
        .or_else(|| manifest_scan.complete.then(|| "not_declared".to_owned()))
        .unwrap_or_else(|| "unknown".to_owned());
    row.msrv_source = match (effective_msrv_source, manifest_scan.complete) {
        (MsrvSource::PackageField, _) => "package_field",
        (MsrvSource::WorkspaceInherited, _) => "workspace_inherited",
        (MsrvSource::NotDeclared, true) => "not_declared",
        (MsrvSource::NotDeclared, false) => "unknown",
    }
    .to_owned();
    row.msrv_observations_json = msrv_observations_json;

    row.os_observed_targets_json = json_cell(&os_support.observed_targets);
    row.os_has_unconditional_declaration = if !declarations_present && !manifest_scan.complete {
        "unknown".to_owned()
    } else {
        os_support.has_unconditional_declaration.to_string()
    };
    row.evidence_strength = if declarations_present {
        "current_direct_declaration"
    } else if row.published_direct_status == "present" {
        "published_direct_declaration"
    } else {
        "discovery_only"
    }
    .to_owned();

    if !tree_inventory_complete {
        append_error(
            row,
            "tree_inventory_incomplete",
            "GitHub tree inventory was incomplete; file absence is not proven",
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

pub(super) fn repository_row_for_evidence(
    context: &RunContext,
    group: &CandidateGroup,
    repository: &GitHubRepository,
    head: Option<&GitHubHead>,
    stale: Option<bool>,
    evidence: RepositoryEvidence<'_>,
) -> CsvRow {
    let mut row = repository_row(context, group, repository, head, stale);
    apply_tree_and_manifest(
        &mut row,
        evidence.tree_truncated,
        evidence.tree_inventory_complete,
        evidence.manifest_scan,
        evidence.enrichment_partial,
    );
    row
}

pub(super) fn project_lock_evidence(
    row: &mut CsvRow,
    evidence: LockEvidence,
    repository_baseline_partial: bool,
) -> LockProjection {
    match evidence {
        LockEvidence::Unclassified {
            status,
            code,
            message,
        } => {
            row.lock_status = status.to_owned();
            row.exact_resolution_status = exact_only_state(row, "unknown").to_owned();
            row.matching_resolution_status = "unknown".to_owned();
            row.recorded_relation = exact_only_state(row, "unknown").to_owned();
            row.matching_recorded_relation = "unknown".to_owned();
            append_error(row, code, &message);
            finalize_completeness(row, true);
            LockProjection {
                partial: true,
                ..LockProjection::default()
            }
        }
        LockEvidence::Parsed(evidence) => {
            row.direct_relation_witness_json = json_cell(&evidence.direct_witness);
            row.transitive_relation_witness_json = json_cell(&evidence.transitive_witness);
            row.evidence_strength = evidence_strength_name(EvidenceStrengthV1::classify(
                Some(&evidence),
                row.current_direct_status == "present",
                row.published_direct_status == "present",
            ))
            .to_owned();
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
            row.matching_resolution_status = row.exact_resolution_status.clone();
            row.matching_occurrence_count = evidence.exact_occurrences;
            row.matching_crates_io_occurrence_count = evidence.exact_crates_io_occurrences;
            row.matching_resolved_versions_json = if evidence.exact_occurrences > 0 {
                json_cell(std::slice::from_ref(&evidence.target_version))
            } else {
                "[]".to_owned()
            };
            row.matching_recorded_relation = row.recorded_relation.clone();
            row.matching_direct_relation_witness_json = row.direct_relation_witness_json.clone();
            row.matching_transitive_relation_witness_json =
                row.transitive_relation_witness_json.clone();
            row.shortest_dependency_depth = evidence
                .shortest_depth
                .map(|depth| depth.to_string())
                .unwrap_or_default();

            let graph_partial = evidence.exact_occurrences > 0 && !evidence.graph_analysis_complete;
            if graph_partial {
                append_error(
                    row,
                    "lock_graph_unclassified",
                    evidence
                        .graph_diagnostic
                        .as_deref()
                        .unwrap_or("lock graph could not be classified"),
                );
            }
            finalize_completeness(row, repository_baseline_partial || graph_partial);
            LockProjection {
                parsed: true,
                exact_occurrences: evidence.exact_occurrences,
                matching_occurrences: evidence.exact_occurrences,
                confirmed: evidence.exact_occurrences > 0
                    && relation_confirms_dependency(evidence.recorded_relation),
                partial: graph_partial,
            }
        }
        LockEvidence::ParsedRange(evidence) => {
            row.lock_status = "parsed".to_owned();
            row.resolved_target_versions_json = json_cell(&evidence.resolved_versions);
            row.resolved_target_sources_json = json_cell(&evidence.occurrences);
            row.exact_resolution_status = "not_applicable".to_owned();
            row.exact_occurrence_count = 0;
            row.exact_crates_io_occurrence_count = 0;
            row.matching_resolution_status = if evidence.matching_occurrence_count > 0 {
                "present"
            } else {
                "absent"
            }
            .to_owned();
            row.matching_occurrence_count = evidence.matching_occurrence_count;
            row.matching_crates_io_occurrence_count = evidence.matching_crates_io_occurrences;
            row.matching_resolved_versions_json = json_cell(&evidence.matching_versions);
            row.range_matching_resolutions_json = json_cell(&evidence.matching_resolutions);
            row.recorded_relation = "not_applicable".to_owned();
            row.matching_recorded_relation = relation_name(evidence.recorded_relation).to_owned();
            row.shortest_dependency_depth.clear();
            row.direct_relation_witness_json = "null".to_owned();
            row.transitive_relation_witness_json = "null".to_owned();
            row.matching_direct_relation_witness_json = json_cell(&evidence.direct_witness);
            row.matching_transitive_relation_witness_json = json_cell(&evidence.transitive_witness);
            row.evidence_strength = if evidence.matching_occurrence_count > 0
                && relation_confirms_dependency(evidence.recorded_relation)
            {
                "verified_matching_graph"
            } else if evidence.matching_occurrence_count > 0 {
                "matching_present_unclassified"
            } else if row.current_direct_status == "present" {
                "current_direct_declaration"
            } else if row.published_direct_status == "present" {
                "published_direct_declaration"
            } else {
                "discovery_only"
            }
            .to_owned();

            let graph_partial =
                evidence.matching_occurrence_count > 0 && !evidence.graph_analysis_complete;
            if graph_partial {
                append_error(
                    row,
                    "lock_graph_unclassified",
                    evidence
                        .graph_diagnostic
                        .as_deref()
                        .unwrap_or("lock graph could not be classified"),
                );
            }
            finalize_completeness(row, repository_baseline_partial || graph_partial);
            LockProjection {
                parsed: true,
                matching_occurrences: evidence.matching_occurrence_count,
                confirmed: evidence.matching_occurrence_count > 0
                    && relation_confirms_dependency(evidence.recorded_relation),
                partial: graph_partial,
                ..LockProjection::default()
            }
        }
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
    let mut reasons = Vec::new();
    if row.published_direct_status == "present" {
        reasons.push("published_direct_declaration");
    }
    if row.current_direct_status == "present" {
        reasons.push("current_direct_declaration");
    }
    if row.exact_occurrence_count > 0 {
        reasons.push("exact_lockfile_occurrence");
    }
    if row.target_selector_kind == "range" && row.matching_occurrence_count > 0 {
        reasons.push("matching_lockfile_occurrence");
    }
    let selected_relation = if row.target_selector_kind == "range" {
        row.matching_recorded_relation.as_str()
    } else {
        row.recorded_relation.as_str()
    };
    if matches!(
        selected_relation,
        "recorded_direct" | "recorded_transitive" | "recorded_direct_and_transitive"
    ) {
        reasons.push("recorded_dependency_path");
    }
    row.inclusion_reasons_json = json_cell(&reasons);
    let limitations = row
        .error_code
        .split(';')
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .collect::<Vec<_>>();
    row.scope_limitations_json = json_cell(&limitations);
}

pub(super) fn base_row(context: &RunContext, group: &CandidateGroup) -> CsvRow {
    let mut declarations = group
        .published
        .iter()
        .flat_map(|candidate| {
            candidate
                .declarations
                .iter()
                .map(|declaration| published_cell(context, candidate, declaration))
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
    let (accepts, exact_pin, intersects, pin_matches_selector) = match &context.version_selector {
        VersionSelector::Exact(version) => {
            let evaluations = declarations
                .iter()
                .map(|declaration| evaluate_cargo_requirement(&declaration.requirement, version))
                .collect::<Vec<_>>();
            let accepts = tri_state(
                evaluations.iter().map(|evaluation| evaluation.accepts),
                enrichment_unknown,
            );
            let exact_pin = tri_state(
                evaluations
                    .iter()
                    .map(|evaluation| evaluation.explicit_exact_pin),
                enrichment_unknown,
            );
            (accepts.clone(), exact_pin.clone(), accepts, exact_pin)
        }
        VersionSelector::Range(_) => (
            "not_applicable".to_owned(),
            "not_applicable".to_owned(),
            tri_state(
                declarations
                    .iter()
                    .map(|declaration| declaration.requirement_intersects),
                enrichment_unknown,
            ),
            tri_state(
                declarations
                    .iter()
                    .map(|declaration| declaration.exact_pin_matches_selector),
                enrichment_unknown,
            ),
        ),
    };
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
        target_version: context
            .exact_version()
            .map(ToString::to_string)
            .unwrap_or_default(),
        target_repository_url: context.target_repository_url.clone().unwrap_or_default(),
        globally_exhaustive: context.globally_exhaustive,
        candidate_scope: context.candidate_scope.clone(),
        repository_scope: context.repository_scope.as_str().to_owned(),
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
        repository_visibility: "unknown".to_owned(),
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
        exact_resolution_status: exact_only_state_for_selector(
            &context.version_selector,
            "unknown",
        )
        .to_owned(),
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
        recorded_relation: exact_only_state_for_selector(&context.version_selector, "unknown")
            .to_owned(),
        shortest_dependency_depth: String::new(),
        direct_relation_witness_json: "null".to_owned(),
        transitive_relation_witness_json: "null".to_owned(),
        evidence_strength: if group.published.is_empty() {
            "discovery_only"
        } else {
            "published_direct_declaration"
        }
        .to_owned(),
        inclusion_reasons_json: "[]".to_owned(),
        scope_limitations_json: "[]".to_owned(),
        cache_status: "cold".to_owned(),
        reused_from_scan_id: String::new(),
        evidence_completeness: "unknown".to_owned(),
        error_code: String::new(),
        error_message: String::new(),
        csv_schema_version: crate::inventory::csv_schema::CSV_SCHEMA_VERSION,
        target_selector_kind: match context.version_selector.kind() {
            crate::version_selector::VersionSelectorKind::Exact => "exact",
            crate::version_selector::VersionSelectorKind::Range => "range",
        }
        .to_owned(),
        target_version_requirement: context.version_selector.canonical_spec(),
        target_version_catalog_sha256: context
            .version_catalog
            .as_deref()
            .map(|catalog| catalog.sha256.clone())
            .unwrap_or_default(),
        tree_inventory_complete: "unknown".to_owned(),
        any_requirement_intersects: intersects,
        any_exact_pin_matches_selector: pin_matches_selector,
        matching_resolution_status: "unknown".to_owned(),
        matching_occurrence_count: 0,
        matching_crates_io_occurrence_count: 0,
        matching_resolved_versions_json: "[]".to_owned(),
        range_matching_resolutions_json: "[]".to_owned(),
        matching_recorded_relation: "unknown".to_owned(),
        matching_direct_relation_witness_json: "null".to_owned(),
        matching_transitive_relation_witness_json: "null".to_owned(),
    }
}

fn exact_only_state<'a>(row: &CsvRow, exact_state: &'a str) -> &'a str {
    if row.target_selector_kind == "range" {
        "not_applicable"
    } else {
        exact_state
    }
}

fn exact_only_state_for_selector<'a>(selector: &VersionSelector, exact_state: &'a str) -> &'a str {
    if matches!(selector, VersionSelector::Range(_)) {
        "not_applicable"
    } else {
        exact_state
    }
}

fn published_cell(
    context: &RunContext,
    candidate: &ReverseDependencyCandidate,
    declaration: &DependencyDeclaration,
) -> PublishedDeclarationCell {
    let range_evaluation = match &context.version_selector {
        VersionSelector::Exact(_) => None,
        VersionSelector::Range(_) => Some(context.evaluate_range_requirement(&declaration.req)),
    };
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
        requirement_intersects: range_evaluation
            .as_ref()
            .and_then(|evaluation| evaluation.intersects),
        intersection_witness: range_evaluation
            .as_ref()
            .and_then(|evaluation| evaluation.witness.clone()),
        exact_pin_matches_selector: range_evaluation.and_then(|evaluation| {
            if evaluation.error.is_some() {
                None
            } else {
                Some(evaluation.pin_matches_selector == Some(true))
            }
        }),
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
    row.repository_visibility = repository.effective_visibility().as_str().to_owned();
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

fn evidence_strength_name(strength: EvidenceStrengthV1) -> &'static str {
    match strength {
        EvidenceStrengthV1::VerifiedExactGraph => "verified_exact_graph",
        EvidenceStrengthV1::ExactPresentUnclassified => "exact_present_unclassified",
        EvidenceStrengthV1::CurrentDirectDeclaration => "current_direct_declaration",
        EvidenceStrengthV1::PublishedDirectDeclaration => "published_direct_declaration",
        EvidenceStrengthV1::DiscoveryOnly => "discovery_only",
    }
}

pub(super) fn json_cell<T: Serialize + ?Sized>(value: &T) -> String {
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
    row.target_version_requirement = csv_safe(row.target_version_requirement);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo_evidence::{ManifestEvidence, MsrvSource};
    use semver::Version;

    #[test]
    fn recovered_initial_truncation_is_not_projected_as_partial() {
        let manifest_scan = ManifestScan {
            evidence: ManifestAnalysis::Exact(ManifestEvidence {
                target_name: "fs2".to_owned(),
                target_version: Version::new(0, 4, 3),
                manifests_supplied: 0,
                manifests_parsed: 0,
                declarations: Vec::new(),
                diagnostics: Vec::new(),
                analysis_complete: true,
                msrv_observations: Vec::new(),
                effective_msrv: None,
                effective_msrv_source: MsrvSource::NotDeclared,
            }),
            paths: Vec::new(),
            complete: true,
            diagnostics: Vec::new(),
        };
        let mut row = CsvRow::default();

        apply_tree_and_manifest(&mut row, true, true, &manifest_scan, false);
        finalize_completeness(&mut row, false);

        assert_eq!(row.tree_truncated, "true");
        assert_eq!(row.tree_inventory_complete, "true");
        assert_eq!(row.inventory_status, "complete");
        assert!(row.error_code.is_empty());
    }
}
