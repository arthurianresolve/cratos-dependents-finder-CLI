//! Projection from completed scan rows into the canonical evidence model.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use semver::Version;
use serde::Deserialize;

use crate::{
    cargo_evidence::{
        DependencyWitnessV1, DirectDeclaration, PackageIdentityV1, RecordedRelation,
        evaluate_cargo_requirement,
    },
    evidence::{
        DirectRequirementEvidenceV1, EvidenceBundleV1, EvidenceCompletenessV1, EvidenceReferenceV1,
        EvidenceStrengthV1, ExplanationStepKindV1, ExplanationStepV1, LimitationV1,
        PackageEvidenceV1, RepositoryEvidenceV1, RepositoryExplanationV1, RepositoryVisibilityV1,
        RequirementEvidenceSourceV1,
    },
};

use super::{CsvRow, ScanSummary};

#[derive(Deserialize)]
struct PublishedRequirementCell {
    dependent_crate: String,
    requirement: String,
}

struct RepositoryBuilder {
    evidence: RepositoryEvidenceV1,
}

pub(super) fn build_evidence_bundle(
    summary: &ScanSummary,
    rows: &[CsvRow],
) -> Result<EvidenceBundleV1> {
    let generated_at = DateTime::parse_from_rfc3339(&summary.observed_at_utc)
        .context("parsing scan observation time")?
        .with_timezone(&Utc);
    let target_version = Version::parse(&summary.target_version)
        .with_context(|| format!("parsing target version {}", summary.target_version))?;
    let target = PackageIdentityV1 {
        name: summary.target_crate.clone(),
        version: target_version.clone(),
        source: None,
    };
    let mut repositories = BTreeMap::<String, RepositoryBuilder>::new();

    for row in rows {
        let repository = if row.github_full_name.is_empty() {
            row.repository_url.clone()
        } else {
            row.github_full_name.clone()
        };
        let builder = repositories.entry(repository.clone()).or_insert_with(|| {
            let completeness = parse_completeness(&row.evidence_completeness);
            let strength = parse_strength(&row.evidence_strength);
            RepositoryBuilder {
                evidence: RepositoryEvidenceV1 {
                    repository: repository.clone(),
                    repository_id: (!row.github_repository_id.is_empty())
                        .then(|| row.github_repository_id.clone()),
                    visibility: parse_visibility(&row.repository_visibility),
                    head_committed_at: parse_optional_time(&row.head_committed_at),
                    completeness,
                    requirements: Vec::new(),
                    exact_resolution_count: 0,
                    recorded_relation: RecordedRelation::NotRecorded,
                    direct_witness: None,
                    transitive_witness: None,
                    msrv: parse_msrv(&row.msrv_effective),
                    package_inventory_complete: false,
                    packages: vec![PackageEvidenceV1 {
                        package: target.clone(),
                        license_expression: None,
                    }],
                    vulnerabilities: Vec::new(),
                    explanation: RepositoryExplanationV1 {
                        repository: repository.clone(),
                        observed_at: generated_at,
                        strength,
                        completeness,
                        steps: base_steps(row),
                        limitations: row_limitations(row),
                        direct_witness: None,
                        transitive_witness: None,
                    },
                },
            }
        });

        builder.evidence.completeness = worst_completeness(
            builder.evidence.completeness,
            parse_completeness(&row.evidence_completeness),
        );
        builder.evidence.explanation.completeness = builder.evidence.completeness;
        builder.evidence.explanation.strength = strongest(
            builder.evidence.explanation.strength,
            parse_strength(&row.evidence_strength),
        );
        builder.evidence.exact_resolution_count = builder
            .evidence
            .exact_resolution_count
            .saturating_add(row.exact_occurrence_count);
        builder.evidence.recorded_relation = merge_relation(
            builder.evidence.recorded_relation,
            parse_relation(&row.recorded_relation),
        );

        retain_witness(
            &mut builder.evidence.direct_witness,
            parse_witness(&row.direct_relation_witness_json),
        );
        retain_witness(
            &mut builder.evidence.transitive_witness,
            parse_witness(&row.transitive_relation_witness_json),
        );
        builder.evidence.explanation.direct_witness = builder.evidence.direct_witness.clone();
        builder.evidence.explanation.transitive_witness =
            builder.evidence.transitive_witness.clone();

        add_current_requirements(&mut builder.evidence, row);
        add_published_requirements(&mut builder.evidence, row, &target_version);
        builder.evidence.explanation.steps.extend(lock_steps(row));
        builder
            .evidence
            .explanation
            .limitations
            .extend(row_limitations(row));
    }

    let mut limitations = vec![LimitationV1 {
        code: "globally_non_exhaustive".to_owned(),
        message: "GitHub and registry discovery are bounded and non-exhaustive".to_owned(),
    }];
    if summary.partial {
        limitations.push(LimitationV1 {
            code: "scan_partial".to_owned(),
            message: "one or more repository observations were partial or unavailable".to_owned(),
        });
    }

    Ok(EvidenceBundleV1 {
        schema_version: EvidenceBundleV1::SCHEMA_VERSION,
        generated_at,
        target,
        globally_exhaustive: summary.globally_exhaustive,
        repositories: repositories
            .into_values()
            .map(|builder| builder.evidence)
            .collect(),
        advisory_snapshots: Vec::new(),
        limitations,
    }
    .normalized())
}

fn add_current_requirements(repository: &mut RepositoryEvidenceV1, row: &CsvRow) {
    let Ok(declarations) =
        serde_json::from_str::<Vec<DirectDeclaration>>(&row.current_direct_requirements_json)
    else {
        return;
    };
    repository
        .requirements
        .extend(
            declarations
                .into_iter()
                .map(|declaration| DirectRequirementEvidenceV1 {
                    source: RequirementEvidenceSourceV1::CurrentManifest,
                    manifest_path: declaration.manifest_path,
                    package_name: declaration.package_name,
                    requirement: declaration.requirement,
                    accepts_target: declaration.requirement_accepts,
                    explicit_exact_pin: declaration.explicit_exact_pin,
                }),
        );
}

fn add_published_requirements(
    repository: &mut RepositoryEvidenceV1,
    row: &CsvRow,
    target_version: &Version,
) {
    let Ok(declarations) =
        serde_json::from_str::<Vec<PublishedRequirementCell>>(&row.published_requirements_json)
    else {
        return;
    };
    repository
        .requirements
        .extend(declarations.into_iter().map(|declaration| {
            let evaluation = evaluate_cargo_requirement(&declaration.requirement, target_version);
            DirectRequirementEvidenceV1 {
                source: RequirementEvidenceSourceV1::PublishedRegistry,
                manifest_path: format!("crates.io:{}", declaration.dependent_crate),
                package_name: Some(declaration.dependent_crate),
                requirement: Some(declaration.requirement),
                accepts_target: evaluation.accepts,
                explicit_exact_pin: evaluation.explicit_exact_pin,
            }
        }));
}

fn base_steps(row: &CsvRow) -> Vec<ExplanationStepV1> {
    let mut steps = vec![
        ExplanationStepV1 {
            kind: ExplanationStepKindV1::InputResolution,
            statement: format!(
                "resolved input to {} {}",
                row.target_crate, row.target_version
            ),
            reference: None,
        },
        ExplanationStepV1 {
            kind: ExplanationStepKindV1::CandidateDiscovery,
            statement: format!("candidate sources: {}", row.candidate_sources_json),
            reference: None,
        },
        ExplanationStepV1 {
            kind: ExplanationStepKindV1::RepositoryIdentity,
            statement: format!(
                "canonical repository {} (id {})",
                row.github_full_name, row.github_repository_id
            ),
            reference: None,
        },
        ExplanationStepV1 {
            kind: ExplanationStepKindV1::VisibilityDecision,
            statement: format!(
                "visibility {} under {} scope",
                row.repository_visibility, row.repository_scope
            ),
            reference: None,
        },
    ];
    if !row.head_sha.is_empty() {
        steps.push(ExplanationStepV1 {
            kind: ExplanationStepKindV1::ImmutableRevision,
            statement: format!("default branch {} frozen at head", row.default_branch),
            reference: Some(EvidenceReferenceV1 {
                commit_sha: Some(row.head_sha.clone()),
                tree_sha: (!row.tree_sha.is_empty()).then(|| row.tree_sha.clone()),
                path: None,
                blob_sha: None,
            }),
        });
    }
    if row.current_direct_status == "present" {
        steps.push(ExplanationStepV1 {
            kind: ExplanationStepKindV1::ManifestDeclaration,
            statement: "current default-branch manifest declares the target".to_owned(),
            reference: None,
        });
    }
    steps
}

fn lock_steps(row: &CsvRow) -> Vec<ExplanationStepV1> {
    if row.cargo_lock_path.is_empty() {
        return Vec::new();
    }
    vec![ExplanationStepV1 {
        kind: ExplanationStepKindV1::LockResolution,
        statement: format!(
            "{}; relation {}; exact occurrences {}",
            row.lock_status, row.recorded_relation, row.exact_occurrence_count
        ),
        reference: Some(EvidenceReferenceV1 {
            commit_sha: (!row.head_sha.is_empty()).then(|| row.head_sha.clone()),
            tree_sha: (!row.tree_sha.is_empty()).then(|| row.tree_sha.clone()),
            path: Some(row.cargo_lock_path.clone()),
            blob_sha: (!row.cargo_lock_blob_sha.is_empty())
                .then(|| row.cargo_lock_blob_sha.clone()),
        }),
    }]
}

fn row_limitations(row: &CsvRow) -> Vec<LimitationV1> {
    let codes = row
        .error_code
        .split(';')
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .collect::<Vec<_>>();
    let messages = row.error_message.split(" | ").collect::<Vec<_>>();
    codes
        .into_iter()
        .enumerate()
        .map(|(index, code)| LimitationV1 {
            code: code.to_owned(),
            message: messages
                .get(index)
                .copied()
                .unwrap_or("evidence collection limitation")
                .to_owned(),
        })
        .collect()
}

fn parse_witness(value: &str) -> Option<DependencyWitnessV1> {
    serde_json::from_str::<Option<DependencyWitnessV1>>(value)
        .ok()
        .flatten()
}

fn retain_witness(
    current: &mut Option<DependencyWitnessV1>,
    candidate: Option<DependencyWitnessV1>,
) {
    let Some(candidate) = candidate else {
        return;
    };
    let replace = current.as_ref().is_none_or(|existing| {
        (candidate.packages.len(), &candidate.packages)
            < (existing.packages.len(), &existing.packages)
    });
    if replace {
        *current = Some(candidate);
    }
}

fn parse_optional_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn parse_msrv(value: &str) -> Option<Version> {
    Version::parse(value).ok()
}

fn parse_visibility(value: &str) -> RepositoryVisibilityV1 {
    match value {
        "public" => RepositoryVisibilityV1::Public,
        "private" => RepositoryVisibilityV1::Private,
        "internal" => RepositoryVisibilityV1::Internal,
        _ => RepositoryVisibilityV1::Unknown,
    }
}

fn parse_completeness(value: &str) -> EvidenceCompletenessV1 {
    match value {
        "complete" => EvidenceCompletenessV1::Complete,
        "partial" => EvidenceCompletenessV1::Partial,
        _ => EvidenceCompletenessV1::Unavailable,
    }
}

fn parse_strength(value: &str) -> EvidenceStrengthV1 {
    match value {
        "verified_exact_graph" => EvidenceStrengthV1::VerifiedExactGraph,
        "exact_present_unclassified" => EvidenceStrengthV1::ExactPresentUnclassified,
        "current_direct_declaration" => EvidenceStrengthV1::CurrentDirectDeclaration,
        "published_direct_declaration" => EvidenceStrengthV1::PublishedDirectDeclaration,
        _ => EvidenceStrengthV1::DiscoveryOnly,
    }
}

fn strongest(left: EvidenceStrengthV1, right: EvidenceStrengthV1) -> EvidenceStrengthV1 {
    left.min(right)
}

fn worst_completeness(
    left: EvidenceCompletenessV1,
    right: EvidenceCompletenessV1,
) -> EvidenceCompletenessV1 {
    left.max(right)
}

fn parse_relation(value: &str) -> RecordedRelation {
    match value {
        "recorded_direct" => RecordedRelation::Direct,
        "recorded_transitive" => RecordedRelation::Transitive,
        "recorded_direct_and_transitive" => RecordedRelation::DirectAndTransitive,
        "recorded_present_unclassified" => RecordedRelation::PresentUnclassified,
        _ => RecordedRelation::NotRecorded,
    }
}

fn merge_relation(left: RecordedRelation, right: RecordedRelation) -> RecordedRelation {
    use RecordedRelation::{
        Direct, DirectAndTransitive, NotRecorded, PresentUnclassified, Transitive,
    };
    match (left, right) {
        (DirectAndTransitive, _) | (_, DirectAndTransitive) => DirectAndTransitive,
        (Direct, Transitive) | (Transitive, Direct) => DirectAndTransitive,
        (Direct, _) | (_, Direct) => Direct,
        (Transitive, _) | (_, Transitive) => Transitive,
        (PresentUnclassified, _) | (_, PresentUnclassified) => PresentUnclassified,
        (NotRecorded, NotRecorded) => NotRecorded,
    }
}
