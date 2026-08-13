use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::cargo_evidence::{
    CargoLockEvidence, DependencyWitnessV1, PackageIdentityV1, RecordedRelation,
};

use super::RepositoryExplanationV1;

pub const ADVISORY_SOURCE_RUSTSEC: &str = "rustsec";
pub const ADVISORY_SOURCE_OSV: &str = "osv";

/// Whether collected evidence can support negative conclusions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompletenessV1 {
    Complete,
    Partial,
    Unavailable,
}

/// Categorical evidence strength, independent of completeness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrengthV1 {
    VerifiedExactGraph,
    ExactPresentUnclassified,
    CurrentDirectDeclaration,
    PublishedDirectDeclaration,
    DiscoveryOnly,
}

impl EvidenceStrengthV1 {
    /// Classify the strongest positive observation without conflating it with completeness.
    pub fn classify(
        lock: Option<&CargoLockEvidence>,
        has_current_declaration: bool,
        has_published_declaration: bool,
    ) -> Self {
        if lock.is_some_and(|evidence| {
            evidence.exact_occurrences > 0
                && evidence.graph_analysis_complete
                && matches!(
                    evidence.recorded_relation,
                    RecordedRelation::Direct
                        | RecordedRelation::Transitive
                        | RecordedRelation::DirectAndTransitive
                )
        }) {
            Self::VerifiedExactGraph
        } else if lock.is_some_and(|evidence| evidence.exact_occurrences > 0) {
            Self::ExactPresentUnclassified
        } else if has_current_declaration {
            Self::CurrentDirectDeclaration
        } else if has_published_declaration {
            Self::PublishedDirectDeclaration
        } else {
            Self::DiscoveryOnly
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryVisibilityV1 {
    Public,
    Private,
    Internal,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityV1 {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LimitationV1 {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementEvidenceSourceV1 {
    #[default]
    CurrentManifest,
    PublishedRegistry,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DirectRequirementEvidenceV1 {
    #[serde(default)]
    pub source: RequirementEvidenceSourceV1,
    pub manifest_path: String,
    pub package_name: Option<String>,
    pub requirement: Option<String>,
    pub accepts_target: Option<bool>,
    pub explicit_exact_pin: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PackageEvidenceV1 {
    pub package: PackageIdentityV1,
    pub license_expression: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct VulnerabilityEvidenceV1 {
    pub package: PackageIdentityV1,
    pub advisory_id: String,
    pub source: String,
    pub severity: Option<SeverityV1>,
    pub withdrawn: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AdvisorySnapshotV1 {
    pub source: String,
    pub revision: String,
    pub sha256: String,
    pub collected_at: DateTime<Utc>,
}

/// Typed evidence retained for one canonical repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryEvidenceV1 {
    pub repository: String,
    pub repository_id: Option<String>,
    pub visibility: RepositoryVisibilityV1,
    pub head_committed_at: Option<DateTime<Utc>>,
    pub completeness: EvidenceCompletenessV1,
    pub requirements: Vec<DirectRequirementEvidenceV1>,
    pub exact_resolution_count: usize,
    pub recorded_relation: RecordedRelation,
    pub direct_witness: Option<DependencyWitnessV1>,
    pub transitive_witness: Option<DependencyWitnessV1>,
    pub msrv: Option<Version>,
    /// True only when `packages` covers the full resolved dependency graph.
    /// Standalone target evidence leaves this false even when all selected
    /// repository files were read successfully.
    #[serde(default)]
    pub package_inventory_complete: bool,
    pub packages: Vec<PackageEvidenceV1>,
    pub vulnerabilities: Vec<VulnerabilityEvidenceV1>,
    pub explanation: RepositoryExplanationV1,
}

impl RepositoryEvidenceV1 {
    fn normalize(&mut self) {
        self.requirements.sort();
        self.requirements.dedup();
        self.packages.sort();
        self.packages.dedup();
        self.vulnerabilities.sort();
        self.vulnerabilities.dedup();
        self.explanation.normalize();
    }
}

/// Canonical input to offline explanation and policy evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceBundleV1 {
    pub schema_version: u16,
    pub generated_at: DateTime<Utc>,
    pub target: PackageIdentityV1,
    pub globally_exhaustive: bool,
    pub repositories: Vec<RepositoryEvidenceV1>,
    pub advisory_snapshots: Vec<AdvisorySnapshotV1>,
    pub limitations: Vec<LimitationV1>,
}

impl EvidenceBundleV1 {
    pub const SCHEMA_VERSION: u16 = 1;

    /// Return a stable representation suitable for hashing or serialization.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        for repository in &mut self.repositories {
            repository.normalize();
        }
        self.repositories.sort_by(|left, right| {
            (&left.repository, &left.repository_id).cmp(&(&right.repository, &right.repository_id))
        });
        self.advisory_snapshots.sort();
        self.advisory_snapshots.dedup();
        self.limitations.sort();
        self.limitations.dedup();
        self
    }

    pub fn schema_is_supported(&self) -> bool {
        self.schema_version == Self::SCHEMA_VERSION
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    use crate::evidence::{EvidenceReferenceV1, ExplanationStepKindV1, ExplanationStepV1};

    fn package(name: &str) -> PackageIdentityV1 {
        PackageIdentityV1 {
            name: name.to_owned(),
            version: Version::new(1, 0, 0),
            source: None,
        }
    }

    fn repository(name: &str) -> RepositoryEvidenceV1 {
        let observed_at = Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0).unwrap();
        RepositoryEvidenceV1 {
            repository: name.to_owned(),
            repository_id: None,
            visibility: RepositoryVisibilityV1::Public,
            head_committed_at: Some(observed_at),
            completeness: EvidenceCompletenessV1::Complete,
            requirements: Vec::new(),
            exact_resolution_count: 0,
            recorded_relation: RecordedRelation::NotRecorded,
            direct_witness: None,
            transitive_witness: None,
            msrv: None,
            package_inventory_complete: false,
            packages: Vec::new(),
            vulnerabilities: Vec::new(),
            explanation: RepositoryExplanationV1 {
                repository: name.to_owned(),
                observed_at,
                strength: EvidenceStrengthV1::DiscoveryOnly,
                completeness: EvidenceCompletenessV1::Complete,
                steps: vec![ExplanationStepV1 {
                    kind: ExplanationStepKindV1::RepositoryIdentity,
                    statement: name.to_owned(),
                    reference: Some(EvidenceReferenceV1::default()),
                }],
                limitations: Vec::new(),
                direct_witness: None,
                transitive_witness: None,
            },
        }
    }

    #[test]
    fn normalization_is_stable_and_deduplicates_set_like_evidence() {
        let generated_at = Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0).unwrap();
        let bundle = EvidenceBundleV1 {
            schema_version: EvidenceBundleV1::SCHEMA_VERSION,
            generated_at,
            target: package("target"),
            globally_exhaustive: false,
            repositories: vec![repository("z/repo"), repository("a/repo")],
            advisory_snapshots: Vec::new(),
            limitations: vec![
                LimitationV1 {
                    code: "indexed_only".to_owned(),
                    message: "bounded".to_owned(),
                },
                LimitationV1 {
                    code: "indexed_only".to_owned(),
                    message: "bounded".to_owned(),
                },
            ],
        }
        .normalized();

        assert_eq!(bundle.repositories[0].repository, "a/repo");
        assert_eq!(bundle.limitations.len(), 1);
        assert_eq!(
            serde_json::to_string(&bundle).unwrap(),
            serde_json::to_string(&bundle.clone().normalized()).unwrap()
        );
    }

    #[test]
    fn evidence_strength_prefers_verified_graph_over_declarations() {
        let lock = crate::cargo_evidence::analyze_cargo_lock(
            r#"
version = 3

[[package]]
name = "app"
version = "1.0.0"
dependencies = ["target"]

[[package]]
name = "target"
version = "1.0.0"
"#,
            "target",
            &Version::new(1, 0, 0),
        )
        .unwrap();
        assert_eq!(
            EvidenceStrengthV1::classify(Some(&lock), true, true),
            EvidenceStrengthV1::VerifiedExactGraph
        );
        assert_eq!(
            EvidenceStrengthV1::classify(None, true, true),
            EvidenceStrengthV1::CurrentDirectDeclaration
        );
    }
}
