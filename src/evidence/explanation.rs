use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cargo_evidence::DependencyWitnessV1;

use super::{EvidenceCompletenessV1, EvidenceStrengthV1, LimitationV1};

/// The ordered stages which justify retaining a repository as evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationStepKindV1 {
    InputResolution,
    CandidateDiscovery,
    RepositoryIdentity,
    VisibilityDecision,
    ImmutableRevision,
    ManifestDeclaration,
    LockResolution,
    PolicyConclusion,
    SourceSnapshot,
    CacheReuse,
}

/// Immutable source coordinates supporting an explanation step.
#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EvidenceReferenceV1 {
    pub commit_sha: Option<String>,
    pub tree_sha: Option<String>,
    pub path: Option<String>,
    pub blob_sha: Option<String>,
}

/// One deterministic link in a repository's evidence chain.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExplanationStepV1 {
    pub kind: ExplanationStepKindV1,
    pub statement: String,
    pub reference: Option<EvidenceReferenceV1>,
}

/// Human- and machine-readable justification for one retained repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryExplanationV1 {
    pub repository: String,
    pub observed_at: DateTime<Utc>,
    pub strength: EvidenceStrengthV1,
    pub completeness: EvidenceCompletenessV1,
    pub steps: Vec<ExplanationStepV1>,
    pub limitations: Vec<LimitationV1>,
    pub direct_witness: Option<DependencyWitnessV1>,
    pub transitive_witness: Option<DependencyWitnessV1>,
}

impl RepositoryExplanationV1 {
    pub fn normalize(&mut self) {
        self.steps.sort();
        self.steps.dedup();
        self.limitations.sort();
        self.limitations.dedup();
    }
}
