//! Versioned, provider-independent dependency evidence records.

mod explanation;
mod model;

pub use explanation::{
    EvidenceReferenceV1, ExplanationStepKindV1, ExplanationStepV1, RepositoryExplanationV1,
};
pub use model::{
    ADVISORY_SOURCE_OSV, ADVISORY_SOURCE_RUSTSEC, AdvisorySnapshotV1, DirectRequirementEvidenceV1,
    EvidenceBundleV1, EvidenceCompletenessV1, EvidenceStrengthV1, LimitationV1, PackageEvidenceV1,
    RepositoryEvidenceV1, RepositoryVisibilityV1, RequirementEvidenceSourceV1, SeverityV1,
    VulnerabilityEvidenceV1,
};
