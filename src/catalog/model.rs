use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    cargo_evidence::{DependencyWitnessV1, PackageIdentityV1, RecordedRelation},
    coordinator::{ArtifactRefV1, JobId, TaskId},
    evidence::{
        DirectRequirementEvidenceV1, EvidenceBundleV1, EvidenceCompletenessV1, EvidenceStrengthV1,
        LimitationV1, RepositoryVisibilityV1, RequirementEvidenceSourceV1,
    },
};

pub const CATALOG_SCHEMA_VERSION_V1: u16 = 1;
pub const TRIGRAM_INDEX_VERSION_V1: u16 = 1;
pub const DEFAULT_PAGE_SIZE: usize = 250;
pub const MAX_PAGE_SIZE: usize = 1_000;
pub const MAX_PACKAGES_PER_RESULT: usize = 100;
pub const MAX_SEARCH_CHARS: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InventoryNamespaceV1 {
    Public,
    Private { credential_profile_id: String },
}

impl InventoryNamespaceV1 {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if let Self::Private {
            credential_profile_id,
        } = self
            && (credential_profile_id.trim().is_empty()
                || credential_profile_id.trim() != credential_profile_id)
        {
            return Err(CatalogError::InvalidInput(
                "private namespace requires a normalized credential profile".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryAccessV1 {
    pub principal_id: String,
    #[serde(default)]
    pub private_credential_profiles: BTreeSet<String>,
}

impl InventoryAccessV1 {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.principal_id.trim().is_empty() || self.principal_id.trim() != self.principal_id {
            return Err(CatalogError::InvalidInput(
                "principal_id must be non-empty and normalized".to_owned(),
            ));
        }
        if self
            .private_credential_profiles
            .iter()
            .any(|profile| profile.trim().is_empty() || profile.as_str() != profile.trim())
        {
            return Err(CatalogError::InvalidInput(
                "private credential profiles must be non-empty and normalized".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn allows(&self, namespace: &InventoryNamespaceV1) -> bool {
        match namespace {
            InventoryNamespaceV1::Public => true,
            InventoryNamespaceV1::Private {
                credential_profile_id,
            } => self
                .private_credential_profiles
                .contains(credential_profile_id),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RepositoryKeyV1 {
    pub namespace: InventoryNamespaceV1,
    /// Stable GitHub numeric repository identity, encoded as text.
    pub repository_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryRepositoryV1 {
    pub key: RepositoryKeyV1,
    pub full_name: String,
    pub normalized_full_name: String,
    pub owner: String,
    pub normalized_owner: String,
    pub visibility: RepositoryVisibilityV1,
    /// Normalized former owner/name values observed for this stable ID.
    pub aliases: BTreeSet<String>,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RepositoryRevisionV1 {
    pub commit_sha: String,
    pub tree_sha: String,
    pub analyzer_profile_digest: String,
}

impl RepositoryRevisionV1 {
    pub fn validate(&self) -> Result<(), CatalogError> {
        for (field, value) in [
            ("commit_sha", &self.commit_sha),
            ("tree_sha", &self.tree_sha),
            ("analyzer_profile_digest", &self.analyzer_profile_digest),
        ] {
            if value.trim().is_empty() || value.trim() != value {
                return Err(CatalogError::InvalidInput(format!(
                    "{field} must be non-empty and normalized"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RepositorySnapshotKeyV1 {
    pub repository: RepositoryKeyV1,
    pub revision: RepositoryRevisionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositorySnapshotV1 {
    pub key: RepositorySnapshotKeyV1,
    pub head_committed_at: Option<DateTime<Utc>>,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryObservationEnvelopeV1 {
    pub schema_version: u16,
    pub namespace: InventoryNamespaceV1,
    pub job_id: JobId,
    pub task_id: TaskId,
    pub task_attempt: u32,
    pub artifact: ArtifactRefV1,
    pub repository_id: String,
    pub revision: RepositoryRevisionV1,
    /// Must be the normalized exact selector corresponding to `evidence.target`.
    pub target_selector: String,
    pub completed_at: DateTime<Utc>,
    pub evidence: EvidenceBundleV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryAttemptInputV1 {
    pub schema_version: u16,
    pub namespace: InventoryNamespaceV1,
    pub job_id: JobId,
    pub task_id: TaskId,
    pub task_attempt: u32,
    pub repository_id: String,
    pub repository_full_name: String,
    pub visibility: RepositoryVisibilityV1,
    pub revision: Option<RepositoryRevisionV1>,
    pub completed_at: DateTime<Utc>,
    pub failure_code: String,
    pub failure_message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum InventoryProjectionInputV1 {
    Observation(InventoryObservationEnvelopeV1),
    FailedAttempt(RepositoryAttemptInputV1),
}

impl InventoryProjectionInputV1 {
    pub fn completed_at(&self) -> DateTime<Utc> {
        match self {
            Self::Observation(envelope) => envelope.completed_at,
            Self::FailedAttempt(attempt) => attempt.completed_at,
        }
    }

    pub fn stable_order_key(&self) -> (&str, &str, u32) {
        match self {
            Self::Observation(envelope) => (
                &envelope.job_id.0,
                &envelope.task_id.0,
                envelope.task_attempt,
            ),
            Self::FailedAttempt(attempt) => {
                (&attempt.job_id.0, &attempt.task_id.0, attempt.task_attempt)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryAttemptStatusV1 {
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryAttemptV1 {
    pub attempt_id: String,
    /// Stable digest of the projection input used for idempotency checks.
    pub projection_digest: String,
    pub projection_sequence: u64,
    pub repository: RepositoryKeyV1,
    pub repository_full_name: String,
    pub normalized_repository_name: String,
    pub repository_owner: String,
    pub normalized_repository_owner: String,
    pub repository_visibility: RepositoryVisibilityV1,
    pub repository_aliases: BTreeSet<String>,
    pub snapshot: Option<RepositorySnapshotKeyV1>,
    pub job_id: JobId,
    pub task_id: TaskId,
    pub task_attempt: u32,
    pub completed_at: DateTime<Utc>,
    pub status: InventoryAttemptStatusV1,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub observation_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryLatestV1 {
    pub latest_attempt_id: Option<String>,
    pub latest_evidence_id: Option<String>,
    pub latest_complete_evidence_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetObservationV1 {
    pub observation_id: String,
    pub attempt_id: String,
    pub snapshot: RepositorySnapshotKeyV1,
    pub target: PackageIdentityV1,
    pub requirements: Vec<DirectRequirementEvidenceV1>,
    pub exact_resolution_count: usize,
    pub recorded_relation: RecordedRelation,
    pub direct_witness: Option<DependencyWitnessV1>,
    pub transitive_witness: Option<DependencyWitnessV1>,
    pub msrv: Option<Version>,
    pub strength: EvidenceStrengthV1,
    pub completeness: EvidenceCompletenessV1,
    pub limitations: Vec<LimitationV1>,
    pub globally_exhaustive: bool,
    pub package_inventory_complete: bool,
    pub observed_at: DateTime<Utc>,
    pub job_id: JobId,
    pub task_id: TaskId,
    pub task_attempt: u32,
    pub artifact: ArtifactRefV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackagePresenceV1 {
    pub observation_id: String,
    pub snapshot: RepositorySnapshotKeyV1,
    pub package: PackageIdentityV1,
    pub license_expression: Option<String>,
    pub inventory_complete: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryHistoryModeV1 {
    #[default]
    LatestAttempt,
    LatestEvidence,
    LastComplete,
    Observations,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryFreshnessV1 {
    #[default]
    Current,
    RefreshPartial,
    RefreshFailed,
    Historical,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySearchFieldV1 {
    #[default]
    Any,
    Repository,
    Package,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryMatchModeV1 {
    Exact,
    Prefix,
    Substring,
    #[default]
    Fuzzy,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum InventorySourceFilterV1 {
    #[default]
    Any,
    Local,
    Exact(String),
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySortV1 {
    #[default]
    Relevance,
    RepositoryAsc,
    ObservedAtDesc,
    MsrvAsc,
}

/// Typed filters for the inventory read model. Empty sets mean no restriction.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryQueryV1 {
    pub schema_version: u16,
    pub namespace: Option<InventoryNamespaceV1>,
    pub history: InventoryHistoryModeV1,
    /// Evaluate latest/history selection at this instant rather than now.
    pub as_of: Option<DateTime<Utc>>,
    pub search: Option<String>,
    pub search_field: InventorySearchFieldV1,
    pub match_mode: InventoryMatchModeV1,
    pub repository_ids: BTreeSet<String>,
    pub repository_owner: Option<String>,
    pub repository_visibilities: BTreeSet<RepositoryVisibilityV1>,
    pub target_name: Option<String>,
    pub target_version: Option<Version>,
    pub target_source: InventorySourceFilterV1,
    pub package_name: Option<String>,
    pub package_version: Option<Version>,
    pub package_source: InventorySourceFilterV1,
    pub requirement: Option<String>,
    pub requirement_sources: BTreeSet<RequirementEvidenceSourceV1>,
    pub requirement_accepts_target: Option<bool>,
    pub explicit_exact_pin: Option<bool>,
    pub recorded_relations: Vec<RecordedRelation>,
    pub min_msrv: Option<Version>,
    pub max_msrv: Option<Version>,
    pub strengths: BTreeSet<EvidenceStrengthV1>,
    pub completeness: BTreeSet<EvidenceCompletenessV1>,
    pub limitation_codes: BTreeSet<String>,
    pub commit_sha: Option<String>,
    pub tree_sha: Option<String>,
    pub analyzer_profile_digest: Option<String>,
    pub observed_after: Option<DateTime<Utc>>,
    pub observed_before: Option<DateTime<Utc>>,
    pub job_ids: BTreeSet<JobId>,
    pub freshness: BTreeSet<InventoryFreshnessV1>,
    pub sort: InventorySortV1,
}

impl InventoryQueryV1 {
    pub fn new() -> Self {
        Self {
            schema_version: CATALOG_SCHEMA_VERSION_V1,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != CATALOG_SCHEMA_VERSION_V1 {
            return Err(CatalogError::UnsupportedSchemaVersion(self.schema_version));
        }
        if let Some(namespace) = &self.namespace {
            namespace.validate()?;
        }
        if self
            .search
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(CatalogError::InvalidInput(
                "search must be absent or non-empty".to_owned(),
            ));
        }
        if self
            .search
            .as_ref()
            .is_some_and(|value| value.chars().count() > MAX_SEARCH_CHARS)
        {
            return Err(CatalogError::InvalidInput(format!(
                "search must not exceed {MAX_SEARCH_CHARS} characters"
            )));
        }
        if self
            .min_msrv
            .as_ref()
            .zip(self.max_msrv.as_ref())
            .is_some_and(|(min, max)| min > max)
        {
            return Err(CatalogError::InvalidInput(
                "min_msrv must not exceed max_msrv".to_owned(),
            ));
        }
        for (field, value) in [
            ("repository_owner", self.repository_owner.as_deref()),
            ("target_name", self.target_name.as_deref()),
            ("package_name", self.package_name.as_deref()),
            ("requirement", self.requirement.as_deref()),
            ("commit_sha", self.commit_sha.as_deref()),
            ("tree_sha", self.tree_sha.as_deref()),
            (
                "analyzer_profile_digest",
                self.analyzer_profile_digest.as_deref(),
            ),
        ] {
            if value.is_some_and(|value| {
                value.trim().is_empty() || value.trim() != value || value.chars().count() > 512
            }) {
                return Err(CatalogError::InvalidInput(format!(
                    "{field} must be absent or contain 1-512 normalized characters"
                )));
            }
        }
        for (field, source) in [
            ("target_source", &self.target_source),
            ("package_source", &self.package_source),
        ] {
            if let InventorySourceFilterV1::Exact(value) = source
                && (value.trim().is_empty()
                    || value.trim() != value
                    || value.chars().count() > 2_048)
            {
                return Err(CatalogError::InvalidInput(format!(
                    "{field} must contain 1-2048 normalized characters"
                )));
            }
        }
        if self
            .repository_ids
            .iter()
            .any(|value| value.trim().is_empty() || value.trim() != value || value.len() > 128)
            || self
                .limitation_codes
                .iter()
                .any(|value| value.trim().is_empty() || value.trim() != value || value.len() > 128)
        {
            return Err(CatalogError::InvalidInput(
                "repository IDs and limitation codes must be normalized and at most 128 bytes"
                    .to_owned(),
            ));
        }
        if self
            .observed_after
            .zip(self.observed_before)
            .is_some_and(|(after, before)| after > before)
        {
            return Err(CatalogError::InvalidInput(
                "observed_after must not exceed observed_before".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryPageRequestV1 {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl InventoryPageRequestV1 {
    pub fn limit(&self) -> Result<usize, CatalogError> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(CatalogError::InvalidInput(format!(
                "page limit must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }
        Ok(limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventorySearchResultV1 {
    pub repository: InventoryRepositoryV1,
    pub attempt: RepositoryAttemptV1,
    pub snapshot: Option<RepositorySnapshotV1>,
    pub observation: Option<TargetObservationV1>,
    pub packages: Vec<PackagePresenceV1>,
    pub package_matches_total: usize,
    pub package_matches_truncated: bool,
    pub freshness: InventoryFreshnessV1,
    /// Deterministic integer score; larger values rank first.
    pub relevance: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryPageV1 {
    pub schema_version: u16,
    pub trigram_index_version: u16,
    pub index_watermark: u64,
    pub items: Vec<InventorySearchResultV1>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryProjectionOutcomeV1 {
    pub attempt_id: String,
    pub observation_id: Option<String>,
    pub projection_sequence: u64,
    pub index_watermark: u64,
    pub already_projected: bool,
}

/// Durable ordering record used to restore projection and cursor semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryProjectionRecordV1 {
    pub sequence: u64,
    pub input: InventoryProjectionInputV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SavedInventoryQueryDraftV1 {
    pub schema_version: u16,
    pub query_id: String,
    pub expected_previous_revision: Option<u64>,
    pub name: String,
    pub namespace: InventoryNamespaceV1,
    pub query: InventoryQueryV1,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SavedInventoryQueryRevisionV1 {
    pub schema_version: u16,
    pub query_id: String,
    pub revision: u64,
    pub name: String,
    pub namespace: InventoryNamespaceV1,
    pub query: InventoryQueryV1,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    UnsupportedSchemaVersion(u16),
    InvalidInput(String),
    InvalidEvidence(String),
    Unauthorized,
    CursorInvalid,
    CursorStale,
    StoreUnavailable,
    RevisionConflict {
        expected: Option<u64>,
        actual: Option<u64>,
    },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported catalog schema version {version}")
            }
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::InvalidEvidence(message) => formatter.write_str(message),
            Self::Unauthorized => formatter.write_str("inventory resource not found"),
            Self::CursorInvalid => formatter.write_str("inventory cursor is invalid"),
            Self::CursorStale => formatter.write_str("inventory cursor is stale"),
            Self::StoreUnavailable => formatter.write_str("inventory store is unavailable"),
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "saved query revision conflict: expected {expected:?}, actual {actual:?}"
            ),
        }
    }
}

impl std::error::Error for CatalogError {}
