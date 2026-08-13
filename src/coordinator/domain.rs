use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

pub const SCHEMA_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct JobId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ReservationId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PermitId(pub String);

/// A lowercase hexadecimal SHA-256 digest supplied by a hashing adapter.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, DomainError> {
        let value = value.as_ref();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidSha256);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<DeserializerT>(deserializer: DeserializerT) -> Result<Self, DeserializerT::Error>
    where
        DeserializerT: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(DeserializerT::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryScopeV1 {
    PublicOnly,
    AllVisible,
}

/// Private credential profiles an enrolled worker is trusted to use.
///
/// Public jobs are available to every enrolled worker. An empty set therefore
/// represents the safe, backwards-compatible public-only enrollment.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentAuthorizationV1 {
    #[serde(default)]
    pub private_credential_profiles: BTreeSet<String>,
}

impl AgentAuthorizationV1 {
    pub fn allows(&self, spec: &ScanSpecV1) -> bool {
        match spec.repository_scope {
            RepositoryScopeV1::PublicOnly => true,
            RepositoryScopeV1::AllVisible => spec
                .credential_profile_id
                .as_ref()
                .is_some_and(|profile| self.private_credential_profiles.contains(profile)),
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self
            .private_credential_profiles
            .iter()
            .any(|profile| profile.trim().is_empty() || profile.trim() != profile)
        {
            return Err(DomainError::InvalidCredentialProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanTargetV1 {
    pub crate_name: String,
    /// A normalized exact version or Cargo version requirement.
    pub version_spec: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanBoundsV1 {
    pub repository_limit: u64,
    pub provider_request_limit: u64,
    pub download_byte_limit: u64,
    pub artifact_byte_limit: u64,
}

impl Default for ScanBoundsV1 {
    fn default() -> Self {
        Self {
            repository_limit: 10_000,
            provider_request_limit: 250_000,
            download_byte_limit: 50 * 1024 * 1024 * 1024,
            artifact_byte_limit: 25 * 1024 * 1024 * 1024,
        }
    }
}

/// Immutable, normalized inputs used to submit or resume a scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanSpecV1 {
    pub schema_version: u16,
    pub target: ScanTargetV1,
    pub repository_scope: RepositoryScopeV1,
    pub credential_profile_id: Option<String>,
    pub bounds: ScanBoundsV1,
    pub analyzer_versions: BTreeMap<String, String>,
}

impl ScanSpecV1 {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(DomainError::UnsupportedSchemaVersion(self.schema_version));
        }
        if self.target.crate_name.trim().is_empty()
            || self
                .target
                .version_spec
                .strip_prefix('=')
                .is_none_or(|version| semver::Version::parse(version).is_err())
        {
            return Err(DomainError::InvalidScanTarget);
        }
        if self.repository_scope == RepositoryScopeV1::AllVisible
            && self
                .credential_profile_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(DomainError::PrivateScopeRequiresCredential);
        }
        if self.bounds.repository_limit == 0
            || self.bounds.provider_request_limit == 0
            || self.bounds.download_byte_limit == 0
            || self.bounds.artifact_byte_limit == 0
        {
            return Err(DomainError::InvalidScanBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobStateV1 {
    Queued,
    Running,
    Paused,
    Completed,
    CompletedPartial,
    Failed,
    Cancelled,
}

impl ScanJobStateV1 {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CompletedPartial | Self::Failed | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobProgressV1 {
    pub tasks_total: u64,
    pub tasks_pending: u64,
    pub tasks_leased: u64,
    pub tasks_succeeded: u64,
    pub tasks_failed: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotaUsageV1 {
    pub repositories: u64,
    pub provider_requests: u64,
    pub downloaded_bytes: u64,
    pub artifact_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanJobV1 {
    pub schema_version: u16,
    pub id: JobId,
    pub idempotency_key: String,
    pub spec: ScanSpecV1,
    pub state: ScanJobStateV1,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub progress: JobProgressV1,
    pub quota_usage: QuotaUsageV1,
    pub partial_reasons: BTreeSet<String>,
    pub failure: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseV1 {
    pub lease_id: String,
    pub agent_id: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryTaskStateV1 {
    Pending,
    Leased,
    Succeeded,
    Failed,
    Cancelled,
}

impl RepositoryTaskStateV1 {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRefV1 {
    pub digest: Sha256Digest,
    pub media_type: String,
    pub stored_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskUsageV1 {
    pub provider_requests: u64,
    pub downloaded_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryTaskV1 {
    pub schema_version: u16,
    pub id: TaskId,
    pub job_id: JobId,
    pub repository_id: String,
    pub state: RepositoryTaskStateV1,
    pub attempt: u32,
    pub not_before: DateTime<Utc>,
    pub lease: Option<LeaseV1>,
    pub result: Option<ArtifactRefV1>,
    pub failure: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobEventKindV1 {
    Submitted,
    Started,
    Paused,
    Resumed,
    Cancelled,
    Completed,
    CompletedPartial,
    Failed,
    TaskQueued,
    TaskLeased,
    TaskHeartbeat,
    TaskReclaimed,
    TaskSucceeded,
    TaskFailed,
    QuotaReserved,
    QuotaReconciled,
    QuotaReleased,
    ProviderPermitGranted,
    ProviderRequestFinished,
}

/// Append-only lifecycle evidence. `sequence` is monotonically increasing per store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobEventV1 {
    pub schema_version: u16,
    pub sequence: u64,
    pub job_id: JobId,
    pub task_id: Option<TaskId>,
    pub occurred_at: DateTime<Utc>,
    pub kind: JobEventKindV1,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    InvalidSha256,
    UnsupportedSchemaVersion(u16),
    InvalidScanTarget,
    InvalidScanBounds,
    PrivateScopeRequiresCredential,
    InvalidCredentialProfile,
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSha256 => formatter.write_str("invalid SHA-256 digest"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported schema version {version}")
            }
            Self::InvalidScanTarget => formatter.write_str("scan target is empty"),
            Self::InvalidScanBounds => formatter.write_str("scan bounds must be non-zero"),
            Self::PrivateScopeRequiresCredential => {
                formatter.write_str("all-visible repository scope requires a credential profile")
            }
            Self::InvalidCredentialProfile => {
                formatter.write_str("credential profiles must be non-empty and normalized")
            }
        }
    }
}

impl std::error::Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_validated_and_normalized() {
        let digest = Sha256Digest::parse("AA".repeat(32)).unwrap();
        assert_eq!(digest.as_str(), "aa".repeat(32));
        assert_eq!(Sha256Digest::parse("nope"), Err(DomainError::InvalidSha256));
    }

    #[test]
    fn private_scope_requires_a_credential_profile() {
        let spec = ScanSpecV1 {
            schema_version: SCHEMA_VERSION_V1,
            target: ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: RepositoryScopeV1::AllVisible,
            credential_profile_id: None,
            bounds: ScanBoundsV1::default(),
            analyzer_versions: BTreeMap::new(),
        };

        assert_eq!(
            spec.validate(),
            Err(DomainError::PrivateScopeRequiresCredential)
        );
    }

    #[test]
    fn worker_authorization_defaults_to_public_only() {
        let public = ScanSpecV1 {
            schema_version: SCHEMA_VERSION_V1,
            target: ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: RepositoryScopeV1::PublicOnly,
            credential_profile_id: None,
            bounds: ScanBoundsV1::default(),
            analyzer_versions: BTreeMap::new(),
        };
        let private = ScanSpecV1 {
            repository_scope: RepositoryScopeV1::AllVisible,
            credential_profile_id: Some("production".to_owned()),
            ..public.clone()
        };

        let public_only = AgentAuthorizationV1::default();
        assert!(public_only.allows(&public));
        assert!(!public_only.allows(&private));

        let authorized = AgentAuthorizationV1 {
            private_credential_profiles: BTreeSet::from(["production".to_owned()]),
        };
        assert!(authorized.allows(&private));
    }
}
