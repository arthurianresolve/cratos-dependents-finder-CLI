use std::collections::BTreeMap;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::domain::{SCHEMA_VERSION_V1, Sha256Digest};

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "visibility")]
pub enum CacheNamespaceV1 {
    Public,
    Private { principal_id: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheContentKindV1 {
    RawRepositoryContent,
    DerivedEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum CacheProtectionV1 {
    Plaintext,
    EnvelopeEncrypted {
        algorithm: String,
        wrapping_key_id: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompletenessV1 {
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ReuseFingerprintV1 {
    pub repository_id: String,
    pub tree_sha: String,
    pub analyzer_version: String,
    pub bounds_hash: Sha256Digest,
    pub target_hash: Sha256Digest,
    pub evidence_profile_hash: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CacheKeyV1 {
    pub namespace: CacheNamespaceV1,
    pub digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheMetadataV1 {
    pub schema_version: u16,
    pub key: CacheKeyV1,
    pub content_kind: CacheContentKindV1,
    pub content_length: u64,
    pub github_blob_sha: Option<String>,
    pub protection: CacheProtectionV1,
    pub completeness: EvidenceCompletenessV1,
    pub reuse_fingerprint: Option<ReuseFingerprintV1>,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
    pub retain_until: DateTime<Utc>,
    pub reference_count: u64,
}

impl CacheMetadataV1 {
    pub fn can_reuse(&self, fingerprint: &ReuseFingerprintV1) -> bool {
        self.content_kind == CacheContentKindV1::DerivedEvidence
            && self.completeness == EvidenceCompletenessV1::Complete
            && self.reuse_fingerprint.as_ref() == Some(fingerprint)
    }

    pub fn can_reuse_at(&self, fingerprint: &ReuseFingerprintV1, now: DateTime<Utc>) -> bool {
        self.can_reuse(fingerprint) && self.retain_until > now
    }

    pub fn is_retention_candidate(&self, now: DateTime<Utc>) -> bool {
        self.reference_count == 0 && self.retain_until <= now
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetentionPolicyV1 {
    pub raw_content_days: u32,
    pub derived_evidence_days: u32,
}

impl Default for RetentionPolicyV1 {
    fn default() -> Self {
        Self {
            raw_content_days: 30,
            derived_evidence_days: 365,
        }
    }
}

impl RetentionPolicyV1 {
    pub fn deadline(
        self,
        content_kind: CacheContentKindV1,
        created_at: DateTime<Utc>,
    ) -> DateTime<Utc> {
        let days = match content_kind {
            CacheContentKindV1::RawRepositoryContent => self.raw_content_days,
            CacheContentKindV1::DerivedEvidence => self.derived_evidence_days,
        };
        created_at
            .checked_add_signed(TimeDelta::days(i64::from(days)))
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheInsertOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Clone, Debug, Default)]
pub struct CacheCatalog {
    entries: BTreeMap<CacheKeyV1, CacheMetadataV1>,
}

impl CacheCatalog {
    pub fn insert(&mut self, metadata: CacheMetadataV1) -> Result<CacheInsertOutcome, CacheError> {
        validate_metadata(&metadata)?;
        match self.entries.get(&metadata.key) {
            Some(existing) if immutable_metadata_matches(existing, &metadata) => {
                Ok(CacheInsertOutcome::AlreadyPresent)
            }
            Some(_) => Err(CacheError::DigestMetadataConflict),
            None => {
                self.entries.insert(metadata.key.clone(), metadata);
                Ok(CacheInsertOutcome::Inserted)
            }
        }
    }

    pub fn get(&self, key: &CacheKeyV1) -> Option<&CacheMetadataV1> {
        self.entries.get(key)
    }

    pub fn touch(
        &mut self,
        key: &CacheKeyV1,
        accessed_at: DateTime<Utc>,
    ) -> Result<(), CacheError> {
        let entry = self.entries.get_mut(key).ok_or(CacheError::NotFound)?;
        if accessed_at > entry.last_accessed_at {
            entry.last_accessed_at = accessed_at;
        }
        Ok(())
    }

    pub fn retain(&mut self, key: &CacheKeyV1) -> Result<(), CacheError> {
        let entry = self.entries.get_mut(key).ok_or(CacheError::NotFound)?;
        entry.reference_count = entry
            .reference_count
            .checked_add(1)
            .ok_or(CacheError::ReferenceCountOverflow)?;
        Ok(())
    }

    pub fn release(&mut self, key: &CacheKeyV1) -> Result<(), CacheError> {
        let entry = self.entries.get_mut(key).ok_or(CacheError::NotFound)?;
        entry.reference_count = entry
            .reference_count
            .checked_sub(1)
            .ok_or(CacheError::ReferenceCountUnderflow)?;
        Ok(())
    }

    pub fn retention_candidates(&self, now: DateTime<Utc>) -> Vec<CacheKeyV1> {
        self.entries
            .values()
            .filter(|entry| entry.is_retention_candidate(now))
            .map(|entry| entry.key.clone())
            .collect()
    }

    pub fn remove_retention_candidate(
        &mut self,
        key: &CacheKeyV1,
        now: DateTime<Utc>,
    ) -> Result<CacheMetadataV1, CacheError> {
        let entry = self.entries.get(key).ok_or(CacheError::NotFound)?;
        if !entry.is_retention_candidate(now) {
            return Err(CacheError::StillRetained);
        }
        Ok(self.entries.remove(key).expect("entry was just checked"))
    }
}

fn validate_metadata(metadata: &CacheMetadataV1) -> Result<(), CacheError> {
    if metadata.schema_version != SCHEMA_VERSION_V1 {
        return Err(CacheError::UnsupportedSchemaVersion(
            metadata.schema_version,
        ));
    }
    if metadata.retain_until < metadata.created_at
        || metadata.last_accessed_at < metadata.created_at
    {
        return Err(CacheError::InvalidTimestamps);
    }
    if matches!(&metadata.key.namespace, CacheNamespaceV1::Private { .. })
        && matches!(&metadata.protection, CacheProtectionV1::Plaintext)
    {
        return Err(CacheError::PrivateContentMustBeEncrypted);
    }
    if matches!(
        &metadata.key.namespace,
        CacheNamespaceV1::Private { principal_id } if principal_id.trim().is_empty()
    ) {
        return Err(CacheError::InvalidPrivatePrincipal);
    }
    Ok(())
}

fn immutable_metadata_matches(left: &CacheMetadataV1, right: &CacheMetadataV1) -> bool {
    left.schema_version == right.schema_version
        && left.key == right.key
        && left.content_kind == right.content_kind
        && left.content_length == right.content_length
        && left.github_blob_sha == right.github_blob_sha
        && left.protection == right.protection
        && left.completeness == right.completeness
        && left.reuse_fingerprint == right.reuse_fingerprint
        && left.created_at == right.created_at
        && left.retain_until == right.retain_until
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheError {
    NotFound,
    UnsupportedSchemaVersion(u16),
    InvalidTimestamps,
    PrivateContentMustBeEncrypted,
    InvalidPrivatePrincipal,
    DigestMetadataConflict,
    StillRetained,
    ReferenceCountOverflow,
    ReferenceCountUnderflow,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CacheError {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn time(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, day, 0, 0, 0).unwrap()
    }

    fn digest(value: char) -> Sha256Digest {
        Sha256Digest::parse(value.to_string().repeat(64)).unwrap()
    }

    fn private_metadata(principal_id: &str) -> CacheMetadataV1 {
        CacheMetadataV1 {
            schema_version: SCHEMA_VERSION_V1,
            key: CacheKeyV1 {
                namespace: CacheNamespaceV1::Private {
                    principal_id: principal_id.to_owned(),
                },
                digest: digest('a'),
            },
            content_kind: CacheContentKindV1::RawRepositoryContent,
            content_length: 12,
            github_blob_sha: Some("blob".to_owned()),
            protection: CacheProtectionV1::EnvelopeEncrypted {
                algorithm: "AES-256-GCM".to_owned(),
                wrapping_key_id: "installation-key".to_owned(),
            },
            completeness: EvidenceCompletenessV1::Complete,
            reuse_fingerprint: None,
            created_at: time(1),
            last_accessed_at: time(1),
            retain_until: time(2),
            reference_count: 0,
        }
    }

    #[test]
    fn private_content_is_namespaced_by_principal() {
        let mut catalog = CacheCatalog::default();
        catalog.insert(private_metadata("principal-a")).unwrap();
        catalog.insert(private_metadata("principal-b")).unwrap();
        assert_eq!(catalog.entries.len(), 2);
    }

    #[test]
    fn private_plaintext_metadata_is_rejected() {
        let mut metadata = private_metadata("principal-a");
        metadata.protection = CacheProtectionV1::Plaintext;
        assert_eq!(
            CacheCatalog::default().insert(metadata),
            Err(CacheError::PrivateContentMustBeEncrypted)
        );
    }

    #[test]
    fn referenced_entries_survive_retention_collection() {
        let mut catalog = CacheCatalog::default();
        let metadata = private_metadata("principal-a");
        let key = metadata.key.clone();
        catalog.insert(metadata).unwrap();
        catalog.retain(&key).unwrap();
        assert!(catalog.retention_candidates(time(3)).is_empty());
        catalog.release(&key).unwrap();
        assert_eq!(catalog.retention_candidates(time(3)), vec![key]);
    }

    #[test]
    fn partial_evidence_is_never_reused() {
        let fingerprint = ReuseFingerprintV1 {
            repository_id: "1".to_owned(),
            tree_sha: "tree".to_owned(),
            analyzer_version: "1".to_owned(),
            bounds_hash: digest('b'),
            target_hash: digest('c'),
            evidence_profile_hash: digest('d'),
        };
        let mut metadata = private_metadata("principal-a");
        metadata.content_kind = CacheContentKindV1::DerivedEvidence;
        metadata.reuse_fingerprint = Some(fingerprint.clone());
        metadata.completeness = EvidenceCompletenessV1::Partial;
        assert!(!metadata.can_reuse(&fingerprint));
    }

    #[test]
    fn expired_complete_evidence_is_not_reused() {
        let fingerprint = ReuseFingerprintV1 {
            repository_id: "1".to_owned(),
            tree_sha: "tree".to_owned(),
            analyzer_version: "1".to_owned(),
            bounds_hash: digest('b'),
            target_hash: digest('c'),
            evidence_profile_hash: digest('d'),
        };
        let mut metadata = private_metadata("principal-a");
        metadata.content_kind = CacheContentKindV1::DerivedEvidence;
        metadata.reuse_fingerprint = Some(fingerprint.clone());
        assert!(metadata.can_reuse_at(&fingerprint, time(1)));
        assert!(!metadata.can_reuse_at(&fingerprint, time(2)));
    }
}
