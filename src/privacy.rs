//! Repository suppression and online evidence-removal policy.
//!
//! Suppression is authoritative; catalog visibility and physical deletion are
//! recoverable projections. Operational history is deliberately retained.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

use crate::{
    catalog::{InventoryNamespaceV1, InventoryProjectionStore},
    coordinator::{CacheNamespaceV1, TursoCoordinatorStore},
    secure_cache::EnvelopeKey,
};

pub const REMOVAL_BATCH_SIZE: usize = 256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyOperationError {
    Conflict,
    InvalidPlan,
}

impl std::fmt::Display for PrivacyOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "privacy request conflicts with retained policy",
            Self::InvalidPlan => "invalid privacy removal plan",
        })
    }
}

impl std::error::Error for PrivacyOperationError {}
pub const LEDGER_KEY_ID: &str = "cratos-suppression-v1";
const LEDGER_AAD: &[u8] = b"cratos/suppression-ledger/v1";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;

pub fn namespace_for_spec(spec: &crate::coordinator::ScanSpecV1) -> InventoryNamespaceV1 {
    match spec.repository_scope {
        crate::coordinator::RepositoryScopeV1::PublicOnly => InventoryNamespaceV1::Public,
        crate::coordinator::RepositoryScopeV1::AllVisible => InventoryNamespaceV1::Private {
            credential_profile_id: spec.credential_profile_id.clone().unwrap_or_default(),
        },
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemovalScopeV1 {
    All,
    Public,
    CredentialProfile { credential_profile_id: String },
}

impl RemovalScopeV1 {
    pub fn allows(&self, namespace: &InventoryNamespaceV1) -> bool {
        match (self, namespace) {
            (Self::All, _) | (Self::Public, InventoryNamespaceV1::Public) => true,
            (
                Self::CredentialProfile {
                    credential_profile_id: selected,
                },
                InventoryNamespaceV1::Private {
                    credential_profile_id,
                },
            ) => selected == credential_profile_id,
            _ => false,
        }
    }

    pub fn allows_cache(&self, namespace: &CacheNamespaceV1) -> bool {
        match namespace {
            CacheNamespaceV1::Public => self.allows(&InventoryNamespaceV1::Public),
            CacheNamespaceV1::Private { principal_id } => {
                self.allows(&InventoryNamespaceV1::Private {
                    credential_profile_id: principal_id.clone(),
                })
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionTargetV1 {
    pub repository_id: String,
    pub scope: RemovalScopeV1,
    pub aliases: BTreeSet<String>,
}

impl SuppressionTargetV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.repository_id.is_empty()
                && self.repository_id.len() <= 32
                && self.repository_id.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid repository identity"
        );
        ensure!(self.aliases.len() <= 256, "too many repository aliases");
        for alias in &self.aliases {
            ensure!(valid_alias(alias), "invalid repository alias");
        }
        if let RemovalScopeV1::CredentialProfile {
            credential_profile_id,
        } = &self.scope
        {
            crate::control_auth::CredentialProfileIdV1::parse(credential_profile_id.clone())
                .map_err(|_| anyhow::anyhow!("invalid credential profile"))?;
        }
        Ok(())
    }

    pub fn matches(
        &self,
        namespace: &InventoryNamespaceV1,
        repository_id: &str,
        alias: &str,
    ) -> bool {
        self.scope.allows(namespace)
            && if !repository_id.is_empty()
                && repository_id.bytes().all(|byte| byte.is_ascii_digit())
            {
                self.repository_id == repository_id
            } else {
                self.aliases.contains(&alias.to_lowercase())
            }
    }
}

fn valid_alias(alias: &str) -> bool {
    alias.len() <= 256
        && alias == alias.to_lowercase()
        && alias.split('/').count() == 2
        && alias.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalPlanV1 {
    pub schema_version: u16,
    pub deployment_id: String,
    pub target: SuppressionTargetV1,
    pub estimated_attempts: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalPhaseV1 {
    Pending,
    Catalog,
    Artifacts,
    Verifying,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalRequestV1 {
    pub schema_version: u16,
    pub request_id: String,
    pub deployment_id: String,
    pub revision: u64,
    pub target: SuppressionTargetV1,
    pub created_at: DateTime<Utc>,
    pub phase: RemovalPhaseV1,
    pub attempts_removed: u64,
    pub artifacts_removed: u64,
    pub failure_code: Option<String>,
    #[serde(default)]
    pub task_cursor: Option<String>,
    #[serde(default)]
    pub artifact_cursor: Option<String>,
    #[serde(default)]
    pub failed_attempt_cursor: Option<crate::coordinator::FailedAttemptProjectionKeyV1>,
    #[serde(default)]
    pub pending_artifact: Option<crate::coordinator::TaskId>,
}

impl RemovalRequestV1 {
    pub(crate) fn reset_for_recovery(&mut self) {
        self.phase = RemovalPhaseV1::Pending;
        self.attempts_removed = 0;
        self.artifacts_removed = 0;
        self.failure_code = None;
        self.task_cursor = None;
        self.artifact_cursor = None;
        self.failed_attempt_cursor = None;
        self.pending_artifact = None;
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.revision > 0,
            "unsupported removal record"
        );
        Uuid::parse_str(&self.request_id).context("invalid removal request identity")?;
        Uuid::parse_str(&self.deployment_id).context("invalid deployment identity")?;
        self.target.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionLedgerV1 {
    pub schema_version: u16,
    pub deployment_id: String,
    pub revision: u64,
    pub records: Vec<RemovalRequestV1>,
}

impl SuppressionLedgerV1 {
    /// Policy identity excludes mutable purge progress, which is not evidence
    /// that an independently restored database has already been purged.
    pub fn policy_digest(&self) -> Result<String> {
        self.validate()?;
        let mut records = self
            .records
            .iter()
            .map(|record| (&record.request_id, record.revision, &record.target))
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.1);
        Ok(crate::secure_cache::sha256_hex(&serde_json::to_vec(&(
            "cratos/suppression-policy/v1",
            &self.deployment_id,
            self.revision,
            records,
        ))?))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported suppression ledger");
        Uuid::parse_str(&self.deployment_id).context("invalid ledger deployment")?;
        let mut ids = BTreeSet::new();
        let mut revisions = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            ensure!(
                record.deployment_id == self.deployment_id
                    && record.revision <= self.revision
                    && ids.insert(&record.request_id)
                    && revisions.insert(record.revision),
                "inconsistent suppression ledger"
            );
        }
        ensure!(
            self.records.len() as u64 == self.revision,
            "suppression ledger has missing policy revisions"
        );
        Ok(())
    }

    pub fn load(path: &Path, key: &EnvelopeKey) -> Result<Self> {
        use std::io::Read as _;
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_LEDGER_BYTES,
            "suppression ledger exceeds limit"
        );
        let mut ciphertext = Vec::new();
        file.take(MAX_LEDGER_BYTES + 1)
            .read_to_end(&mut ciphertext)?;
        ensure!(
            ciphertext.len() as u64 <= MAX_LEDGER_BYTES,
            "suppression ledger exceeds limit"
        );
        let plaintext = key.open(LEDGER_AAD, &ciphertext)?;
        let ledger: Self = serde_json::from_slice(&plaintext)?;
        ledger.validate()?;
        Ok(ledger)
    }

    pub fn persist(&self, path: &Path, key: &EnvelopeKey) -> Result<()> {
        use std::io::Write as _;
        self.validate()?;
        let ciphertext = key.seal(LEDGER_AAD, &serde_json::to_vec(self)?)?;
        ensure!(
            ciphertext.len() as u64 <= MAX_LEDGER_BYTES,
            "suppression ledger exceeds limit"
        );
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&ciphertext)?;
        temporary.as_file_mut().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    async fn persist_async(&self, path: &Path, key: &Arc<EnvelopeKey>) -> Result<()> {
        let ledger = self.clone();
        let path = path.to_owned();
        let key = key.clone();
        tokio::task::spawn_blocking(move || ledger.persist(&path, &key)).await?
    }

    pub fn suppresses(
        &self,
        namespace: &InventoryNamespaceV1,
        repository_id: &str,
        alias: &str,
    ) -> bool {
        self.records
            .iter()
            .any(|record| record.target.matches(namespace, repository_id, alias))
    }
}

#[derive(Clone, Debug)]
pub struct PrivacyState {
    pub ledger: SuppressionLedgerV1,
    pub ready: bool,
}

pub struct PrivacyService {
    pub gate: RwLock<PrivacyState>,
    pub notify: Notify,
    store: TursoCoordinatorStore,
    inventory: Arc<dyn InventoryProjectionStore>,
    publication: Option<(PathBuf, Arc<EnvelopeKey>)>,
}

impl PrivacyService {
    pub async fn open(
        store: TursoCoordinatorStore,
        inventory: Arc<dyn InventoryProjectionStore>,
    ) -> Result<Arc<Self>> {
        Self::open_internal(store, inventory, None).await
    }

    pub async fn open_with_ledger(
        store: TursoCoordinatorStore,
        inventory: Arc<dyn InventoryProjectionStore>,
        path: PathBuf,
        key: EnvelopeKey,
    ) -> Result<Arc<Self>> {
        Self::open_internal(store, inventory, Some((path, Arc::new(key)))).await
    }

    async fn open_internal(
        store: TursoCoordinatorStore,
        inventory: Arc<dyn InventoryProjectionStore>,
        publication: Option<(PathBuf, Arc<EnvelopeKey>)>,
    ) -> Result<Arc<Self>> {
        let mut ledger = store.privacy_ledger().await?;
        if let Some((path, key)) = &publication {
            if path.exists() {
                let path = path.clone();
                let key = key.clone();
                let mut external =
                    tokio::task::spawn_blocking(move || SuppressionLedgerV1::load(&path, &key))
                        .await??;
                ensure!(
                    external.deployment_id == ledger.deployment_id,
                    "suppression ledger deployment mismatch"
                );
                external.records.sort_by_key(|record| record.revision);
                for mut record in external.records {
                    if let Some(existing) = ledger
                        .records
                        .iter()
                        .find(|existing| existing.request_id == record.request_id)
                    {
                        ensure!(
                            existing.target == record.target
                                && existing.revision == record.revision
                                && existing.created_at == record.created_at,
                            "suppression ledger conflicts with durable policy"
                        );
                    } else {
                        record.reset_for_recovery();
                        store.put_privacy_record(record.clone()).await?;
                        ledger.revision = record.revision;
                        ledger.records.push(record);
                    }
                }
            } else {
                ensure!(
                    ledger.revision == 0,
                    "current suppression ledger is missing; recover it before serving"
                );
            }
            ledger.persist_async(path, key).await?;
        }
        inventory
            .install_suppressions(
                &ledger
                    .records
                    .iter()
                    .map(|record| record.target.clone())
                    .collect::<Vec<_>>(),
            )
            .await?;
        Ok(Arc::new(Self {
            gate: RwLock::new(PrivacyState {
                ledger,
                ready: true,
            }),
            notify: Notify::new(),
            store,
            inventory,
            publication,
        }))
    }

    pub async fn submit(
        &self,
        request_id: String,
        plan: RemovalPlanV1,
    ) -> Result<RemovalRequestV1> {
        ensure!(plan.schema_version == 1, PrivacyOperationError::InvalidPlan);
        plan.target
            .validate()
            .map_err(|_| PrivacyOperationError::InvalidPlan)?;
        Uuid::parse_str(&request_id).map_err(|_| PrivacyOperationError::InvalidPlan)?;
        let mut state = self.gate.write().await;
        if !state.ready {
            self.repair_policy(&mut state).await?;
        }
        ensure!(
            state.ready && plan.deployment_id == state.ledger.deployment_id,
            "privacy policy unavailable"
        );
        if let Some(existing) = state
            .ledger
            .records
            .iter()
            .find(|record| record.request_id == request_id)
        {
            ensure!(
                existing.target == plan.target,
                PrivacyOperationError::Conflict
            );
            return Ok(existing.clone());
        }
        let current = self.plan_with_state(plan.target.clone(), &state).await?;
        ensure!(
            current.target.aliases == plan.target.aliases,
            PrivacyOperationError::Conflict
        );
        let revision = state
            .ledger
            .revision
            .checked_add(1)
            .context("policy revision exhausted")?;
        let record = RemovalRequestV1 {
            schema_version: 1,
            request_id,
            deployment_id: plan.deployment_id,
            revision,
            target: plan.target,
            created_at: Utc::now(),
            phase: RemovalPhaseV1::Pending,
            attempts_removed: 0,
            artifacts_removed: 0,
            failure_code: None,
            task_cursor: None,
            artifact_cursor: None,
            failed_attempt_cursor: None,
            pending_artifact: None,
        };
        state.ready = false;
        self.store.put_privacy_record(record.clone()).await?;
        state.ledger.revision = revision;
        state.ledger.records.push(record.clone());
        if let Some((path, key)) = &self.publication {
            state.ledger.persist_async(path, key).await?;
        }
        self.inventory
            .install_suppressions(
                &state
                    .ledger
                    .records
                    .iter()
                    .map(|record| record.target.clone())
                    .collect::<Vec<_>>(),
            )
            .await?;
        state.ready = true;
        self.notify.notify_one();
        Ok(record)
    }

    pub async fn status(&self, request_id: &str) -> Option<RemovalRequestV1> {
        self.gate
            .read()
            .await
            .ledger
            .records
            .iter()
            .find(|record| record.request_id == request_id)
            .cloned()
    }

    pub async fn plan(&self, target: SuppressionTargetV1) -> Result<RemovalPlanV1> {
        let state = self.gate.read().await;
        ensure!(state.ready, "privacy policy unavailable");
        self.plan_with_state(target, &state).await
    }

    async fn plan_with_state(
        &self,
        mut target: SuppressionTargetV1,
        state: &PrivacyState,
    ) -> Result<RemovalPlanV1> {
        use crate::catalog::{
            InventoryAccessV1, InventoryHistoryModeV1, InventoryPageRequestV1, InventoryQueryV1,
        };
        target
            .validate()
            .map_err(|_| PrivacyOperationError::InvalidPlan)?;
        target.aliases.clear();
        let profiles = self
            .store
            .control_snapshot()
            .await?
            .credential_profiles
            .into_iter()
            .map(|profile| profile.id)
            .collect();
        let access = InventoryAccessV1 {
            principal_id: "privacy-maintenance".into(),
            private_credential_profiles: profiles,
        };
        let namespace = match &target.scope {
            RemovalScopeV1::All => None,
            RemovalScopeV1::Public => Some(InventoryNamespaceV1::Public),
            RemovalScopeV1::CredentialProfile {
                credential_profile_id,
            } => Some(InventoryNamespaceV1::Private {
                credential_profile_id: credential_profile_id.clone(),
            }),
        };
        let query = InventoryQueryV1 {
            schema_version: 1,
            namespace,
            history: InventoryHistoryModeV1::Observations,
            repository_ids: BTreeSet::from([target.repository_id.clone()]),
            ..InventoryQueryV1::default()
        };
        let mut page = InventoryPageRequestV1::default();
        let mut attempts = 0_u64;
        loop {
            let result = self.inventory.search(&access, &query, &page).await?;
            for item in &result.items {
                target
                    .aliases
                    .insert(item.repository.full_name.to_lowercase());
                target
                    .aliases
                    .extend(item.repository.aliases.iter().cloned());
            }
            attempts = attempts.saturating_add(result.items.len() as u64);
            page.cursor = result.next_cursor;
            if page.cursor.is_none() {
                break;
            }
        }
        for record in &state.ledger.records {
            if record.target.repository_id == target.repository_id
                && record.target.scope == target.scope
            {
                target.aliases.extend(record.target.aliases.iter().cloned());
            }
        }
        target.validate()?;
        Ok(RemovalPlanV1 {
            schema_version: 1,
            deployment_id: state.ledger.deployment_id.clone(),
            target,
            estimated_attempts: attempts,
        })
    }

    pub async fn retry(&self, request_id: &str) -> Result<RemovalRequestV1> {
        let mut state = self.gate.write().await;
        if !state.ready {
            self.repair_policy(&mut state).await?;
        }
        let existing = state
            .ledger
            .records
            .iter_mut()
            .find(|record| record.request_id == request_id)
            .context("unknown removal request")?;
        let mut record = existing.clone();
        if record.phase == RemovalPhaseV1::Failed {
            record.phase = RemovalPhaseV1::Pending;
            record.failure_code = None;
            record.task_cursor = None;
            record.artifact_cursor = None;
            record.failed_attempt_cursor = None;
            self.store.put_privacy_record(record.clone()).await?;
            *existing = record.clone();
            self.notify.notify_one();
        }
        Ok(record)
    }

    pub async fn update(&self, record: RemovalRequestV1) -> Result<()> {
        let mut state = self.gate.write().await;
        let existing = state
            .ledger
            .records
            .iter_mut()
            .find(|item| item.request_id == record.request_id)
            .context("unknown removal request")?;
        self.store.put_privacy_record(record.clone()).await?;
        *existing = record;
        Ok(())
    }

    async fn repair_policy(&self, state: &mut PrivacyState) -> Result<()> {
        let recovered = Self::open_internal(
            self.store.clone(),
            self.inventory.clone(),
            self.publication.clone(),
        )
        .await?;
        let recovered = recovered.gate.read().await;
        ensure!(
            state.ledger.records.iter().all(|record| recovered
                .ledger
                .records
                .iter()
                .any(|candidate| candidate.request_id == record.request_id
                    && candidate.target == record.target)),
            "recovered policy cannot remove existing suppression"
        );
        *state = recovered.clone();
        self.notify.notify_one();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SuppressionTargetV1 {
        SuppressionTargetV1 {
            repository_id: "42".into(),
            scope: RemovalScopeV1::Public,
            aliases: BTreeSet::from(["owner/old".into()]),
        }
    }

    #[test]
    fn suppression_binds_identity_alias_and_namespace() {
        let subject = target();
        subject.validate().unwrap();
        assert!(subject.matches(&InventoryNamespaceV1::Public, "42", "new/name"));
        assert!(subject.matches(&InventoryNamespaceV1::Public, "", "OWNER/OLD"));
        assert!(!subject.matches(&InventoryNamespaceV1::Public, "99", "OWNER/OLD"));
        assert!(!subject.matches(&InventoryNamespaceV1::Public, "99", "other/name"));
        assert!(!subject.matches(
            &InventoryNamespaceV1::Private {
                credential_profile_id: "private".into()
            },
            "42",
            "owner/old"
        ));
    }

    #[test]
    fn ledger_authenticates_and_rejects_wrong_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger");
        let key = EnvelopeKey::generate(LEDGER_KEY_ID);
        let ledger = SuppressionLedgerV1 {
            schema_version: 1,
            deployment_id: Uuid::new_v4().to_string(),
            revision: 0,
            records: vec![],
        };
        ledger.persist(&path, &key).unwrap();
        assert_eq!(SuppressionLedgerV1::load(&path, &key).unwrap(), ledger);
        assert!(SuppressionLedgerV1::load(&path, &EnvelopeKey::generate(LEDGER_KEY_ID)).is_err());
    }

    #[tokio::test]
    async fn retry_repairs_failed_publication_without_lifting_suppression() {
        let directory = tempfile::tempdir().unwrap();
        let ledger_path = directory.path().join("ledger");
        let key_path = directory.path().join("key");
        EnvelopeKey::generate(LEDGER_KEY_ID)
            .persist_new(&key_path)
            .unwrap();
        let store = TursoCoordinatorStore::open(
            directory.path().join("state.db"),
            EnvelopeKey::generate("journal"),
        )
        .await
        .unwrap();
        let inventory = Arc::new(crate::catalog::InMemoryInventoryStore::new([11; 32]));
        let service = PrivacyService::open_with_ledger(
            store.clone(),
            inventory,
            ledger_path.clone(),
            EnvelopeKey::load(&key_path, LEDGER_KEY_ID).unwrap(),
        )
        .await
        .unwrap();
        let original = service.gate.read().await.ledger.clone();
        let plan = service.plan(target()).await.unwrap();
        let request_id = Uuid::new_v4().to_string();
        std::fs::remove_file(&ledger_path).unwrap();
        std::fs::create_dir(&ledger_path).unwrap();
        assert!(
            service
                .submit(request_id.clone(), plan.clone())
                .await
                .is_err()
        );
        assert!(!service.gate.read().await.ready);
        assert_eq!(store.privacy_ledger().await.unwrap().revision, 1);
        std::fs::remove_dir(&ledger_path).unwrap();
        original
            .persist(
                &ledger_path,
                &EnvelopeKey::load(&key_path, LEDGER_KEY_ID).unwrap(),
            )
            .unwrap();
        let record = service.submit(request_id.clone(), plan).await.unwrap();
        assert_eq!(record.request_id, request_id);
        assert!(service.gate.read().await.ready);
        assert_eq!(
            SuppressionLedgerV1::load(
                &ledger_path,
                &EnvelopeKey::load(&key_path, LEDGER_KEY_ID).unwrap()
            )
            .unwrap()
            .revision,
            1
        );
        drop(service);
        store.shutdown_offline().await.unwrap();
    }

    #[tokio::test]
    async fn startup_repairs_database_ahead_and_imports_newer_independent_policy() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("coordinator.db");
        let path = directory.path().join("suppression.ledger");
        let key = EnvelopeKey::generate(LEDGER_KEY_ID);
        let key_path = directory.path().join("suppression.key");
        key.persist_new(&key_path).unwrap();
        let store = TursoCoordinatorStore::open(database, EnvelopeKey::generate("journal"))
            .await
            .unwrap();
        let inventory = Arc::new(crate::catalog::InMemoryInventoryStore::new([7; 32]));
        let service = PrivacyService::open_with_ledger(
            store.clone(),
            inventory.clone(),
            path.clone(),
            EnvelopeKey::load(&key_path, LEDGER_KEY_ID).unwrap(),
        )
        .await
        .unwrap();
        let plan = service.plan(target()).await.unwrap();
        let first = service
            .submit(Uuid::new_v4().to_string(), plan)
            .await
            .unwrap();
        assert_eq!(SuppressionLedgerV1::load(&path, &key).unwrap().revision, 1);
        let mut second = first.clone();
        second.request_id = Uuid::new_v4().to_string();
        second.revision = 2;
        second.target.repository_id = "43".into();
        store.put_privacy_record(second).await.unwrap();
        drop(service);
        let service = PrivacyService::open_with_ledger(
            store.clone(),
            inventory.clone(),
            path.clone(),
            EnvelopeKey::load(&key_path, LEDGER_KEY_ID).unwrap(),
        )
        .await
        .unwrap();
        let mut external = SuppressionLedgerV1::load(&path, &key).unwrap();
        assert_eq!(external.revision, 2);
        let mut third = first;
        third.request_id = Uuid::new_v4().to_string();
        third.revision = 3;
        third.target.repository_id = "44".into();
        third.phase = RemovalPhaseV1::Completed;
        third.artifacts_removed = 100;
        external.records.push(third.clone());
        external.revision = 3;
        external.persist(&path, &key).unwrap();
        drop(service);
        let service = PrivacyService::open_with_ledger(store.clone(), inventory.clone(), path, key)
            .await
            .unwrap();
        let imported = service.status(&third.request_id).await.unwrap();
        assert_eq!(imported.phase, RemovalPhaseV1::Pending);
        assert_eq!(imported.artifacts_removed, 0);
        assert_eq!(store.privacy_ledger().await.unwrap().revision, 3);
        drop(service);
        drop(inventory);
        store.shutdown_offline().await.unwrap();
    }

    #[test]
    fn policy_digest_is_stable_across_progress_but_requires_complete_history() {
        let mut record = RemovalRequestV1 {
            schema_version: 1,
            request_id: Uuid::new_v4().to_string(),
            deployment_id: Uuid::new_v4().to_string(),
            revision: 1,
            target: target(),
            created_at: Utc::now(),
            phase: RemovalPhaseV1::Pending,
            attempts_removed: 0,
            artifacts_removed: 0,
            failure_code: None,
            task_cursor: None,
            artifact_cursor: None,
            failed_attempt_cursor: None,
            pending_artifact: None,
        };
        let mut ledger = SuppressionLedgerV1 {
            schema_version: 1,
            deployment_id: record.deployment_id.clone(),
            revision: 1,
            records: vec![record.clone()],
        };
        let digest = ledger.policy_digest().unwrap();
        record.phase = RemovalPhaseV1::Completed;
        record.attempts_removed = 30;
        ledger.records[0] = record;
        assert_eq!(ledger.policy_digest().unwrap(), digest);
        ledger.revision = 2;
        assert!(ledger.validate().is_err());
    }
}
