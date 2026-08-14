//! Durable Turso Adapter for the searchable inventory projection.
//!
//! This Adapter opens another connection to the coordinator's database. It
//! intentionally does not acquire the coordinator owner lock: callers must
//! construct it only inside the already-single-owner coordinator process.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use futures::{FutureExt as _, future::BoxFuture};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

use super::{
    InMemoryInventoryStore, InventoryProjectionStore,
    cursor::CursorSigner,
    model::{
        CATALOG_SCHEMA_VERSION_V1, CatalogError, InventoryAccessV1, InventoryHistoryModeV1,
        InventoryNamespaceV1, InventoryPageRequestV1, InventoryPageV1, InventoryProjectionInputV1,
        InventoryProjectionOutcomeV1, InventoryQueryV1, InventorySearchResultV1, PackagePresenceV1,
        SavedInventoryQueryDraftV1, SavedInventoryQueryRevisionV1,
    },
    sql_search,
};

const DURABLE_SCHEMA_VERSION: u16 = 1;
const MAX_BULK_BINDINGS: usize = 900;

struct DatabaseState {
    database: turso::Database,
    connection: turso::Connection,
}

/// Durable read-model store owned by the coordinator process.
pub(crate) struct TursoInventoryStore {
    database: Mutex<DatabaseState>,
    cursor_signer: CursorSigner,
}

impl TursoInventoryStore {
    /// Open the shared coordinator database without acquiring a second owner
    /// lock. The caller must already own the coordinator's single-process lock.
    pub(crate) async fn open(
        database_path: impl Into<PathBuf>,
        cursor_signing_key: [u8; 32],
    ) -> Result<Self, CatalogError> {
        let database_path = normalized_database_path(database_path.into()).await?;
        let database_path = database_path
            .to_str()
            .ok_or(CatalogError::StoreUnavailable)?;
        let database = turso::Builder::new_local(database_path)
            .build()
            .await
            .map_err(unavailable)?;
        let connection = database.connect().map_err(unavailable)?;
        migrate(&connection).await?;

        let watermark = metadata_u64(&connection, "watermark").await?;
        let cursor_floor = metadata_u64(&connection, "cursor_floor").await?;
        if cursor_floor > watermark {
            return Err(CatalogError::StoreUnavailable);
        }

        Ok(Self {
            database: Mutex::new(DatabaseState {
                database,
                connection,
            }),
            cursor_signer: CursorSigner::new(cursor_signing_key),
        })
    }

    async fn project_durable(
        &self,
        input: InventoryProjectionInputV1,
    ) -> Result<InventoryProjectionOutcomeV1, CatalogError> {
        let preview = preview_projection(&input).await?;
        let payload_json = serde_json::to_string(&input).map_err(unavailable)?;
        let payload_sha256 = sha256_hex(payload_json.as_bytes());
        let namespace = input_namespace(&input);
        let namespace_key = NamespaceKey::from(namespace);
        let database = self.database.lock().await;
        let connection = &database.connection;

        if let Some(existing) =
            existing_projection(connection, namespace_key, &preview.outcome.attempt_id).await?
        {
            if existing.payload_sha256 != payload_sha256
                || existing.observation_id != preview.outcome.observation_id
            {
                return Err(CatalogError::InvalidEvidence(
                    "a logical task attempt was projected with different evidence".to_owned(),
                ));
            }
            return Ok(InventoryProjectionOutcomeV1 {
                attempt_id: preview.outcome.attempt_id,
                observation_id: preview.outcome.observation_id,
                projection_sequence: existing.sequence,
                index_watermark: metadata_u64(connection, "watermark").await?,
                already_projected: true,
            });
        }

        connection
            .execute_batch("BEGIN IMMEDIATE")
            .await
            .map_err(unavailable)?;
        let persisted = async {
            let watermark = metadata_u64(connection, "watermark").await?;
            let sequence = watermark
                .checked_add(1)
                .ok_or(CatalogError::StoreUnavailable)?;
            persist_projection(
                connection,
                sequence,
                &input,
                &payload_json,
                &payload_sha256,
                &preview,
            )
            .await?;
            set_metadata_u64(connection, "watermark", sequence).await?;
            Ok::<u64, CatalogError>(sequence)
        }
        .await;
        let sequence = finish_transaction(connection, persisted).await?;

        Ok(InventoryProjectionOutcomeV1 {
            attempt_id: preview.outcome.attempt_id,
            observation_id: preview.outcome.observation_id,
            projection_sequence: sequence,
            index_watermark: sequence,
            already_projected: false,
        })
    }

    async fn rebuild_durable(
        &self,
        mut inputs: Vec<InventoryProjectionInputV1>,
    ) -> Result<(), CatalogError> {
        inputs.sort_by(|left, right| {
            left.completed_at()
                .cmp(&right.completed_at())
                .then_with(|| left.stable_order_key().cmp(&right.stable_order_key()))
        });
        let mut unique = Vec::new();
        let mut identities = std::collections::BTreeMap::<String, String>::new();
        for input in inputs {
            let preview = preview_projection(&input).await?;
            let payload_json = serde_json::to_string(&input).map_err(unavailable)?;
            let payload_sha256 = sha256_hex(payload_json.as_bytes());
            match identities.get(&preview.outcome.attempt_id) {
                Some(existing) if existing != &payload_sha256 => {
                    return Err(CatalogError::InvalidEvidence(
                        "a logical task attempt was rebuilt with different evidence".to_owned(),
                    ));
                }
                Some(_) => continue,
                None => {
                    identities.insert(preview.outcome.attempt_id.clone(), payload_sha256.clone());
                    unique.push(RebuildProjection {
                        input,
                        preview,
                        payload_json,
                        payload_sha256,
                        sequence: 0,
                    });
                }
            }
        }
        enrich_rebuild_repository_aliases(&mut unique);

        let database = self.database.lock().await;
        let connection = &database.connection;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .await
            .map_err(unavailable)?;
        let persisted = async {
            let previous_watermark = metadata_u64(connection, "watermark").await?;
            clear_projection(connection).await?;
            let sequence = assign_rebuild_sequences(previous_watermark, &mut unique)?;
            persist_rebuild(connection, &unique).await?;
            set_metadata_u64(connection, "watermark", sequence).await?;
            set_metadata_u64(connection, "cursor_floor", sequence).await?;
            Ok::<_, CatalogError>(sequence)
        }
        .await;
        finish_transaction(connection, persisted).await.map(|_| ())
    }

    async fn save_query_durable(
        &self,
        access: &InventoryAccessV1,
        draft: SavedInventoryQueryDraftV1,
    ) -> Result<SavedInventoryQueryRevisionV1, CatalogError> {
        validate_saved_query_with_adapter(access, &draft).await?;
        let database = self.database.lock().await;
        let connection = &database.connection;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .await
            .map_err(unavailable)?;
        let persisted = persist_saved_query(connection, access, &draft).await;
        finish_transaction(connection, persisted).await
    }

    async fn retain_since_durable(&self, cutoff: DateTime<Utc>) -> Result<usize, CatalogError> {
        let database = self.database.lock().await;
        let connection = &database.connection;
        let expired = expired_attempts(connection, cutoff).await?;
        remove_attempts_durable(connection, &expired).await
    }

    async fn remove_artifact_projection_durable(
        &self,
        task_id: &crate::coordinator::TaskId,
        artifact_digest: &crate::coordinator::Sha256Digest,
    ) -> Result<usize, CatalogError> {
        let database = self.database.lock().await;
        let connection = &database.connection;
        let expired = artifact_attempts(connection, task_id, artifact_digest).await?;
        remove_attempts_durable(connection, &expired).await
    }

    async fn read_connection(&self) -> Result<turso::Connection, CatalogError> {
        self.database
            .lock()
            .await
            .database
            .connect()
            .map_err(unavailable)
    }

    async fn search_durable(
        &self,
        access: &InventoryAccessV1,
        query: &InventoryQueryV1,
        page: &InventoryPageRequestV1,
    ) -> Result<InventoryPageV1, CatalogError> {
        self.search_durable_with_candidate_observer(access, query, page, |_| Ok(()))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn search_with_candidate_timing(
        &self,
        access: &InventoryAccessV1,
        query: &InventoryQueryV1,
        page: &InventoryPageRequestV1,
    ) -> Result<(InventoryPageV1, std::time::Duration), CatalogError> {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };

        let started = std::time::Instant::now();
        let candidate_nanos = Arc::new(AtomicU64::new(0));
        let observed_nanos = Arc::clone(&candidate_nanos);
        let result = self
            .search_durable_with_candidate_observer(access, query, page, move |_| {
                let elapsed = started.elapsed().as_nanos();
                eprintln!(
                    "catalog candidates ready after {:?}",
                    std::time::Duration::from_nanos(u64::try_from(elapsed).unwrap_or(u64::MAX))
                );
                observed_nanos.store(
                    u64::try_from(elapsed).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                Ok(())
            })
            .await?;
        Ok((
            result,
            std::time::Duration::from_nanos(candidate_nanos.load(Ordering::Relaxed)),
        ))
    }

    async fn search_durable_with_candidate_observer<Observer>(
        &self,
        access: &InventoryAccessV1,
        query: &InventoryQueryV1,
        page: &InventoryPageRequestV1,
        after_candidates: Observer,
    ) -> Result<InventoryPageV1, CatalogError>
    where
        Observer: FnOnce(&turso::Connection) -> Result<(), CatalogError> + Send,
    {
        // Authorization and cursor binding are enforced by sql_search before
        // inventory rows are ranked. The read transaction keeps the metadata
        // watermark, candidate page, and bounded hydration on one snapshot.
        let mut connection = self.read_connection().await?;
        let transaction = connection.transaction().await.map_err(unavailable)?;
        let searched = sql_search::search_with_candidate_observer(
            &transaction,
            &self.cursor_signer,
            access,
            query,
            page,
            after_candidates,
        )
        .await;
        match searched {
            Ok(page) => {
                transaction.commit().await.map_err(unavailable)?;
                Ok(page)
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(error)
            }
        }
    }

    async fn saved_query_durable(
        &self,
        access: &InventoryAccessV1,
        query_id: &str,
        revision: Option<u64>,
    ) -> Result<Option<SavedInventoryQueryRevisionV1>, CatalogError> {
        access.validate()?;
        let connection = self.read_connection().await?;
        let mut rows = connection
            .query(
                "SELECT revision_json FROM catalog_saved_query_revisions
                 WHERE query_id = ?1 AND (?2 IS NULL OR revision = ?2)
                 ORDER BY revision DESC LIMIT 1",
                turso::params![query_id, revision.map(to_i64).transpose()?],
            )
            .await
            .map_err(unavailable)?;
        let Some(row) = rows.next().await.map_err(unavailable)? else {
            return Ok(None);
        };
        let encoded: String = row.get(0).map_err(unavailable)?;
        let saved: SavedInventoryQueryRevisionV1 =
            serde_json::from_str(&encoded).map_err(unavailable)?;
        if !access.allows(&saved.namespace) {
            return Err(CatalogError::Unauthorized);
        }
        Ok(Some(saved))
    }

    async fn repository_for_alias_durable(
        &self,
        namespace: &InventoryNamespaceV1,
        normalized_alias: &str,
    ) -> Result<Option<super::model::InventoryRepositoryV1>, CatalogError> {
        namespace.validate()?;
        if normalized_alias.is_empty()
            || sql_search::normalize_text(normalized_alias) != normalized_alias
        {
            return Err(CatalogError::InvalidInput(
                "repository alias must be non-empty and normalized".to_owned(),
            ));
        }
        let namespace = NamespaceKey::from(namespace);
        let connection = self.read_connection().await?;
        let mut rows = connection
            .query(
                "SELECT repositories.repository_json
                   FROM catalog_repositories AS repositories
                  WHERE repositories.namespace_kind = ?1
                    AND repositories.credential_profile_id = ?2
                    AND (repositories.normalized_full_name = ?3 OR EXISTS (
                        SELECT 1 FROM catalog_repository_aliases AS aliases
                         WHERE aliases.namespace_kind = repositories.namespace_kind
                           AND aliases.credential_profile_id = repositories.credential_profile_id
                           AND aliases.repository_id = repositories.repository_id
                           AND aliases.normalized_alias = ?3))
                  ORDER BY repositories.repository_id LIMIT 2",
                turso::params![
                    namespace.kind,
                    namespace.credential_profile_id.as_str(),
                    normalized_alias
                ],
            )
            .await
            .map_err(unavailable)?;
        let first = rows.next().await.map_err(unavailable)?;
        let second = rows.next().await.map_err(unavailable)?;
        if second.is_some() {
            return Ok(None);
        }
        first
            .map(|row| {
                let encoded: String = row.get(0).map_err(unavailable)?;
                serde_json::from_str(&encoded).map_err(unavailable)
            })
            .transpose()
    }

    async fn watermark_durable(&self) -> Result<u64, CatalogError> {
        let connection = self.read_connection().await?;
        metadata_u64(&connection, "watermark").await
    }
}

impl InventoryProjectionStore for TursoInventoryStore {
    fn project<'a>(
        &'a self,
        input: InventoryProjectionInputV1,
    ) -> BoxFuture<'a, Result<InventoryProjectionOutcomeV1, CatalogError>> {
        async move { self.project_durable(input).await }.boxed()
    }

    fn rebuild(
        &self,
        inputs: Vec<InventoryProjectionInputV1>,
    ) -> BoxFuture<'_, Result<(), CatalogError>> {
        async move { self.rebuild_durable(inputs).await }.boxed()
    }

    fn search<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        query: &'a InventoryQueryV1,
        page: &'a InventoryPageRequestV1,
    ) -> BoxFuture<'a, Result<InventoryPageV1, CatalogError>> {
        async move { self.search_durable(access, query, page).await }.boxed()
    }

    fn save_query<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        draft: SavedInventoryQueryDraftV1,
    ) -> BoxFuture<'a, Result<SavedInventoryQueryRevisionV1, CatalogError>> {
        async move { self.save_query_durable(access, draft).await }.boxed()
    }

    fn saved_query<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        query_id: &'a str,
        revision: Option<u64>,
    ) -> BoxFuture<'a, Result<Option<SavedInventoryQueryRevisionV1>, CatalogError>> {
        async move { self.saved_query_durable(access, query_id, revision).await }.boxed()
    }

    fn remove_artifact_projection<'a>(
        &'a self,
        task_id: &'a crate::coordinator::TaskId,
        artifact_digest: &'a crate::coordinator::Sha256Digest,
    ) -> BoxFuture<'a, Result<usize, CatalogError>> {
        async move {
            self.remove_artifact_projection_durable(task_id, artifact_digest)
                .await
        }
        .boxed()
    }

    fn repository_for_alias<'a>(
        &'a self,
        namespace: &'a InventoryNamespaceV1,
        normalized_alias: &'a str,
    ) -> BoxFuture<'a, Result<Option<super::model::InventoryRepositoryV1>, CatalogError>> {
        async move {
            self.repository_for_alias_durable(namespace, normalized_alias)
                .await
        }
        .boxed()
    }

    fn retain_since(&self, cutoff: DateTime<Utc>) -> BoxFuture<'_, Result<usize, CatalogError>> {
        async move { self.retain_since_durable(cutoff).await }.boxed()
    }

    fn watermark(&self) -> BoxFuture<'_, Result<u64, CatalogError>> {
        async move { self.watermark_durable().await }.boxed()
    }
}

async fn normalized_database_path(requested: PathBuf) -> Result<PathBuf, CatalogError> {
    let file_name = requested
        .file_name()
        .ok_or(CatalogError::StoreUnavailable)?;
    let parent = requested
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(unavailable)?;
    let parent = std::fs::canonicalize(parent).map_err(unavailable)?;
    Ok(parent.join(file_name))
}

async fn migrate(connection: &turso::Connection) -> Result<(), CatalogError> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS catalog_metadata (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS catalog_projection_inputs (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 attempt_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL,
                 observation_id TEXT,
                 repository_id TEXT NOT NULL,
                 completed_at TEXT NOT NULL,
                 payload_sha256 TEXT NOT NULL,
                 payload_json TEXT NOT NULL,
                 PRIMARY KEY (namespace_kind, credential_profile_id, attempt_id)
             );
             CREATE INDEX IF NOT EXISTS catalog_projection_inputs_sequence
                 ON catalog_projection_inputs (sequence);
             CREATE INDEX IF NOT EXISTS catalog_projection_inputs_retention
                 ON catalog_projection_inputs
                    (namespace_kind, credential_profile_id, completed_at, attempt_id);
             CREATE TABLE IF NOT EXISTS catalog_projection_outbox (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL,
                 attempt_id TEXT NOT NULL,
                 payload_sha256 TEXT NOT NULL,
                 enqueued_at TEXT NOT NULL,
                 projected_at TEXT,
                 PRIMARY KEY (namespace_kind, credential_profile_id, sequence),
                 UNIQUE (namespace_kind, credential_profile_id, attempt_id)
             );
             CREATE TABLE IF NOT EXISTS catalog_projection_checkpoints (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 last_sequence INTEGER NOT NULL,
                 updated_at TEXT NOT NULL,
                 PRIMARY KEY (namespace_kind, credential_profile_id)
             );
             CREATE TABLE IF NOT EXISTS catalog_repositories (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 repository_id TEXT NOT NULL,
                 full_name TEXT NOT NULL,
                 normalized_full_name TEXT NOT NULL,
                 owner TEXT NOT NULL,
                 normalized_owner TEXT NOT NULL,
                 visibility TEXT NOT NULL,
                 first_observed_at TEXT NOT NULL,
                 last_observed_at TEXT NOT NULL,
                 repository_json TEXT NOT NULL,
                 PRIMARY KEY (namespace_kind, credential_profile_id, repository_id)
             );
             CREATE INDEX IF NOT EXISTS catalog_repositories_name
                 ON catalog_repositories
                    (namespace_kind, credential_profile_id, normalized_full_name, repository_id);
             CREATE TABLE IF NOT EXISTS catalog_repository_aliases (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 repository_id TEXT NOT NULL,
                 normalized_alias TEXT NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, repository_id, normalized_alias
                 )
             );
             CREATE TABLE IF NOT EXISTS catalog_snapshots (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 repository_id TEXT NOT NULL,
                 commit_sha TEXT NOT NULL,
                 tree_sha TEXT NOT NULL,
                 analyzer_profile_digest TEXT NOT NULL,
                 head_committed_at TEXT,
                 first_observed_at TEXT NOT NULL,
                 last_observed_at TEXT NOT NULL,
                 snapshot_json TEXT NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, repository_id,
                     commit_sha, tree_sha, analyzer_profile_digest
                 )
             );
             CREATE TABLE IF NOT EXISTS catalog_attempts (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 attempt_id TEXT NOT NULL,
                 projection_digest TEXT NOT NULL,
                 projection_sequence INTEGER NOT NULL,
                 repository_id TEXT NOT NULL,
                 normalized_repository_name TEXT NOT NULL,
                 normalized_repository_owner TEXT NOT NULL,
                 repository_visibility TEXT NOT NULL,
                 job_id TEXT NOT NULL,
                 task_id TEXT NOT NULL,
                 task_attempt INTEGER NOT NULL,
                 completed_at TEXT NOT NULL,
                 status TEXT NOT NULL,
                 failure_code TEXT,
                 failure_message TEXT,
                 observation_id TEXT,
                 snapshot_commit_sha TEXT,
                 snapshot_tree_sha TEXT,
                 snapshot_analyzer_profile_digest TEXT,
                 attempt_json TEXT NOT NULL,
                 PRIMARY KEY (namespace_kind, credential_profile_id, attempt_id)
             );
             CREATE INDEX IF NOT EXISTS catalog_attempts_repository_order
                 ON catalog_attempts (
                     namespace_kind, credential_profile_id, repository_id,
                     completed_at DESC, task_id DESC, task_attempt DESC, attempt_id DESC
                 );
             CREATE INDEX IF NOT EXISTS catalog_attempts_projection_sequence
                 ON catalog_attempts (
                     namespace_kind, credential_profile_id, projection_sequence,
                     repository_id, attempt_id
                 );
             CREATE INDEX IF NOT EXISTS catalog_attempts_task_id
                 ON catalog_attempts (
                     task_id, namespace_kind, credential_profile_id, attempt_id
                 );
             CREATE INDEX IF NOT EXISTS catalog_attempts_search_order
                 ON catalog_attempts (
                     namespace_kind, credential_profile_id, normalized_repository_name,
                     completed_at DESC, attempt_id
                 );
             CREATE TABLE IF NOT EXISTS catalog_observations (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 observation_id TEXT NOT NULL,
                 attempt_id TEXT NOT NULL,
                 repository_id TEXT NOT NULL,
                 target_name TEXT NOT NULL,
                 normalized_target_name TEXT NOT NULL,
                 target_version TEXT NOT NULL,
                 target_source TEXT,
                 recorded_relation TEXT NOT NULL,
                 exact_resolution_count INTEGER NOT NULL,
                 msrv TEXT,
                 msrv_sort_key BLOB,
                 strength TEXT NOT NULL,
                 completeness TEXT NOT NULL,
                 globally_exhaustive INTEGER NOT NULL,
                 package_inventory_complete INTEGER NOT NULL,
                 observed_at TEXT NOT NULL,
                 observation_json TEXT NOT NULL,
                 PRIMARY KEY (namespace_kind, credential_profile_id, observation_id)
             );
             CREATE INDEX IF NOT EXISTS catalog_observations_target
                 ON catalog_observations (
                     namespace_kind, credential_profile_id,
                     target_name, target_version, target_source, observed_at DESC
                 );
             CREATE INDEX IF NOT EXISTS catalog_observations_msrv
                 ON catalog_observations (
                     namespace_kind, credential_profile_id, msrv_sort_key, attempt_id
                 );
             CREATE TABLE IF NOT EXISTS catalog_requirements (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 observation_id TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 source TEXT NOT NULL,
                 manifest_path TEXT NOT NULL,
                 package_name TEXT,
                 requirement TEXT,
                 accepts_target INTEGER,
                 explicit_exact_pin INTEGER,
                 requirement_json TEXT NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, observation_id, ordinal
                 )
             );
             CREATE INDEX IF NOT EXISTS catalog_requirements_lookup
                 ON catalog_requirements (
                     namespace_kind, credential_profile_id, requirement, observation_id
                 );
             CREATE TABLE IF NOT EXISTS catalog_packages (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 observation_id TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 repository_id TEXT NOT NULL,
                 package_name TEXT NOT NULL,
                 normalized_package_name TEXT NOT NULL,
                 package_version TEXT NOT NULL,
                 package_source TEXT,
                 license_expression TEXT,
                 inventory_complete INTEGER NOT NULL,
                 package_json TEXT NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, observation_id, ordinal
                 )
             );
             CREATE INDEX IF NOT EXISTS catalog_packages_lookup
                 ON catalog_packages (
                     namespace_kind, credential_profile_id,
                     package_name, package_version, package_source, observation_id
                 );
             CREATE TABLE IF NOT EXISTS catalog_limitations (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 observation_id TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 code TEXT NOT NULL,
                 message TEXT NOT NULL,
                 limitation_json TEXT NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, observation_id, ordinal
                 )
             );
             CREATE INDEX IF NOT EXISTS catalog_limitations_code
                 ON catalog_limitations
                    (namespace_kind, credential_profile_id, code, observation_id);
             CREATE TABLE IF NOT EXISTS catalog_search_documents (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 attempt_id TEXT NOT NULL,
                 ready INTEGER NOT NULL,
                 PRIMARY KEY (namespace_kind, credential_profile_id, attempt_id),
                 FOREIGN KEY (namespace_kind, credential_profile_id, attempt_id)
                     REFERENCES catalog_attempts
                         (namespace_kind, credential_profile_id, attempt_id)
                     ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS catalog_search_terms (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 attempt_id TEXT NOT NULL,
                 field TEXT NOT NULL,
                 term TEXT NOT NULL,
                 term_byte_len INTEGER NOT NULL,
                 trigram_count INTEGER NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, attempt_id, field, term
                 ),
                 FOREIGN KEY (namespace_kind, credential_profile_id, attempt_id)
                     REFERENCES catalog_search_documents
                         (namespace_kind, credential_profile_id, attempt_id)
                     ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS catalog_search_terms_exact
                 ON catalog_search_terms (
                     namespace_kind, credential_profile_id, field, term, attempt_id
                 );
             CREATE TABLE IF NOT EXISTS catalog_search_trigrams (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 attempt_id TEXT NOT NULL,
                 field TEXT NOT NULL,
                 term TEXT NOT NULL,
                 trigram TEXT NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, trigram,
                     attempt_id, field, term
                 ),
                 FOREIGN KEY (namespace_kind, credential_profile_id, attempt_id)
                     REFERENCES catalog_search_documents
                         (namespace_kind, credential_profile_id, attempt_id)
                     ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS catalog_latest (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 repository_id TEXT NOT NULL,
                 latest_attempt_id TEXT,
                 latest_evidence_id TEXT,
                 latest_complete_evidence_id TEXT,
                 PRIMARY KEY (namespace_kind, credential_profile_id, repository_id)
             );
             CREATE TABLE IF NOT EXISTS catalog_saved_query_revisions (
                 namespace_kind TEXT NOT NULL,
                 credential_profile_id TEXT NOT NULL,
                 query_id TEXT NOT NULL,
                 revision INTEGER NOT NULL,
                 name TEXT NOT NULL,
                 created_by TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 revision_json TEXT NOT NULL,
                 PRIMARY KEY (
                     namespace_kind, credential_profile_id, query_id, revision
                 )
             );
             CREATE INDEX IF NOT EXISTS catalog_saved_query_identity
                 ON catalog_saved_query_revisions (query_id, revision);
             INSERT OR IGNORE INTO catalog_metadata (key, value)
                 VALUES ('schema_version', '1');
             INSERT OR IGNORE INTO catalog_metadata (key, value)
                 VALUES ('watermark', '0');
             INSERT OR IGNORE INTO catalog_metadata (key, value)
                 VALUES ('cursor_floor', '0');",
        )
        .await
        .map_err(unavailable)?;
    let schema_version = metadata_u64(connection, "schema_version").await?;
    if schema_version != u64::from(DURABLE_SCHEMA_VERSION) {
        return Err(CatalogError::UnsupportedSchemaVersion(
            u16::try_from(schema_version).unwrap_or(u16::MAX),
        ));
    }
    Ok(())
}

fn unavailable<E>(_error: E) -> CatalogError {
    CatalogError::StoreUnavailable
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NamespaceKey {
    kind: &'static str,
    credential_profile_id: String,
}

impl From<&InventoryNamespaceV1> for NamespaceKey {
    fn from(namespace: &InventoryNamespaceV1) -> Self {
        match namespace {
            InventoryNamespaceV1::Public => Self {
                kind: "public",
                credential_profile_id: String::new(),
            },
            InventoryNamespaceV1::Private {
                credential_profile_id,
            } => Self {
                kind: "private",
                credential_profile_id: credential_profile_id.clone(),
            },
        }
    }
}

struct ProjectionPreview {
    outcome: InventoryProjectionOutcomeV1,
    result: InventorySearchResultV1,
}

struct RebuildProjection {
    input: InventoryProjectionInputV1,
    preview: ProjectionPreview,
    payload_json: String,
    payload_sha256: String,
    sequence: u64,
}

#[derive(Default)]
struct LatestPointers {
    attempt: Option<usize>,
    evidence: Option<usize>,
    complete_evidence: Option<usize>,
}

struct ExistingProjection {
    sequence: u64,
    observation_id: Option<String>,
    payload_sha256: String,
}

#[derive(Clone)]
struct ExpiredAttempt {
    namespace: NamespaceKey,
    attempt_id: String,
    observation_id: Option<String>,
    repository_id: String,
}

async fn preview_projection(
    input: &InventoryProjectionInputV1,
) -> Result<ProjectionPreview, CatalogError> {
    let store = InMemoryInventoryStore::new([0x5a; 32]);
    let outcome = store.project(input.clone()).await?;
    let namespace = input_namespace(input).clone();
    let mut query = InventoryQueryV1::new();
    query.namespace = Some(namespace.clone());
    query.history = InventoryHistoryModeV1::Observations;
    query
        .repository_ids
        .insert(input_repository_id(input).to_owned());
    let page = store
        .search(
            &access_for_namespace(&namespace),
            &query,
            &InventoryPageRequestV1 {
                limit: Some(2),
                cursor: None,
            },
        )
        .await?;
    let result = page
        .items
        .into_iter()
        .find(|result| result.attempt.attempt_id == outcome.attempt_id)
        .ok_or(CatalogError::StoreUnavailable)?;
    Ok(ProjectionPreview { outcome, result })
}

fn input_namespace(input: &InventoryProjectionInputV1) -> &InventoryNamespaceV1 {
    match input {
        InventoryProjectionInputV1::Observation(envelope) => &envelope.namespace,
        InventoryProjectionInputV1::FailedAttempt(attempt) => &attempt.namespace,
    }
}

fn input_repository_id(input: &InventoryProjectionInputV1) -> &str {
    match input {
        InventoryProjectionInputV1::Observation(envelope) => &envelope.repository_id,
        InventoryProjectionInputV1::FailedAttempt(attempt) => &attempt.repository_id,
    }
}

fn access_for_namespace(namespace: &InventoryNamespaceV1) -> InventoryAccessV1 {
    let private_credential_profiles = match namespace {
        InventoryNamespaceV1::Public => BTreeSet::new(),
        InventoryNamespaceV1::Private {
            credential_profile_id,
        } => BTreeSet::from([credential_profile_id.clone()]),
    };
    InventoryAccessV1 {
        principal_id: "catalog-durable-adapter".to_owned(),
        private_credential_profiles,
    }
}

async fn metadata_u64(connection: &turso::Connection, key: &str) -> Result<u64, CatalogError> {
    let mut rows = connection
        .query(
            "SELECT value FROM catalog_metadata WHERE key = ?1",
            turso::params![key],
        )
        .await
        .map_err(unavailable)?;
    let row = rows
        .next()
        .await
        .map_err(unavailable)?
        .ok_or(CatalogError::StoreUnavailable)?;
    let value: String = row.get(0).map_err(unavailable)?;
    value.parse().map_err(unavailable)
}

async fn set_metadata_u64(
    connection: &turso::Connection,
    key: &str,
    value: u64,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "INSERT INTO catalog_metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            turso::params![key, value.to_string()],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn existing_projection(
    connection: &turso::Connection,
    namespace: NamespaceKey,
    attempt_id: &str,
) -> Result<Option<ExistingProjection>, CatalogError> {
    let mut rows = connection
        .query(
            "SELECT sequence, observation_id, payload_sha256
             FROM catalog_projection_inputs
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND attempt_id = ?3",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                attempt_id
            ],
        )
        .await
        .map_err(unavailable)?;
    let Some(row) = rows.next().await.map_err(unavailable)? else {
        return Ok(None);
    };
    Ok(Some(ExistingProjection {
        sequence: from_i64(row.get(0).map_err(unavailable)?)?,
        observation_id: row.get(1).map_err(unavailable)?,
        payload_sha256: row.get(2).map_err(unavailable)?,
    }))
}

async fn finish_transaction<T>(
    connection: &turso::Connection,
    result: Result<T, CatalogError>,
) -> Result<T, CatalogError> {
    match result {
        Ok(value) => {
            connection
                .execute_batch("COMMIT")
                .await
                .map_err(unavailable)?;
            Ok(value)
        }
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK").await;
            Err(error)
        }
    }
}

fn from_i64(value: i64) -> Result<u64, CatalogError> {
    u64::try_from(value).map_err(unavailable)
}

fn to_i64(value: u64) -> Result<i64, CatalogError> {
    i64::try_from(value).map_err(unavailable)
}

fn usize_to_i64(value: usize) -> Result<i64, CatalogError> {
    i64::try_from(value).map_err(unavailable)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn json<T: Serialize>(value: &T) -> Result<String, CatalogError> {
    serde_json::to_string(value).map_err(unavailable)
}

fn enum_text<T: Serialize>(value: &T) -> Result<String, CatalogError> {
    let encoded = json(value)?;
    Ok(encoded.trim_matches('"').to_owned())
}

fn optional_bool(value: Option<bool>) -> Option<i64> {
    value.map(|value| if value { 1 } else { 0 })
}

async fn persist_projection(
    connection: &turso::Connection,
    sequence: u64,
    input: &InventoryProjectionInputV1,
    payload_json: &str,
    payload_sha256: &str,
    preview: &ProjectionPreview,
) -> Result<(), CatalogError> {
    let namespace = NamespaceKey::from(input_namespace(input));
    let sequence_i64 = to_i64(sequence)?;
    connection
        .execute(
            "INSERT INTO catalog_projection_inputs (
                 namespace_kind, credential_profile_id, attempt_id, sequence,
                 observation_id, repository_id, completed_at, payload_sha256, payload_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                preview.outcome.attempt_id.as_str(),
                sequence_i64,
                preview.outcome.observation_id.as_deref(),
                input_repository_id(input),
                input.completed_at().to_rfc3339(),
                payload_sha256,
                payload_json
            ],
        )
        .await
        .map_err(unavailable)?;
    connection
        .execute(
            "INSERT INTO catalog_projection_outbox (
                 namespace_kind, credential_profile_id, sequence, attempt_id,
                 payload_sha256, enqueued_at, projected_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                sequence_i64,
                preview.outcome.attempt_id.as_str(),
                payload_sha256,
                Utc::now().to_rfc3339()
            ],
        )
        .await
        .map_err(unavailable)?;

    let repository_aliases = persist_repository(connection, &namespace, &preview.result).await?;
    if let Some(snapshot) = &preview.result.snapshot {
        persist_snapshot(connection, &namespace, snapshot).await?;
    }
    let mut attempt = preview.result.attempt.clone();
    attempt.projection_sequence = sequence;
    attempt.repository_aliases.extend(repository_aliases);
    persist_attempt(connection, &namespace, &attempt).await?;
    if let Some(observation) = &preview.result.observation {
        persist_observation(connection, &namespace, input, observation).await?;
    }
    sql_search::persist_search_document(
        connection,
        namespace.kind,
        namespace.credential_profile_id.as_str(),
        &attempt,
        preview.result.observation.as_ref(),
    )
    .await?;
    repair_latest(
        connection,
        &namespace,
        preview.result.repository.key.repository_id.as_str(),
    )
    .await?;
    connection
        .execute(
            "INSERT INTO catalog_projection_checkpoints (
                 namespace_kind, credential_profile_id, last_sequence, updated_at
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace_kind, credential_profile_id) DO UPDATE SET
                 last_sequence = excluded.last_sequence,
                 updated_at = excluded.updated_at",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                sequence_i64,
                Utc::now().to_rfc3339()
            ],
        )
        .await
        .map_err(unavailable)?;
    connection
        .execute(
            "UPDATE catalog_projection_outbox SET projected_at = ?4
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND sequence = ?3",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                sequence_i64,
                Utc::now().to_rfc3339()
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

fn assign_rebuild_sequences(
    previous_watermark: u64,
    projections: &mut [RebuildProjection],
) -> Result<u64, CatalogError> {
    if projections.is_empty() {
        return previous_watermark
            .checked_add(1)
            .ok_or(CatalogError::StoreUnavailable);
    }
    for (offset, projection) in projections.iter_mut().enumerate() {
        let sequence = previous_watermark
            .checked_add(u64::try_from(offset).map_err(unavailable)?)
            .and_then(|value| value.checked_add(1))
            .ok_or(CatalogError::StoreUnavailable)?;
        projection.sequence = sequence;
        projection.preview.result.attempt.projection_sequence = sequence;
    }
    Ok(projections
        .last()
        .ok_or(CatalogError::StoreUnavailable)?
        .sequence)
}

fn enrich_rebuild_repository_aliases(projections: &mut [RebuildProjection]) {
    let mut current_names = BTreeMap::<(NamespaceKey, String), String>::new();
    let mut aliases = BTreeMap::<(NamespaceKey, String), BTreeSet<String>>::new();
    for projection in projections {
        let namespace = NamespaceKey::from(input_namespace(&projection.input));
        let repository_id = projection
            .preview
            .result
            .repository
            .key
            .repository_id
            .clone();
        let normalized_name = projection
            .preview
            .result
            .repository
            .normalized_full_name
            .clone();
        let key = (namespace, repository_id);
        let known_aliases = aliases.entry(key.clone()).or_default();
        if let Some(previous) = current_names.get(&key)
            && previous != &normalized_name
        {
            known_aliases.insert(previous.clone());
        }
        known_aliases.extend(projection.preview.result.repository.aliases.iter().cloned());
        projection
            .preview
            .result
            .attempt
            .repository_aliases
            .extend(known_aliases.iter().cloned());
        current_names.insert(key, normalized_name);
    }
}

async fn persist_rebuild(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
) -> Result<(), CatalogError> {
    if projections.is_empty() {
        return Ok(());
    }
    let projected_at = Utc::now().to_rfc3339();
    persist_rebuild_inputs(connection, projections, &projected_at).await?;
    persist_rebuild_repositories(connection, projections).await?;
    persist_rebuild_snapshots(connection, projections).await?;
    persist_rebuild_attempts(connection, projections).await?;
    persist_rebuild_observations(connection, projections).await?;
    persist_rebuild_search(connection, projections).await?;
    persist_rebuild_latest(connection, projections).await?;
    persist_rebuild_checkpoints(connection, projections, &projected_at).await
}

async fn execute_bulk_insert(
    connection: &turso::Connection,
    prefix: &str,
    suffix: &str,
    column_count: usize,
    rows: Vec<Vec<turso::Value>>,
) -> Result<(), CatalogError> {
    if column_count == 0 || column_count > MAX_BULK_BINDINGS {
        return Err(CatalogError::StoreUnavailable);
    }
    if rows.is_empty() {
        return Ok(());
    }
    if rows.len() > MAX_BULK_BINDINGS / column_count
        || rows.iter().any(|row| row.len() != column_count)
    {
        return Err(CatalogError::StoreUnavailable);
    }
    let row_count = rows.len();
    let params = rows.into_iter().flatten().collect::<Vec<_>>();
    let statement = bulk_insert_statement(prefix, suffix, column_count, row_count);
    let mut statement = connection
        .prepare_cached(&statement)
        .await
        .map_err(unavailable)?;
    statement.execute(params).await.map_err(unavailable)?;
    Ok(())
}

async fn execute_projection_rows(
    connection: &turso::Connection,
    prefix: &str,
    suffix: &str,
    column_count: usize,
    projections: &[RebuildProjection],
    build_row: fn(&RebuildProjection) -> Result<Option<Vec<turso::Value>>, CatalogError>,
) -> Result<(), CatalogError> {
    let capacity = MAX_BULK_BINDINGS / column_count;
    let mut rows = Vec::with_capacity(capacity);
    for projection in projections {
        let Some(row) = build_row(projection)? else {
            continue;
        };
        rows.push(row);
        if rows.len() == capacity {
            execute_bulk_insert(
                connection,
                prefix,
                suffix,
                column_count,
                std::mem::take(&mut rows),
            )
            .await?;
            rows = Vec::with_capacity(capacity);
        }
    }
    execute_bulk_insert(connection, prefix, suffix, column_count, rows).await
}

async fn execute_projection_row_groups(
    connection: &turso::Connection,
    prefix: &str,
    suffix: &str,
    column_count: usize,
    projections: &[RebuildProjection],
    build_rows: fn(&RebuildProjection) -> Result<Vec<Vec<turso::Value>>, CatalogError>,
) -> Result<(), CatalogError> {
    let capacity = MAX_BULK_BINDINGS / column_count;
    let mut rows = Vec::with_capacity(capacity);
    for projection in projections {
        for row in build_rows(projection)? {
            rows.push(row);
            if rows.len() == capacity {
                execute_bulk_insert(
                    connection,
                    prefix,
                    suffix,
                    column_count,
                    std::mem::take(&mut rows),
                )
                .await?;
                rows = Vec::with_capacity(capacity);
            }
        }
    }
    execute_bulk_insert(connection, prefix, suffix, column_count, rows).await
}

fn bulk_insert_statement(
    prefix: &str,
    suffix: &str,
    column_count: usize,
    row_count: usize,
) -> String {
    let row = format!("({})", vec!["?"; column_count].join(","));
    format!(
        "{prefix} VALUES {rows}{suffix}",
        rows = (0..row_count)
            .map(|_| row.as_str())
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn text(value: impl Into<String>) -> turso::Value {
    turso::Value::Text(value.into())
}

fn optional_text(value: Option<String>) -> turso::Value {
    value.map_or(turso::Value::Null, turso::Value::Text)
}

fn integer(value: i64) -> turso::Value {
    turso::Value::Integer(value)
}

fn optional_integer(value: Option<i64>) -> turso::Value {
    value.map_or(turso::Value::Null, turso::Value::Integer)
}

fn optional_blob(value: Option<Vec<u8>>) -> turso::Value {
    value.map_or(turso::Value::Null, turso::Value::Blob)
}

async fn persist_rebuild_inputs(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
    projected_at: &str,
) -> Result<(), CatalogError> {
    execute_projection_rows(
        connection,
        "INSERT INTO catalog_projection_inputs (
             namespace_kind, credential_profile_id, attempt_id, sequence,
             observation_id, repository_id, completed_at, payload_sha256, payload_json
         )",
        "",
        9,
        projections,
        rebuild_input_row,
    )
    .await?;
    let capacity = MAX_BULK_BINDINGS / 7;
    let mut rows = Vec::with_capacity(capacity);
    for projection in projections {
        let namespace = NamespaceKey::from(input_namespace(&projection.input));
        rows.push(vec![
            text(namespace.kind),
            text(namespace.credential_profile_id),
            integer(to_i64(projection.sequence)?),
            text(projection.preview.outcome.attempt_id.clone()),
            text(projection.payload_sha256.clone()),
            text(projected_at),
            text(projected_at),
        ]);
        if rows.len() == capacity {
            execute_bulk_insert(
                connection,
                "INSERT INTO catalog_projection_outbox (
                     namespace_kind, credential_profile_id, sequence, attempt_id,
                     payload_sha256, enqueued_at, projected_at
                 )",
                "",
                7,
                std::mem::take(&mut rows),
            )
            .await?;
            rows = Vec::with_capacity(capacity);
        }
    }
    execute_bulk_insert(
        connection,
        "INSERT INTO catalog_projection_outbox (
             namespace_kind, credential_profile_id, sequence, attempt_id,
             payload_sha256, enqueued_at, projected_at
         )",
        "",
        7,
        rows,
    )
    .await
}

fn rebuild_input_row(
    projection: &RebuildProjection,
) -> Result<Option<Vec<turso::Value>>, CatalogError> {
    let namespace = NamespaceKey::from(input_namespace(&projection.input));
    Ok(Some(vec![
        text(namespace.kind),
        text(namespace.credential_profile_id),
        text(projection.preview.outcome.attempt_id.clone()),
        integer(to_i64(projection.sequence)?),
        optional_text(projection.preview.outcome.observation_id.clone()),
        text(input_repository_id(&projection.input)),
        text(projection.input.completed_at().to_rfc3339()),
        text(projection.payload_sha256.clone()),
        text(projection.payload_json.clone()),
    ]))
}

async fn persist_rebuild_repositories(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
) -> Result<(), CatalogError> {
    execute_projection_rows(
        connection,
        "INSERT INTO catalog_repositories (
             namespace_kind, credential_profile_id, repository_id, full_name,
             normalized_full_name, owner, normalized_owner, visibility,
             first_observed_at, last_observed_at, repository_json
         )",
        " ON CONFLICT(namespace_kind, credential_profile_id, repository_id) DO UPDATE SET
             full_name = CASE WHEN excluded.last_observed_at >= last_observed_at
                 THEN excluded.full_name ELSE full_name END,
             normalized_full_name = CASE WHEN excluded.last_observed_at >= last_observed_at
                 THEN excluded.normalized_full_name ELSE normalized_full_name END,
             owner = CASE WHEN excluded.last_observed_at >= last_observed_at
                 THEN excluded.owner ELSE owner END,
             normalized_owner = CASE WHEN excluded.last_observed_at >= last_observed_at
                 THEN excluded.normalized_owner ELSE normalized_owner END,
             visibility = CASE WHEN excluded.last_observed_at >= last_observed_at
                 THEN excluded.visibility ELSE visibility END,
             first_observed_at = MIN(first_observed_at, excluded.first_observed_at),
             last_observed_at = MAX(last_observed_at, excluded.last_observed_at),
             repository_json = CASE WHEN excluded.last_observed_at >= last_observed_at
                 THEN excluded.repository_json ELSE repository_json END",
        11,
        projections,
        rebuild_repository_row,
    )
    .await?;

    let mut current_names = BTreeMap::<(NamespaceKey, String), String>::new();
    let mut aliases = BTreeSet::<(NamespaceKey, String, String)>::new();
    for projection in projections {
        let namespace = NamespaceKey::from(input_namespace(&projection.input));
        let repository = &projection.preview.result.repository;
        let key = (namespace.clone(), repository.key.repository_id.clone());
        if let Some(previous) = current_names.get(&key)
            && previous != &repository.normalized_full_name
        {
            aliases.insert((
                namespace.clone(),
                repository.key.repository_id.clone(),
                previous.clone(),
            ));
        }
        for alias in &repository.aliases {
            aliases.insert((
                namespace.clone(),
                repository.key.repository_id.clone(),
                alias.clone(),
            ));
        }
        current_names.insert(key, repository.normalized_full_name.clone());
    }
    let capacity = MAX_BULK_BINDINGS / 4;
    let mut rows = Vec::with_capacity(capacity);
    for (namespace, repository_id, alias) in aliases {
        rows.push(vec![
            text(namespace.kind),
            text(namespace.credential_profile_id),
            text(repository_id),
            text(alias),
        ]);
        if rows.len() == capacity {
            execute_bulk_insert(
                connection,
                "INSERT OR IGNORE INTO catalog_repository_aliases (
                     namespace_kind, credential_profile_id, repository_id, normalized_alias
                 )",
                "",
                4,
                std::mem::take(&mut rows),
            )
            .await?;
            rows = Vec::with_capacity(capacity);
        }
    }
    execute_bulk_insert(
        connection,
        "INSERT OR IGNORE INTO catalog_repository_aliases (
             namespace_kind, credential_profile_id, repository_id, normalized_alias
         )",
        "",
        4,
        rows,
    )
    .await
}

fn rebuild_repository_row(
    projection: &RebuildProjection,
) -> Result<Option<Vec<turso::Value>>, CatalogError> {
    let namespace = NamespaceKey::from(input_namespace(&projection.input));
    let repository = &projection.preview.result.repository;
    Ok(Some(vec![
        text(namespace.kind),
        text(namespace.credential_profile_id),
        text(repository.key.repository_id.clone()),
        text(repository.full_name.clone()),
        text(repository.normalized_full_name.clone()),
        text(repository.owner.clone()),
        text(repository.normalized_owner.clone()),
        text(enum_text(&repository.visibility)?),
        text(repository.first_observed_at.to_rfc3339()),
        text(repository.last_observed_at.to_rfc3339()),
        text(json(repository)?),
    ]))
}

async fn persist_rebuild_snapshots(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
) -> Result<(), CatalogError> {
    execute_projection_rows(
        connection,
        "INSERT INTO catalog_snapshots (
             namespace_kind, credential_profile_id, repository_id, commit_sha,
             tree_sha, analyzer_profile_digest, head_committed_at,
             first_observed_at, last_observed_at, snapshot_json
         )",
        " ON CONFLICT(
             namespace_kind, credential_profile_id, repository_id,
             commit_sha, tree_sha, analyzer_profile_digest
         ) DO UPDATE SET
             head_committed_at = COALESCE(head_committed_at, excluded.head_committed_at),
             first_observed_at = MIN(first_observed_at, excluded.first_observed_at),
             last_observed_at = MAX(last_observed_at, excluded.last_observed_at)",
        10,
        projections,
        rebuild_snapshot_row,
    )
    .await
}

fn rebuild_snapshot_row(
    projection: &RebuildProjection,
) -> Result<Option<Vec<turso::Value>>, CatalogError> {
    let Some(snapshot) = projection.preview.result.snapshot.as_ref() else {
        return Ok(None);
    };
    let namespace = NamespaceKey::from(input_namespace(&projection.input));
    Ok(Some(vec![
        text(namespace.kind),
        text(namespace.credential_profile_id),
        text(snapshot.key.repository.repository_id.clone()),
        text(snapshot.key.revision.commit_sha.clone()),
        text(snapshot.key.revision.tree_sha.clone()),
        text(snapshot.key.revision.analyzer_profile_digest.clone()),
        optional_text(
            snapshot
                .head_committed_at
                .as_ref()
                .map(DateTime::to_rfc3339),
        ),
        text(snapshot.first_observed_at.to_rfc3339()),
        text(snapshot.last_observed_at.to_rfc3339()),
        text(json(snapshot)?),
    ]))
}

async fn persist_rebuild_attempts(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
) -> Result<(), CatalogError> {
    execute_projection_rows(
        connection,
        "INSERT INTO catalog_attempts (
             namespace_kind, credential_profile_id, attempt_id, projection_digest,
             projection_sequence, repository_id, normalized_repository_name,
             normalized_repository_owner, repository_visibility, job_id, task_id,
             task_attempt, completed_at, status, failure_code, failure_message,
             observation_id, snapshot_commit_sha, snapshot_tree_sha,
             snapshot_analyzer_profile_digest, attempt_json
         )",
        "",
        21,
        projections,
        rebuild_attempt_row,
    )
    .await
}

fn rebuild_attempt_row(
    projection: &RebuildProjection,
) -> Result<Option<Vec<turso::Value>>, CatalogError> {
    let namespace = NamespaceKey::from(input_namespace(&projection.input));
    let attempt = &projection.preview.result.attempt;
    let (commit_sha, tree_sha, analyzer_digest) = attempt
        .snapshot
        .as_ref()
        .map(|snapshot| {
            (
                Some(snapshot.revision.commit_sha.clone()),
                Some(snapshot.revision.tree_sha.clone()),
                Some(snapshot.revision.analyzer_profile_digest.clone()),
            )
        })
        .unwrap_or_default();
    Ok(Some(vec![
        text(namespace.kind),
        text(namespace.credential_profile_id),
        text(attempt.attempt_id.clone()),
        text(attempt.projection_digest.clone()),
        integer(to_i64(attempt.projection_sequence)?),
        text(attempt.repository.repository_id.clone()),
        text(attempt.normalized_repository_name.clone()),
        text(attempt.normalized_repository_owner.clone()),
        text(enum_text(&attempt.repository_visibility)?),
        text(attempt.job_id.0.clone()),
        text(attempt.task_id.0.clone()),
        integer(i64::from(attempt.task_attempt)),
        text(attempt.completed_at.to_rfc3339()),
        text(enum_text(&attempt.status)?),
        optional_text(attempt.failure_code.clone()),
        optional_text(attempt.failure_message.clone()),
        optional_text(attempt.observation_id.clone()),
        optional_text(commit_sha),
        optional_text(tree_sha),
        optional_text(analyzer_digest),
        text(json(attempt)?),
    ]))
}

async fn persist_rebuild_observations(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
) -> Result<(), CatalogError> {
    execute_projection_rows(
        connection,
        "INSERT INTO catalog_observations (
             namespace_kind, credential_profile_id, observation_id, attempt_id,
             repository_id, target_name, normalized_target_name, target_version,
             target_source, recorded_relation, exact_resolution_count, msrv,
             msrv_sort_key, strength, completeness, globally_exhaustive,
             package_inventory_complete, observed_at, observation_json
         )",
        "",
        19,
        projections,
        rebuild_observation_row,
    )
    .await?;
    execute_projection_row_groups(
        connection,
        "INSERT INTO catalog_requirements (
             namespace_kind, credential_profile_id, observation_id, ordinal,
             source, manifest_path, package_name, requirement,
             accepts_target, explicit_exact_pin, requirement_json
         )",
        "",
        11,
        projections,
        rebuild_requirement_rows,
    )
    .await?;
    execute_projection_row_groups(
        connection,
        "INSERT INTO catalog_packages (
             namespace_kind, credential_profile_id, observation_id, ordinal,
             repository_id, package_name, normalized_package_name,
             package_version, package_source, license_expression,
             inventory_complete, package_json
         )",
        "",
        12,
        projections,
        rebuild_package_rows,
    )
    .await?;
    execute_projection_row_groups(
        connection,
        "INSERT INTO catalog_limitations (
             namespace_kind, credential_profile_id, observation_id, ordinal,
             code, message, limitation_json
         )",
        "",
        7,
        projections,
        rebuild_limitation_rows,
    )
    .await
}

fn rebuild_observation_row(
    projection: &RebuildProjection,
) -> Result<Option<Vec<turso::Value>>, CatalogError> {
    let Some(observation) = projection.preview.result.observation.as_ref() else {
        return Ok(None);
    };
    let namespace = NamespaceKey::from(input_namespace(&projection.input));
    Ok(Some(vec![
        text(namespace.kind),
        text(namespace.credential_profile_id),
        text(observation.observation_id.clone()),
        text(observation.attempt_id.clone()),
        text(observation.snapshot.repository.repository_id.clone()),
        text(observation.target.name.clone()),
        text(sql_search::normalize_text(&observation.target.name)),
        text(observation.target.version.to_string()),
        optional_text(observation.target.source.clone()),
        text(enum_text(&observation.recorded_relation)?),
        integer(usize_to_i64(observation.exact_resolution_count)?),
        optional_text(observation.msrv.as_ref().map(ToString::to_string)),
        optional_blob(observation.msrv.as_ref().map(sql_search::semver_sort_key)),
        text(enum_text(&observation.strength)?),
        text(enum_text(&observation.completeness)?),
        integer(if observation.globally_exhaustive {
            1
        } else {
            0
        }),
        integer(if observation.package_inventory_complete {
            1
        } else {
            0
        }),
        text(observation.observed_at.to_rfc3339()),
        text(json(observation)?),
    ]))
}

fn rebuild_requirement_rows(
    projection: &RebuildProjection,
) -> Result<Vec<Vec<turso::Value>>, CatalogError> {
    let Some(observation) = &projection.preview.result.observation else {
        return Ok(Vec::new());
    };
    let namespace = NamespaceKey::from(input_namespace(&projection.input));
    observation
        .requirements
        .iter()
        .enumerate()
        .map(|(ordinal, requirement)| {
            Ok(vec![
                text(namespace.kind),
                text(namespace.credential_profile_id.clone()),
                text(observation.observation_id.clone()),
                integer(usize_to_i64(ordinal)?),
                text(enum_text(&requirement.source)?),
                text(requirement.manifest_path.clone()),
                optional_text(requirement.package_name.clone()),
                optional_text(requirement.requirement.clone()),
                optional_integer(optional_bool(requirement.accepts_target)),
                optional_integer(optional_bool(requirement.explicit_exact_pin)),
                text(json(requirement)?),
            ])
        })
        .collect()
}

fn rebuild_package_rows(
    projection: &RebuildProjection,
) -> Result<Vec<Vec<turso::Value>>, CatalogError> {
    let Some(observation) = &projection.preview.result.observation else {
        return Ok(Vec::new());
    };
    let InventoryProjectionInputV1::Observation(envelope) = &projection.input else {
        return Err(CatalogError::StoreUnavailable);
    };
    let repository_evidence = envelope
        .evidence
        .repositories
        .first()
        .ok_or(CatalogError::StoreUnavailable)?;
    let namespace = NamespaceKey::from(&envelope.namespace);
    repository_evidence
        .packages
        .iter()
        .enumerate()
        .map(|(ordinal, package)| {
            Ok(vec![
                text(namespace.kind),
                text(namespace.credential_profile_id.clone()),
                text(observation.observation_id.clone()),
                integer(usize_to_i64(ordinal)?),
                text(observation.snapshot.repository.repository_id.clone()),
                text(package.package.name.clone()),
                text(sql_search::normalize_text(&package.package.name)),
                text(package.package.version.to_string()),
                optional_text(package.package.source.clone()),
                optional_text(package.license_expression.clone()),
                integer(if observation.package_inventory_complete {
                    1
                } else {
                    0
                }),
                text(package_presence_json(observation, package)?),
            ])
        })
        .collect()
}

fn rebuild_limitation_rows(
    projection: &RebuildProjection,
) -> Result<Vec<Vec<turso::Value>>, CatalogError> {
    let Some(observation) = &projection.preview.result.observation else {
        return Ok(Vec::new());
    };
    let namespace = NamespaceKey::from(input_namespace(&projection.input));
    observation
        .limitations
        .iter()
        .enumerate()
        .map(|(ordinal, limitation)| {
            Ok(vec![
                text(namespace.kind),
                text(namespace.credential_profile_id.clone()),
                text(observation.observation_id.clone()),
                integer(usize_to_i64(ordinal)?),
                text(limitation.code.clone()),
                text(limitation.message.clone()),
                text(json(limitation)?),
            ])
        })
        .collect()
}

fn package_presence_json(
    observation: &super::model::TargetObservationV1,
    package: &crate::evidence::PackageEvidenceV1,
) -> Result<String, CatalogError> {
    json(&PackagePresenceV1 {
        observation_id: observation.observation_id.clone(),
        snapshot: observation.snapshot.clone(),
        package: package.package.clone(),
        license_expression: package.license_expression.clone(),
        inventory_complete: observation.package_inventory_complete,
    })
}

async fn persist_rebuild_search(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
) -> Result<(), CatalogError> {
    let mut documents = Vec::with_capacity(sql_search::REBUILD_SEARCH_DOCUMENT_BATCH_SIZE);
    let mut estimated_working_set = 0_usize;
    for projection in projections {
        let namespace = NamespaceKey::from(input_namespace(&projection.input));
        let package_names = match &projection.input {
            InventoryProjectionInputV1::Observation(envelope) => envelope
                .evidence
                .repositories
                .first()
                .ok_or(CatalogError::StoreUnavailable)?
                .packages
                .iter()
                .map(|package| package.package.name.as_str())
                .collect(),
            InventoryProjectionInputV1::FailedAttempt(_) => Vec::new(),
        };
        let document = sql_search::RebuildSearchDocument::new(
            namespace.kind,
            &namespace.credential_profile_id,
            &projection.preview.result.attempt,
            projection.preview.result.observation.as_ref(),
            package_names,
        );
        let document_working_set = document.estimated_working_set_bytes();
        if sql_search::rebuild_search_batch_should_flush(
            documents.len(),
            estimated_working_set,
            document_working_set,
        ) {
            sql_search::persist_rebuild_search_documents(
                connection,
                std::mem::take(&mut documents),
            )
            .await?;
            estimated_working_set = 0;
        }
        estimated_working_set = estimated_working_set.saturating_add(document_working_set);
        documents.push(document);
    }
    sql_search::persist_rebuild_search_documents(connection, documents).await
}

impl LatestPointers {
    fn consider(&mut self, candidate: usize, projections: &[RebuildProjection]) {
        update_latest_pointer(&mut self.attempt, candidate, projections);
        let observation = projections[candidate].preview.result.observation.as_ref();
        if observation.is_some() {
            update_latest_pointer(&mut self.evidence, candidate, projections);
        }
        if observation.is_some_and(|observation| {
            observation.completeness == crate::evidence::EvidenceCompletenessV1::Complete
        }) {
            update_latest_pointer(&mut self.complete_evidence, candidate, projections);
        }
    }
}

fn update_latest_pointer(
    current: &mut Option<usize>,
    candidate: usize,
    projections: &[RebuildProjection],
) {
    let replace = current.is_none_or(|current| {
        attempt_order(
            &projections[candidate].preview.result.attempt,
            &projections[current].preview.result.attempt,
        )
        .is_gt()
    });
    if replace {
        *current = Some(candidate);
    }
}

fn attempt_order(
    left: &super::model::RepositoryAttemptV1,
    right: &super::model::RepositoryAttemptV1,
) -> std::cmp::Ordering {
    left.completed_at
        .cmp(&right.completed_at)
        .then_with(|| left.task_id.cmp(&right.task_id))
        .then_with(|| left.task_attempt.cmp(&right.task_attempt))
        .then_with(|| left.attempt_id.cmp(&right.attempt_id))
}

async fn persist_rebuild_latest(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
) -> Result<(), CatalogError> {
    let mut latest = BTreeMap::<(NamespaceKey, String), LatestPointers>::new();
    for (index, projection) in projections.iter().enumerate() {
        latest
            .entry((
                NamespaceKey::from(input_namespace(&projection.input)),
                projection
                    .preview
                    .result
                    .repository
                    .key
                    .repository_id
                    .clone(),
            ))
            .or_default()
            .consider(index, projections);
    }
    let capacity = MAX_BULK_BINDINGS / 6;
    let mut rows = Vec::with_capacity(capacity);
    for ((namespace, repository_id), pointers) in latest {
        let attempt = &projections[pointers.attempt.ok_or(CatalogError::StoreUnavailable)?]
            .preview
            .result
            .attempt;
        let evidence = pointers.evidence.and_then(|index| {
            projections[index]
                .preview
                .result
                .observation
                .as_ref()
                .map(|observation| observation.observation_id.clone())
        });
        let complete_evidence = pointers.complete_evidence.and_then(|index| {
            projections[index]
                .preview
                .result
                .observation
                .as_ref()
                .map(|observation| observation.observation_id.clone())
        });
        rows.push(vec![
            text(namespace.kind),
            text(namespace.credential_profile_id),
            text(repository_id),
            text(attempt.attempt_id.clone()),
            optional_text(evidence),
            optional_text(complete_evidence),
        ]);
        if rows.len() == capacity {
            execute_bulk_insert(
                connection,
                "INSERT INTO catalog_latest (
                     namespace_kind, credential_profile_id, repository_id,
                     latest_attempt_id, latest_evidence_id, latest_complete_evidence_id
                 )",
                "",
                6,
                std::mem::take(&mut rows),
            )
            .await?;
            rows = Vec::with_capacity(capacity);
        }
    }
    execute_bulk_insert(
        connection,
        "INSERT INTO catalog_latest (
             namespace_kind, credential_profile_id, repository_id,
             latest_attempt_id, latest_evidence_id, latest_complete_evidence_id
         )",
        "",
        6,
        rows,
    )
    .await
}

async fn persist_rebuild_checkpoints(
    connection: &turso::Connection,
    projections: &[RebuildProjection],
    updated_at: &str,
) -> Result<(), CatalogError> {
    let mut checkpoints = BTreeMap::<NamespaceKey, u64>::new();
    for projection in projections {
        checkpoints
            .entry(NamespaceKey::from(input_namespace(&projection.input)))
            .and_modify(|sequence| *sequence = (*sequence).max(projection.sequence))
            .or_insert(projection.sequence);
    }
    let capacity = MAX_BULK_BINDINGS / 4;
    let mut rows = Vec::with_capacity(capacity);
    for (namespace, sequence) in checkpoints {
        rows.push(vec![
            text(namespace.kind),
            text(namespace.credential_profile_id),
            integer(to_i64(sequence)?),
            text(updated_at),
        ]);
        if rows.len() == capacity {
            execute_bulk_insert(
                connection,
                "INSERT INTO catalog_projection_checkpoints (
                     namespace_kind, credential_profile_id, last_sequence, updated_at
                 )",
                "",
                4,
                std::mem::take(&mut rows),
            )
            .await?;
            rows = Vec::with_capacity(capacity);
        }
    }
    execute_bulk_insert(
        connection,
        "INSERT INTO catalog_projection_checkpoints (
             namespace_kind, credential_profile_id, last_sequence, updated_at
         )",
        "",
        4,
        rows,
    )
    .await
}

async fn persist_repository(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    result: &InventorySearchResultV1,
) -> Result<BTreeSet<String>, CatalogError> {
    let repository = &result.repository;
    let mut rows = connection
        .query(
            "SELECT normalized_full_name FROM catalog_repositories
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository.key.repository_id.as_str()
            ],
        )
        .await
        .map_err(unavailable)?;
    if let Some(row) = rows.next().await.map_err(unavailable)? {
        let prior_name: String = row.get(0).map_err(unavailable)?;
        if prior_name != repository.normalized_full_name {
            insert_alias(
                connection,
                namespace,
                repository.key.repository_id.as_str(),
                &prior_name,
            )
            .await?;
        }
    }
    for alias in &repository.aliases {
        insert_alias(
            connection,
            namespace,
            repository.key.repository_id.as_str(),
            alias,
        )
        .await?;
    }

    connection
        .execute(
            "INSERT INTO catalog_repositories (
                 namespace_kind, credential_profile_id, repository_id, full_name,
                 normalized_full_name, owner, normalized_owner, visibility,
                 first_observed_at, last_observed_at, repository_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(namespace_kind, credential_profile_id, repository_id) DO UPDATE SET
                 full_name = CASE WHEN excluded.last_observed_at >= last_observed_at
                     THEN excluded.full_name ELSE full_name END,
                 normalized_full_name = CASE WHEN excluded.last_observed_at >= last_observed_at
                     THEN excluded.normalized_full_name ELSE normalized_full_name END,
                 owner = CASE WHEN excluded.last_observed_at >= last_observed_at
                     THEN excluded.owner ELSE owner END,
                 normalized_owner = CASE WHEN excluded.last_observed_at >= last_observed_at
                     THEN excluded.normalized_owner ELSE normalized_owner END,
                 visibility = CASE WHEN excluded.last_observed_at >= last_observed_at
                     THEN excluded.visibility ELSE visibility END,
                 first_observed_at = MIN(first_observed_at, excluded.first_observed_at),
                 last_observed_at = MAX(last_observed_at, excluded.last_observed_at),
                 repository_json = CASE WHEN excluded.last_observed_at >= last_observed_at
                     THEN excluded.repository_json ELSE repository_json END",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository.key.repository_id.as_str(),
                repository.full_name.as_str(),
                repository.normalized_full_name.as_str(),
                repository.owner.as_str(),
                repository.normalized_owner.as_str(),
                enum_text(&repository.visibility)?,
                repository.first_observed_at.to_rfc3339(),
                repository.last_observed_at.to_rfc3339(),
                json(repository)?
            ],
        )
        .await
        .map_err(unavailable)?;
    repository_aliases(connection, namespace, repository.key.repository_id.as_str()).await
}

async fn insert_alias(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    repository_id: &str,
    alias: &str,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "INSERT OR IGNORE INTO catalog_repository_aliases (
                 namespace_kind, credential_profile_id, repository_id, normalized_alias
             ) VALUES (?1, ?2, ?3, ?4)",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository_id,
                alias
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn repository_aliases(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    repository_id: &str,
) -> Result<BTreeSet<String>, CatalogError> {
    let mut rows = connection
        .query(
            "SELECT normalized_alias FROM catalog_repository_aliases
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3
             ORDER BY normalized_alias",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository_id
            ],
        )
        .await
        .map_err(unavailable)?;
    let mut aliases = BTreeSet::new();
    while let Some(row) = rows.next().await.map_err(unavailable)? {
        aliases.insert(row.get(0).map_err(unavailable)?);
    }
    Ok(aliases)
}

async fn persist_snapshot(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    snapshot: &super::model::RepositorySnapshotV1,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "INSERT INTO catalog_snapshots (
                 namespace_kind, credential_profile_id, repository_id, commit_sha,
                 tree_sha, analyzer_profile_digest, head_committed_at,
                 first_observed_at, last_observed_at, snapshot_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(
                 namespace_kind, credential_profile_id, repository_id,
                 commit_sha, tree_sha, analyzer_profile_digest
             ) DO UPDATE SET
                 head_committed_at = COALESCE(head_committed_at, excluded.head_committed_at),
                 first_observed_at = MIN(first_observed_at, excluded.first_observed_at),
                 last_observed_at = MAX(last_observed_at, excluded.last_observed_at)",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                snapshot.key.repository.repository_id.as_str(),
                snapshot.key.revision.commit_sha.as_str(),
                snapshot.key.revision.tree_sha.as_str(),
                snapshot.key.revision.analyzer_profile_digest.as_str(),
                snapshot
                    .head_committed_at
                    .as_ref()
                    .map(|value| value.to_rfc3339()),
                snapshot.first_observed_at.to_rfc3339(),
                snapshot.last_observed_at.to_rfc3339(),
                json(snapshot)?
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn persist_attempt(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    attempt: &super::model::RepositoryAttemptV1,
) -> Result<(), CatalogError> {
    let (commit_sha, tree_sha, analyzer_digest) = attempt
        .snapshot
        .as_ref()
        .map(|snapshot| {
            (
                Some(snapshot.revision.commit_sha.clone()),
                Some(snapshot.revision.tree_sha.clone()),
                Some(snapshot.revision.analyzer_profile_digest.clone()),
            )
        })
        .unwrap_or_default();
    connection
        .execute(
            "INSERT INTO catalog_attempts (
                 namespace_kind, credential_profile_id, attempt_id, projection_digest,
                 projection_sequence, repository_id, normalized_repository_name,
                 normalized_repository_owner, repository_visibility, job_id, task_id, task_attempt,
                 completed_at, status, failure_code, failure_message, observation_id,
                 snapshot_commit_sha, snapshot_tree_sha, snapshot_analyzer_profile_digest,
                 attempt_json
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                 ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                 ?19, ?20, ?21
             )",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                attempt.attempt_id.as_str(),
                attempt.projection_digest.as_str(),
                to_i64(attempt.projection_sequence)?,
                attempt.repository.repository_id.as_str(),
                attempt.normalized_repository_name.as_str(),
                attempt.normalized_repository_owner.as_str(),
                enum_text(&attempt.repository_visibility)?,
                attempt.job_id.0.as_str(),
                attempt.task_id.0.as_str(),
                i64::from(attempt.task_attempt),
                attempt.completed_at.to_rfc3339(),
                enum_text(&attempt.status)?,
                attempt.failure_code.as_deref(),
                attempt.failure_message.as_deref(),
                attempt.observation_id.as_deref(),
                commit_sha,
                tree_sha,
                analyzer_digest,
                json(attempt)?
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn persist_observation(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    input: &InventoryProjectionInputV1,
    observation: &super::model::TargetObservationV1,
) -> Result<(), CatalogError> {
    let InventoryProjectionInputV1::Observation(envelope) = input else {
        return Err(CatalogError::StoreUnavailable);
    };
    let repository_evidence = envelope
        .evidence
        .repositories
        .first()
        .ok_or(CatalogError::StoreUnavailable)?;
    connection
        .execute(
            "INSERT INTO catalog_observations (
                 namespace_kind, credential_profile_id, observation_id, attempt_id,
                 repository_id, target_name, normalized_target_name, target_version, target_source,
                 recorded_relation, exact_resolution_count, msrv, msrv_sort_key, strength, completeness,
                 globally_exhaustive, package_inventory_complete, observed_at, observation_json
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                 ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
             )",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                observation.observation_id.as_str(),
                observation.attempt_id.as_str(),
                observation.snapshot.repository.repository_id.as_str(),
                observation.target.name.as_str(),
                sql_search::normalize_text(&observation.target.name),
                observation.target.version.to_string(),
                observation.target.source.as_deref(),
                enum_text(&observation.recorded_relation)?,
                usize_to_i64(observation.exact_resolution_count)?,
                observation.msrv.as_ref().map(ToString::to_string),
                observation.msrv.as_ref().map(sql_search::semver_sort_key),
                enum_text(&observation.strength)?,
                enum_text(&observation.completeness)?,
                if observation.globally_exhaustive {
                    1_i64
                } else {
                    0
                },
                if observation.package_inventory_complete {
                    1_i64
                } else {
                    0
                },
                observation.observed_at.to_rfc3339(),
                json(observation)?
            ],
        )
        .await
        .map_err(unavailable)?;

    for (ordinal, requirement) in observation.requirements.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO catalog_requirements (
                     namespace_kind, credential_profile_id, observation_id, ordinal,
                     source, manifest_path, package_name, requirement,
                     accepts_target, explicit_exact_pin, requirement_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                turso::params![
                    namespace.kind,
                    namespace.credential_profile_id.as_str(),
                    observation.observation_id.as_str(),
                    usize_to_i64(ordinal)?,
                    enum_text(&requirement.source)?,
                    requirement.manifest_path.as_str(),
                    requirement.package_name.as_deref(),
                    requirement.requirement.as_deref(),
                    optional_bool(requirement.accepts_target),
                    optional_bool(requirement.explicit_exact_pin),
                    json(requirement)?
                ],
            )
            .await
            .map_err(unavailable)?;
    }

    for (ordinal, package) in repository_evidence.packages.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO catalog_packages (
                     namespace_kind, credential_profile_id, observation_id, ordinal,
                     repository_id, package_name, normalized_package_name,
                     package_version, package_source,
                     license_expression, inventory_complete, package_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                turso::params![
                    namespace.kind,
                    namespace.credential_profile_id.as_str(),
                    observation.observation_id.as_str(),
                    usize_to_i64(ordinal)?,
                    observation.snapshot.repository.repository_id.as_str(),
                    package.package.name.as_str(),
                    sql_search::normalize_text(&package.package.name),
                    package.package.version.to_string(),
                    package.package.source.as_deref(),
                    package.license_expression.as_deref(),
                    if observation.package_inventory_complete {
                        1_i64
                    } else {
                        0
                    },
                    package_presence_json(observation, package)?
                ],
            )
            .await
            .map_err(unavailable)?;
    }

    for (ordinal, limitation) in observation.limitations.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO catalog_limitations (
                     namespace_kind, credential_profile_id, observation_id, ordinal,
                     code, message, limitation_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                turso::params![
                    namespace.kind,
                    namespace.credential_profile_id.as_str(),
                    observation.observation_id.as_str(),
                    usize_to_i64(ordinal)?,
                    limitation.code.as_str(),
                    limitation.message.as_str(),
                    json(limitation)?
                ],
            )
            .await
            .map_err(unavailable)?;
    }
    Ok(())
}

async fn repair_latest(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    repository_id: &str,
) -> Result<(), CatalogError> {
    let latest_attempt = select_latest_value(
        connection,
        "SELECT attempt_id FROM catalog_attempts
         WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3
         ORDER BY completed_at DESC, task_id DESC, task_attempt DESC, attempt_id DESC LIMIT 1",
        namespace,
        repository_id,
    )
    .await?;
    let Some(latest_attempt) = latest_attempt else {
        connection
            .execute(
                "DELETE FROM catalog_latest
                 WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3",
                turso::params![
                    namespace.kind,
                    namespace.credential_profile_id.as_str(),
                    repository_id
                ],
            )
            .await
            .map_err(unavailable)?;
        return Ok(());
    };
    let latest_evidence = select_latest_value(
        connection,
        "SELECT observation_id FROM catalog_attempts
         WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3
           AND observation_id IS NOT NULL
         ORDER BY completed_at DESC, task_id DESC, task_attempt DESC, attempt_id DESC LIMIT 1",
        namespace,
        repository_id,
    )
    .await?;
    let complete = enum_text(&crate::evidence::EvidenceCompletenessV1::Complete)?;
    let mut rows = connection
        .query(
            "SELECT attempts.observation_id
             FROM catalog_attempts AS attempts
             JOIN catalog_observations AS observations
               ON observations.namespace_kind = attempts.namespace_kind
              AND observations.credential_profile_id = attempts.credential_profile_id
              AND observations.observation_id = attempts.observation_id
             WHERE attempts.namespace_kind = ?1
               AND attempts.credential_profile_id = ?2
               AND attempts.repository_id = ?3
               AND observations.completeness = ?4
             ORDER BY attempts.completed_at DESC, attempts.task_id DESC,
                      attempts.task_attempt DESC, attempts.attempt_id DESC LIMIT 1",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository_id,
                complete
            ],
        )
        .await
        .map_err(unavailable)?;
    let latest_complete: Option<String> = match rows.next().await.map_err(unavailable)? {
        Some(row) => row.get(0).map_err(unavailable)?,
        None => None,
    };
    connection
        .execute(
            "INSERT INTO catalog_latest (
                 namespace_kind, credential_profile_id, repository_id,
                 latest_attempt_id, latest_evidence_id, latest_complete_evidence_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(namespace_kind, credential_profile_id, repository_id) DO UPDATE SET
                 latest_attempt_id = excluded.latest_attempt_id,
                 latest_evidence_id = excluded.latest_evidence_id,
                 latest_complete_evidence_id = excluded.latest_complete_evidence_id",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository_id,
                latest_attempt,
                latest_evidence,
                latest_complete
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn select_latest_value(
    connection: &turso::Connection,
    sql: &str,
    namespace: &NamespaceKey,
    repository_id: &str,
) -> Result<Option<String>, CatalogError> {
    let mut rows = connection
        .query(
            sql,
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository_id
            ],
        )
        .await
        .map_err(unavailable)?;
    match rows.next().await.map_err(unavailable)? {
        Some(row) => row.get(0).map_err(unavailable),
        None => Ok(None),
    }
}

async fn clear_projection(connection: &turso::Connection) -> Result<(), CatalogError> {
    connection
        .execute_batch(
            "DELETE FROM catalog_search_trigrams;
             DELETE FROM catalog_search_terms;
             DELETE FROM catalog_search_documents;
             DELETE FROM catalog_limitations;
             DELETE FROM catalog_packages;
             DELETE FROM catalog_requirements;
             DELETE FROM catalog_observations;
             DELETE FROM catalog_latest;
             DELETE FROM catalog_attempts;
             DELETE FROM catalog_snapshots;
             DELETE FROM catalog_repository_aliases;
             DELETE FROM catalog_repositories;
             DELETE FROM catalog_projection_outbox;
             DELETE FROM catalog_projection_inputs;
             DELETE FROM catalog_projection_checkpoints;",
        )
        .await
        .map_err(unavailable)
}

async fn expired_attempts(
    connection: &turso::Connection,
    cutoff: DateTime<Utc>,
) -> Result<Vec<ExpiredAttempt>, CatalogError> {
    let mut rows = connection
        .query(
            "SELECT namespace_kind, credential_profile_id, attempt_id,
                    observation_id, repository_id
             FROM catalog_projection_inputs
             WHERE completed_at < ?1
             ORDER BY namespace_kind, credential_profile_id, attempt_id",
            turso::params![cutoff.to_rfc3339()],
        )
        .await
        .map_err(unavailable)?;
    let mut attempts = Vec::new();
    while let Some(row) = rows.next().await.map_err(unavailable)? {
        let kind: String = row.get(0).map_err(unavailable)?;
        attempts.push(ExpiredAttempt {
            namespace: NamespaceKey {
                kind: match kind.as_str() {
                    "public" => "public",
                    "private" => "private",
                    _ => return Err(CatalogError::StoreUnavailable),
                },
                credential_profile_id: row.get(1).map_err(unavailable)?,
            },
            attempt_id: row.get(2).map_err(unavailable)?,
            observation_id: row.get(3).map_err(unavailable)?,
            repository_id: row.get(4).map_err(unavailable)?,
        });
    }
    Ok(attempts)
}

async fn artifact_attempts(
    connection: &turso::Connection,
    task_id: &crate::coordinator::TaskId,
    artifact_digest: &crate::coordinator::Sha256Digest,
) -> Result<Vec<ExpiredAttempt>, CatalogError> {
    let mut rows = connection
        .query(
            "SELECT inputs.namespace_kind, inputs.credential_profile_id,
                    inputs.attempt_id, inputs.observation_id,
                    inputs.repository_id, inputs.payload_json
             FROM catalog_attempts AS attempts
             JOIN catalog_projection_inputs AS inputs
               ON inputs.namespace_kind = attempts.namespace_kind
              AND inputs.credential_profile_id = attempts.credential_profile_id
              AND inputs.attempt_id = attempts.attempt_id
             WHERE attempts.task_id = ?1
             ORDER BY inputs.namespace_kind, inputs.credential_profile_id,
                      inputs.attempt_id",
            turso::params![task_id.0.as_str()],
        )
        .await
        .map_err(unavailable)?;
    let mut attempts = Vec::new();
    while let Some(row) = rows.next().await.map_err(unavailable)? {
        let kind: String = row.get(0).map_err(unavailable)?;
        let payload: String = row.get(5).map_err(unavailable)?;
        let input: InventoryProjectionInputV1 =
            serde_json::from_str(&payload).map_err(unavailable)?;
        match input {
            InventoryProjectionInputV1::Observation(envelope)
                if envelope.task_id == *task_id && envelope.artifact.digest == *artifact_digest => {
            }
            InventoryProjectionInputV1::Observation(_) => {
                return Err(CatalogError::InvalidEvidence(
                    "artifact digest does not match its searchable projection".to_owned(),
                ));
            }
            InventoryProjectionInputV1::FailedAttempt(_) => {
                return Err(CatalogError::InvalidEvidence(
                    "artifact task is bound to a non-artifact projection".to_owned(),
                ));
            }
        }
        attempts.push(ExpiredAttempt {
            namespace: NamespaceKey {
                kind: match kind.as_str() {
                    "public" => "public",
                    "private" => "private",
                    _ => return Err(CatalogError::StoreUnavailable),
                },
                credential_profile_id: row.get(1).map_err(unavailable)?,
            },
            attempt_id: row.get(2).map_err(unavailable)?,
            observation_id: row.get(3).map_err(unavailable)?,
            repository_id: row.get(4).map_err(unavailable)?,
        });
    }
    Ok(attempts)
}

async fn remove_attempts_durable(
    connection: &turso::Connection,
    attempts: &[ExpiredAttempt],
) -> Result<usize, CatalogError> {
    if attempts.is_empty() {
        return Ok(0);
    }
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .await
        .map_err(unavailable)?;
    let persisted = async {
        let affected = attempts
            .iter()
            .map(|attempt| (attempt.namespace.clone(), attempt.repository_id.clone()))
            .collect::<BTreeSet<_>>();
        for attempt in attempts {
            delete_attempt(connection, attempt).await?;
        }
        for (namespace, repository_id) in affected {
            repair_repository(connection, &namespace, &repository_id).await?;
        }
        repair_checkpoints(connection).await?;
        let watermark = metadata_u64(connection, "watermark")
            .await?
            .checked_add(1)
            .ok_or(CatalogError::StoreUnavailable)?;
        set_metadata_u64(connection, "watermark", watermark).await?;
        set_metadata_u64(connection, "cursor_floor", watermark).await?;
        Ok::<u64, CatalogError>(watermark)
    }
    .await;
    finish_transaction(connection, persisted).await?;
    Ok(attempts.len())
}

async fn delete_attempt(
    connection: &turso::Connection,
    expired: &ExpiredAttempt,
) -> Result<(), CatalogError> {
    if let Some(observation_id) = &expired.observation_id {
        for table in [
            "catalog_limitations",
            "catalog_packages",
            "catalog_requirements",
            "catalog_observations",
        ] {
            connection
                .execute(
                    &format!(
                        "DELETE FROM {table} WHERE namespace_kind = ?1
                         AND credential_profile_id = ?2 AND observation_id = ?3"
                    ),
                    turso::params![
                        expired.namespace.kind,
                        expired.namespace.credential_profile_id.as_str(),
                        observation_id.clone()
                    ],
                )
                .await
                .map_err(unavailable)?;
        }
    }
    connection
        .execute(
            "DELETE FROM catalog_attempts WHERE namespace_kind = ?1
             AND credential_profile_id = ?2 AND attempt_id = ?3",
            turso::params![
                expired.namespace.kind,
                expired.namespace.credential_profile_id.as_str(),
                expired.attempt_id.as_str()
            ],
        )
        .await
        .map_err(unavailable)?;
    connection
        .execute(
            "DELETE FROM catalog_projection_outbox WHERE namespace_kind = ?1
             AND credential_profile_id = ?2 AND attempt_id = ?3",
            turso::params![
                expired.namespace.kind,
                expired.namespace.credential_profile_id.as_str(),
                expired.attempt_id.as_str()
            ],
        )
        .await
        .map_err(unavailable)?;
    connection
        .execute(
            "DELETE FROM catalog_projection_inputs WHERE namespace_kind = ?1
             AND credential_profile_id = ?2 AND attempt_id = ?3",
            turso::params![
                expired.namespace.kind,
                expired.namespace.credential_profile_id.as_str(),
                expired.attempt_id.as_str()
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn repair_repository(
    connection: &turso::Connection,
    namespace: &NamespaceKey,
    repository_id: &str,
) -> Result<(), CatalogError> {
    repair_latest(connection, namespace, repository_id).await?;
    connection
        .execute(
            "DELETE FROM catalog_snapshots
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3
               AND NOT EXISTS (
                   SELECT 1 FROM catalog_attempts AS attempts
                   WHERE attempts.namespace_kind = catalog_snapshots.namespace_kind
                     AND attempts.credential_profile_id = catalog_snapshots.credential_profile_id
                     AND attempts.repository_id = catalog_snapshots.repository_id
                     AND attempts.snapshot_commit_sha = catalog_snapshots.commit_sha
                     AND attempts.snapshot_tree_sha = catalog_snapshots.tree_sha
                     AND attempts.snapshot_analyzer_profile_digest =
                         catalog_snapshots.analyzer_profile_digest
               )",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository_id
            ],
        )
        .await
        .map_err(unavailable)?;
    let mut rows = connection
        .query(
            "SELECT 1 FROM catalog_attempts
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3
             LIMIT 1",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                repository_id
            ],
        )
        .await
        .map_err(unavailable)?;
    if rows.next().await.map_err(unavailable)?.is_none() {
        connection
            .execute(
                "DELETE FROM catalog_repository_aliases
                 WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3",
                turso::params![
                    namespace.kind,
                    namespace.credential_profile_id.as_str(),
                    repository_id
                ],
            )
            .await
            .map_err(unavailable)?;
        connection
            .execute(
                "DELETE FROM catalog_repositories
                 WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND repository_id = ?3",
                turso::params![
                    namespace.kind,
                    namespace.credential_profile_id.as_str(),
                    repository_id
                ],
            )
            .await
            .map_err(unavailable)?;
    }
    Ok(())
}

async fn repair_checkpoints(connection: &turso::Connection) -> Result<(), CatalogError> {
    connection
        .execute_batch("DELETE FROM catalog_projection_checkpoints")
        .await
        .map_err(unavailable)?;
    connection
        .execute(
            "INSERT INTO catalog_projection_checkpoints (
                 namespace_kind, credential_profile_id, last_sequence, updated_at
             )
             SELECT namespace_kind, credential_profile_id, MAX(sequence), ?1
             FROM catalog_projection_inputs
             GROUP BY namespace_kind, credential_profile_id",
            turso::params![Utc::now().to_rfc3339()],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

async fn validate_saved_query_with_adapter(
    access: &InventoryAccessV1,
    draft: &SavedInventoryQueryDraftV1,
) -> Result<(), CatalogError> {
    let validation = InMemoryInventoryStore::new([0x33; 32]);
    let mut draft = draft.clone();
    draft.expected_previous_revision = None;
    validation.save_query(access, draft).await.map(|_| ())
}

async fn persist_saved_query(
    connection: &turso::Connection,
    access: &InventoryAccessV1,
    draft: &SavedInventoryQueryDraftV1,
) -> Result<SavedInventoryQueryRevisionV1, CatalogError> {
    let mut rows = connection
        .query(
            "SELECT revision_json FROM catalog_saved_query_revisions
             WHERE query_id = ?1 ORDER BY revision DESC LIMIT 1",
            turso::params![draft.query_id.as_str()],
        )
        .await
        .map_err(unavailable)?;
    let latest = match rows.next().await.map_err(unavailable)? {
        Some(row) => {
            let encoded: String = row.get(0).map_err(unavailable)?;
            Some(
                serde_json::from_str::<SavedInventoryQueryRevisionV1>(&encoded)
                    .map_err(unavailable)?,
            )
        }
        None => None,
    };
    if latest
        .as_ref()
        .is_some_and(|revision| !access.allows(&revision.namespace))
    {
        return Err(CatalogError::Unauthorized);
    }
    if latest
        .as_ref()
        .is_some_and(|revision| revision.namespace != draft.namespace)
    {
        return Err(CatalogError::InvalidInput(
            "saved query namespace cannot change across revisions".to_owned(),
        ));
    }
    let actual = latest.as_ref().map(|revision| revision.revision);
    if actual != draft.expected_previous_revision {
        return Err(CatalogError::RevisionConflict {
            expected: draft.expected_previous_revision,
            actual,
        });
    }
    let revision = SavedInventoryQueryRevisionV1 {
        schema_version: CATALOG_SCHEMA_VERSION_V1,
        query_id: draft.query_id.clone(),
        revision: actual.unwrap_or(0).saturating_add(1),
        name: draft.name.clone(),
        namespace: draft.namespace.clone(),
        query: draft.query.clone(),
        created_by: draft.created_by.clone(),
        created_at: draft.created_at,
    };
    let namespace = NamespaceKey::from(&revision.namespace);
    connection
        .execute(
            "INSERT INTO catalog_saved_query_revisions (
                 namespace_kind, credential_profile_id, query_id, revision,
                 name, created_by, created_at, revision_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            turso::params![
                namespace.kind,
                namespace.credential_profile_id.as_str(),
                revision.query_id.as_str(),
                to_i64(revision.revision)?,
                revision.name.as_str(),
                revision.created_by.as_str(),
                revision.created_at.to_rfc3339(),
                json(&revision)?
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use chrono::{TimeDelta, TimeZone as _};
    use semver::Version;

    use crate::{
        cargo_evidence::{PackageIdentityV1, RecordedRelation},
        coordinator::{ArtifactRefV1, JobId, Sha256Digest, TaskId},
        evidence::{
            DirectRequirementEvidenceV1, EvidenceBundleV1, EvidenceCompletenessV1,
            EvidenceReferenceV1, EvidenceStrengthV1, ExplanationStepKindV1, ExplanationStepV1,
            PackageEvidenceV1, RepositoryEvidenceV1, RepositoryExplanationV1,
            RepositoryVisibilityV1, RequirementEvidenceSourceV1,
        },
    };

    use super::super::model::{
        InventoryMatchModeV1, InventoryObservationEnvelopeV1, InventorySearchFieldV1,
        RepositoryAttemptInputV1, RepositoryRevisionV1,
    };
    use super::*;

    fn time(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, hour, 0, 0).unwrap()
    }

    fn failed(namespace: InventoryNamespaceV1) -> InventoryProjectionInputV1 {
        failed_at(namespace, "42", "owner/repository", "task-1", time(10))
    }

    fn failed_at(
        namespace: InventoryNamespaceV1,
        repository_id: &str,
        repository_full_name: &str,
        task_id: &str,
        completed_at: DateTime<Utc>,
    ) -> InventoryProjectionInputV1 {
        InventoryProjectionInputV1::FailedAttempt(RepositoryAttemptInputV1 {
            schema_version: CATALOG_SCHEMA_VERSION_V1,
            namespace,
            job_id: JobId("job-1".to_owned()),
            task_id: TaskId(task_id.to_owned()),
            task_attempt: 1,
            repository_id: repository_id.to_owned(),
            repository_full_name: repository_full_name.to_owned(),
            visibility: RepositoryVisibilityV1::Public,
            revision: None,
            completed_at,
            failure_code: "provider_unavailable".to_owned(),
            failure_message: "provider unavailable".to_owned(),
        })
    }

    fn observation(
        repository_id: &str,
        repository: &str,
        completed_at: DateTime<Utc>,
    ) -> InventoryProjectionInputV1 {
        let target = PackageIdentityV1 {
            name: "fs2".to_owned(),
            version: Version::new(0, 4, 3),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
        };
        let revision = RepositoryRevisionV1 {
            commit_sha: format!("commit-{repository_id}-{completed_at}"),
            tree_sha: format!("tree-{repository_id}-{completed_at}"),
            analyzer_profile_digest: "analyzer-v1".to_owned(),
        };
        let evidence = RepositoryEvidenceV1 {
            repository: repository.to_owned(),
            repository_id: Some(repository_id.to_owned()),
            visibility: RepositoryVisibilityV1::Public,
            head_committed_at: Some(completed_at - TimeDelta::days(1)),
            completeness: EvidenceCompletenessV1::Complete,
            requirements: vec![DirectRequirementEvidenceV1 {
                source: RequirementEvidenceSourceV1::CurrentManifest,
                manifest_path: "Cargo.toml".to_owned(),
                package_name: Some("app".to_owned()),
                requirement: Some("^0.4".to_owned()),
                accepts_target: Some(true),
                explicit_exact_pin: Some(false),
            }],
            exact_resolution_count: 1,
            recorded_relation: RecordedRelation::Direct,
            direct_witness: None,
            transitive_witness: None,
            msrv: Some(Version::new(1, 85, 0)),
            package_inventory_complete: true,
            packages: vec![
                PackageEvidenceV1 {
                    package: target.clone(),
                    license_expression: Some("MIT OR Apache-2.0".to_owned()),
                },
                PackageEvidenceV1 {
                    package: PackageIdentityV1 {
                        name: "serde".to_owned(),
                        version: Version::new(1, 0, 0),
                        source: target.source.clone(),
                    },
                    license_expression: None,
                },
            ],
            vulnerabilities: Vec::new(),
            explanation: RepositoryExplanationV1 {
                repository: repository.to_owned(),
                observed_at: completed_at,
                strength: EvidenceStrengthV1::VerifiedExactGraph,
                completeness: EvidenceCompletenessV1::Complete,
                steps: vec![ExplanationStepV1 {
                    kind: ExplanationStepKindV1::ImmutableRevision,
                    statement: "pinned revision".to_owned(),
                    reference: Some(EvidenceReferenceV1 {
                        commit_sha: Some(revision.commit_sha.clone()),
                        tree_sha: Some(revision.tree_sha.clone()),
                        path: None,
                        blob_sha: None,
                    }),
                }],
                limitations: Vec::new(),
                direct_witness: None,
                transitive_witness: None,
            },
        };
        InventoryProjectionInputV1::Observation(InventoryObservationEnvelopeV1 {
            schema_version: CATALOG_SCHEMA_VERSION_V1,
            namespace: InventoryNamespaceV1::Public,
            job_id: JobId(format!("job-{repository_id}-{completed_at}")),
            task_id: TaskId(format!("task-{repository_id}-{completed_at}")),
            task_attempt: 1,
            artifact: ArtifactRefV1 {
                digest: Sha256Digest::parse(format!("{repository_id:0>64}")).unwrap(),
                media_type: "application/vnd.crate-dependent-repos.evidence.v1+json".to_owned(),
                stored_bytes: 10,
            },
            repository_id: repository_id.to_owned(),
            revision,
            target_selector: "=0.4.3".to_owned(),
            completed_at,
            evidence: EvidenceBundleV1 {
                schema_version: EvidenceBundleV1::SCHEMA_VERSION,
                generated_at: completed_at,
                target,
                globally_exhaustive: false,
                repositories: vec![evidence],
                advisory_snapshots: Vec::new(),
                limitations: Vec::new(),
            },
        })
    }

    async fn scalar_i64(connection: &turso::Connection, sql: &str) -> i64 {
        let mut rows = connection.query(sql, ()).await.unwrap();
        rows.next().await.unwrap().unwrap().get(0).unwrap()
    }

    #[tokio::test]
    async fn bulk_rebuild_matches_incremental_projection_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let incremental =
            TursoInventoryStore::open(directory.path().join("incremental.db"), [19; 32])
                .await
                .unwrap();
        let rebuilt = TursoInventoryStore::open(directory.path().join("rebuilt.db"), [19; 32])
            .await
            .unwrap();
        let observed = observation("42", "owner/old-name", time(10));
        let failed = failed_at(
            InventoryNamespaceV1::Public,
            "42",
            "owner/new-name",
            "task-new",
            time(12),
        );
        let observed_outcome = incremental.project(observed.clone()).await.unwrap();
        let failed_outcome = incremental.project(failed.clone()).await.unwrap();
        rebuilt
            .rebuild(vec![failed, observed.clone(), observed])
            .await
            .unwrap();

        let access = access_for_namespace(&InventoryNamespaceV1::Public);
        let mut latest_evidence = InventoryQueryV1::new();
        latest_evidence.history = InventoryHistoryModeV1::LatestEvidence;
        let mut package_search = latest_evidence.clone();
        package_search.search = Some("serde".to_owned());
        package_search.search_field = InventorySearchFieldV1::Package;
        package_search.match_mode = InventoryMatchModeV1::Exact;
        for query in [
            InventoryQueryV1::new(),
            latest_evidence.clone(),
            package_search,
        ] {
            assert_eq!(
                rebuilt
                    .search(&access, &query, &InventoryPageRequestV1::default())
                    .await
                    .unwrap(),
                incremental
                    .search(&access, &query, &InventoryPageRequestV1::default())
                    .await
                    .unwrap()
            );
        }
        let mut prior_name_search = InventoryQueryV1::new();
        prior_name_search.search = Some("owner/old-name".to_owned());
        prior_name_search.search_field = InventorySearchFieldV1::Repository;
        prior_name_search.match_mode = InventoryMatchModeV1::Exact;
        for store in [&incremental, &rebuilt] {
            let page = store
                .search(
                    &access,
                    &prior_name_search,
                    &InventoryPageRequestV1::default(),
                )
                .await
                .unwrap();
            assert_eq!(page.items.len(), 1);
            assert_eq!(page.items[0].attempt.task_id, TaskId("task-new".to_owned()));
        }
        let latest = rebuilt
            .search(
                &access,
                &InventoryQueryV1::new(),
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            latest.items[0].attempt.task_id,
            TaskId("task-new".to_owned())
        );
        assert!(
            latest.items[0]
                .repository
                .aliases
                .contains("owner/old-name")
        );
        assert_eq!(rebuilt.watermark().await.unwrap(), 2);

        let database = rebuilt.database.lock().await;
        let connection = &database.connection;
        assert_eq!(metadata_u64(connection, "cursor_floor").await.unwrap(), 2);
        assert_eq!(
            scalar_i64(connection, "SELECT COUNT(*) FROM catalog_projection_inputs").await,
            2
        );
        assert_eq!(
            scalar_i64(
                connection,
                "SELECT COUNT(*) FROM catalog_projection_outbox WHERE projected_at IS NULL"
            )
            .await,
            0
        );
        assert_eq!(
            scalar_i64(
                connection,
                "SELECT COUNT(*) FROM catalog_search_documents WHERE ready <> 1"
            )
            .await,
            0
        );
        let mut rows = connection
            .query(
                "SELECT latest_attempt_id, latest_evidence_id, latest_complete_evidence_id
                 FROM catalog_latest WHERE namespace_kind = 'public'
                   AND credential_profile_id = '' AND repository_id = '42'",
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get::<String>(0).unwrap(), failed_outcome.attempt_id);
        assert_eq!(
            row.get::<String>(1).unwrap(),
            observed_outcome.observation_id.clone().unwrap()
        );
        assert_eq!(
            row.get::<String>(2).unwrap(),
            observed_outcome.observation_id.unwrap()
        );
        let mut rows = connection
            .query("SELECT field, term FROM catalog_search_terms", ())
            .await
            .unwrap();
        let mut terms = BTreeSet::new();
        while let Some(row) = rows.next().await.unwrap() {
            terms.insert((row.get::<String>(0).unwrap(), row.get::<String>(1).unwrap()));
        }
        for term in [
            ("repository", "owner/old-name"),
            ("repository", "owner/new-name"),
            ("package", "fs2"),
            ("package", "serde"),
        ] {
            assert!(terms.contains(&(term.0.to_owned(), term.1.to_owned())));
        }
    }

    #[tokio::test]
    async fn rebuild_transaction_rolls_back_partial_bulk_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = TursoInventoryStore::open(directory.path().join("coordinator.db"), [20; 32])
            .await
            .unwrap();
        store
            .project(failed_at(
                InventoryNamespaceV1::Public,
                "7",
                "owner/baseline",
                "task-baseline",
                time(9),
            ))
            .await
            .unwrap();

        let observed = observation("42", "owner/observed", time(10));
        let preview = preview_projection(&observed).await.unwrap();
        let malformed_input = failed_at(
            InventoryNamespaceV1::Public,
            "42",
            "owner/observed",
            "task-malformed",
            time(10),
        );
        let payload_json = serde_json::to_string(&malformed_input).unwrap();
        let payload_sha256 = sha256_hex(payload_json.as_bytes());
        let mut projections = vec![RebuildProjection {
            input: malformed_input,
            preview,
            payload_json,
            payload_sha256,
            sequence: 0,
        }];
        assign_rebuild_sequences(1, &mut projections).unwrap();

        let database = store.database.lock().await;
        let connection = &database.connection;
        connection.execute_batch("BEGIN IMMEDIATE").await.unwrap();
        let persisted = async {
            clear_projection(connection).await?;
            persist_rebuild(connection, &projections).await
        }
        .await;
        assert!(finish_transaction(connection, persisted).await.is_err());
        assert_eq!(metadata_u64(connection, "watermark").await.unwrap(), 1);
        assert_eq!(
            scalar_i64(connection, "SELECT COUNT(*) FROM catalog_projection_inputs").await,
            1
        );
        assert_eq!(
            scalar_i64(
                connection,
                "SELECT COUNT(*) FROM catalog_repositories WHERE repository_id = '7'"
            )
            .await,
            1
        );
    }

    #[tokio::test]
    async fn projection_is_idempotent_and_restores_its_sequence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordinator.db");
        let store = TursoInventoryStore::open(&path, [7; 32]).await.unwrap();
        let first = store
            .project(failed(InventoryNamespaceV1::Public))
            .await
            .unwrap();
        let repeated = store
            .project(failed(InventoryNamespaceV1::Public))
            .await
            .unwrap();
        assert_eq!(first.projection_sequence, 1);
        assert_eq!(repeated.projection_sequence, first.projection_sequence);
        assert!(repeated.already_projected);
        drop(store);

        let reopened = TursoInventoryStore::open(&path, [7; 32]).await.unwrap();
        assert_eq!(reopened.watermark().await.unwrap(), 1);
        let query = InventoryQueryV1::new();
        let page = reopened
            .search(
                &access_for_namespace(&InventoryNamespaceV1::Public),
                &query,
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);

        assert_eq!(
            reopened
                .retain_since(time(10) + TimeDelta::seconds(1))
                .await
                .unwrap(),
            1
        );
        assert!(
            reopened
                .search(
                    &access_for_namespace(&InventoryNamespaceV1::Public),
                    &InventoryQueryV1::new(),
                    &InventoryPageRequestV1::default(),
                )
                .await
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[tokio::test]
    async fn artifact_removal_fails_closed_for_non_artifact_attempts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordinator.db");
        let store = TursoInventoryStore::open(&path, [17; 32]).await.unwrap();
        store
            .project(failed(InventoryNamespaceV1::Public))
            .await
            .unwrap();
        let digest = crate::coordinator::Sha256Digest::parse("a".repeat(64)).unwrap();
        assert!(matches!(
            store
                .remove_artifact_projection(&TaskId("task-1".to_owned()), &digest)
                .await,
            Err(CatalogError::InvalidEvidence(_))
        ));
        assert_eq!(
            store
                .search(
                    &access_for_namespace(&InventoryNamespaceV1::Public),
                    &InventoryQueryV1::new(),
                    &InventoryPageRequestV1::default(),
                )
                .await
                .unwrap()
                .items
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn durable_cursor_keeps_its_projection_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordinator.db");
        let store = TursoInventoryStore::open(&path, [8; 32]).await.unwrap();
        for input in [
            failed_at(
                InventoryNamespaceV1::Public,
                "1",
                "owner/a",
                "task-a",
                time(10),
            ),
            failed_at(
                InventoryNamespaceV1::Public,
                "2",
                "owner/c",
                "task-c",
                time(11),
            ),
        ] {
            store.project(input).await.unwrap();
        }
        let mut query = InventoryQueryV1::new();
        query.sort = super::super::model::InventorySortV1::RepositoryAsc;
        let first = store
            .search(
                &access_for_namespace(&InventoryNamespaceV1::Public),
                &query,
                &InventoryPageRequestV1 {
                    limit: Some(1),
                    cursor: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(first.items[0].repository.full_name, "owner/a");

        store
            .project(failed_at(
                InventoryNamespaceV1::Public,
                "3",
                "owner/b",
                "task-b",
                time(12),
            ))
            .await
            .unwrap();
        let second = store
            .search(
                &access_for_namespace(&InventoryNamespaceV1::Public),
                &query,
                &InventoryPageRequestV1 {
                    limit: Some(1),
                    cursor: first.next_cursor,
                },
            )
            .await
            .unwrap();
        assert_eq!(second.index_watermark, 2);
        assert_eq!(second.items[0].repository.full_name, "owner/c");
        assert!(second.next_cursor.is_none());
    }

    #[tokio::test]
    async fn candidate_selection_and_hydration_share_a_read_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordinator.db");
        let store = TursoInventoryStore::open(&path, [18; 32]).await.unwrap();
        store
            .project(failed(InventoryNamespaceV1::Public))
            .await
            .unwrap();
        let observed_transaction = AtomicBool::new(false);

        let page = store
            .search_durable_with_candidate_observer(
                &access_for_namespace(&InventoryNamespaceV1::Public),
                &InventoryQueryV1::new(),
                &InventoryPageRequestV1::default(),
                |connection| {
                    observed_transaction.store(
                        !connection.is_autocommit().map_err(unavailable)?,
                        Ordering::Relaxed,
                    );
                    Ok(())
                },
            )
            .await
            .unwrap();

        assert!(observed_transaction.load(Ordering::Relaxed));
        assert_eq!(page.items.len(), 1);
    }

    #[tokio::test]
    async fn as_of_selection_streams_the_historical_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordinator.db");
        let store = TursoInventoryStore::open(&path, [9; 32]).await.unwrap();
        store
            .project(failed_at(
                InventoryNamespaceV1::Public,
                "42",
                "owner/repository",
                "task-old",
                time(10),
            ))
            .await
            .unwrap();
        store
            .project(failed_at(
                InventoryNamespaceV1::Public,
                "42",
                "owner/repository",
                "task-new",
                time(12),
            ))
            .await
            .unwrap();

        let mut query = InventoryQueryV1::new();
        query.as_of = Some(time(11));
        let page = store
            .search(
                &access_for_namespace(&InventoryNamespaceV1::Public),
                &query,
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].attempt.task_id, TaskId("task-old".to_owned()));
        assert_eq!(
            page.items[0].freshness,
            super::super::model::InventoryFreshnessV1::RefreshFailed
        );
    }
}
