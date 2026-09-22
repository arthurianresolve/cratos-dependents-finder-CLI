//! Searchable projections of canonical repository evidence.
//!
//! The catalog is a read model. Canonical evidence artifacts remain the source
//! of truth and can rebuild any [`InventoryProjectionStore`] implementation.

mod cursor;
mod memory;
mod model;
mod search;
mod sql_search;
mod turso;

pub use memory::InMemoryInventoryStore;
pub use model::{
    CATALOG_SCHEMA_VERSION_V1, CatalogError, InventoryAccessV1, InventoryAttemptStatusV1,
    InventoryFreshnessV1, InventoryHistoryModeV1, InventoryMatchModeV1, InventoryNamespaceV1,
    InventoryObservationEnvelopeV1, InventoryPageRequestV1, InventoryPageV1,
    InventoryProjectionInputV1, InventoryProjectionOutcomeV1, InventoryProjectionRecordV1,
    InventoryQueryV1, InventoryRepositoryV1, InventorySearchFieldV1, InventorySearchResultV1,
    InventorySortV1, InventorySourceFilterV1, PackagePresenceV1, RepositoryAttemptInputV1,
    RepositoryAttemptV1, RepositoryKeyV1, RepositoryLatestV1, RepositoryRevisionV1,
    RepositorySnapshotKeyV1, RepositorySnapshotV1, SavedInventoryQueryDraftV1,
    SavedInventoryQueryRevisionV1, TargetObservationV1,
};
pub(crate) use turso::TursoInventoryStore;

use futures::future::BoxFuture;

/// Normalize an exact repository owner/name for namespace-bound alias lookup.
pub(crate) fn normalize_repository_alias(value: &str) -> String {
    search::normalize_text(value)
}

fn input_is_suppressed(
    targets: &[crate::privacy::SuppressionTargetV1],
    input: &InventoryProjectionInputV1,
) -> bool {
    match input {
        InventoryProjectionInputV1::Observation(envelope) => targets.iter().any(|target| {
            target.matches(&envelope.namespace, &envelope.repository_id, "")
                || envelope.evidence.repositories.iter().any(|repository| {
                    target.matches(
                        &envelope.namespace,
                        &envelope.repository_id,
                        &repository.repository,
                    )
                })
        }),
        InventoryProjectionInputV1::FailedAttempt(attempt) => targets.iter().any(|target| {
            target.matches(
                &attempt.namespace,
                &attempt.repository_id,
                &attempt.repository_full_name,
            )
        }),
    }
}

/// Projection and query Interface implemented by durable and in-memory Adapters.
pub trait InventoryProjectionStore: Send + Sync {
    fn install_suppressions<'a>(
        &'a self,
        targets: &'a [crate::privacy::SuppressionTargetV1],
    ) -> BoxFuture<'a, Result<(), CatalogError>>;

    fn purge_repository<'a>(
        &'a self,
        target: &'a crate::privacy::SuppressionTargetV1,
        limit: usize,
    ) -> BoxFuture<'a, Result<usize, CatalogError>>;

    fn project<'a>(
        &'a self,
        input: InventoryProjectionInputV1,
    ) -> BoxFuture<'a, Result<InventoryProjectionOutcomeV1, CatalogError>>;

    fn rebuild(
        &self,
        inputs: Vec<InventoryProjectionInputV1>,
    ) -> BoxFuture<'_, Result<(), CatalogError>>;

    fn search<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        query: &'a InventoryQueryV1,
        page: &'a InventoryPageRequestV1,
    ) -> BoxFuture<'a, Result<InventoryPageV1, CatalogError>>;

    fn save_query<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        draft: SavedInventoryQueryDraftV1,
    ) -> BoxFuture<'a, Result<SavedInventoryQueryRevisionV1, CatalogError>>;

    fn saved_query<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        query_id: &'a str,
        revision: Option<u64>,
    ) -> BoxFuture<'a, Result<Option<SavedInventoryQueryRevisionV1>, CatalogError>>;

    /// Resolve an already-observed exact repository name or alias inside one
    /// explicit namespace. Ambiguous aliases fail closed as `None`.
    fn repository_for_alias<'a>(
        &'a self,
        namespace: &'a InventoryNamespaceV1,
        normalized_alias: &'a str,
    ) -> BoxFuture<'a, Result<Option<InventoryRepositoryV1>, CatalogError>>;

    /// Remove the projection sourced from one encrypted artifact. A digest
    /// mismatch fails closed so retention cannot delete the source while a
    /// different projection remains searchable.
    fn remove_artifact_projection<'a>(
        &'a self,
        task_id: &'a crate::coordinator::TaskId,
        artifact_digest: &'a crate::coordinator::Sha256Digest,
    ) -> BoxFuture<'a, Result<usize, CatalogError>>;

    /// Remove attempts and evidence observed before `cutoff` and repair all
    /// latest pointers. Returns the number of attempts removed.
    fn retain_since(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> BoxFuture<'_, Result<usize, CatalogError>>;

    fn watermark(&self) -> BoxFuture<'_, Result<u64, CatalogError>>;
}
