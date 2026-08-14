use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    sync::RwLock,
};

use chrono::{DateTime, Utc};
use futures::{FutureExt as _, future::BoxFuture};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::evidence::{EvidenceCompletenessV1, RepositoryEvidenceV1, RepositoryVisibilityV1};

use super::{
    InventoryProjectionStore,
    cursor::CursorSigner,
    model::{
        CATALOG_SCHEMA_VERSION_V1, CatalogError, InventoryAccessV1, InventoryAttemptStatusV1,
        InventoryFreshnessV1, InventoryHistoryModeV1, InventoryNamespaceV1,
        InventoryObservationEnvelopeV1, InventoryPageRequestV1, InventoryPageV1,
        InventoryProjectionInputV1, InventoryProjectionOutcomeV1, InventoryQueryV1,
        InventoryRepositoryV1, InventorySearchResultV1, MAX_PACKAGES_PER_RESULT, PackagePresenceV1,
        RepositoryAttemptInputV1, RepositoryAttemptV1, RepositoryKeyV1, RepositoryLatestV1,
        RepositorySnapshotKeyV1, RepositorySnapshotV1, SavedInventoryQueryDraftV1,
        SavedInventoryQueryRevisionV1, TRIGRAM_INDEX_VERSION_V1, TargetObservationV1,
    },
    search::{
        TrigramIndexV1, compare_results, compare_sort_keys, matches_filters, normalize_text,
        sort_key,
    },
};

#[derive(Debug, Default)]
struct MemoryState {
    repositories: BTreeMap<RepositoryKeyV1, InventoryRepositoryV1>,
    snapshots: BTreeMap<RepositorySnapshotKeyV1, RepositorySnapshotV1>,
    attempts: BTreeMap<String, RepositoryAttemptV1>,
    attempts_by_repository: BTreeMap<RepositoryKeyV1, BTreeSet<String>>,
    observations: BTreeMap<String, TargetObservationV1>,
    packages: BTreeMap<String, Vec<PackagePresenceV1>>,
    latest: BTreeMap<RepositoryKeyV1, RepositoryLatestV1>,
    search_indexes: BTreeMap<InventoryNamespaceV1, TrigramIndexV1>,
    saved_queries: BTreeMap<String, Vec<SavedInventoryQueryRevisionV1>>,
    watermark: u64,
    cursor_floor: u64,
}

/// Pure in-memory Adapter used by tests and single-process callers.
#[derive(Debug)]
pub struct InMemoryInventoryStore {
    state: RwLock<MemoryState>,
    cursor_signer: CursorSigner,
}

impl InMemoryInventoryStore {
    pub fn new(cursor_signing_key: [u8; 32]) -> Self {
        Self {
            state: RwLock::new(MemoryState::default()),
            cursor_signer: CursorSigner::new(cursor_signing_key),
        }
    }

    fn project_inner(
        &self,
        input: InventoryProjectionInputV1,
    ) -> Result<InventoryProjectionOutcomeV1, CatalogError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| CatalogError::StoreUnavailable)?;
        let sequence = state.watermark.saturating_add(1);
        project_input_at(&mut state, input, sequence)
    }

    fn search_inner(
        &self,
        access: &InventoryAccessV1,
        query: &InventoryQueryV1,
        page: &InventoryPageRequestV1,
    ) -> Result<InventoryPageV1, CatalogError> {
        access.validate()?;
        query.validate()?;
        let limit = page.limit()?;
        if query
            .namespace
            .as_ref()
            .is_some_and(|namespace| !access.allows(namespace))
        {
            return Err(CatalogError::Unauthorized);
        }

        let state = self
            .state
            .read()
            .map_err(|_| CatalogError::StoreUnavailable)?;
        let cursor = page
            .cursor
            .as_deref()
            .map(|encoded| self.cursor_signer.decode(encoded, access, query))
            .transpose()?;
        let snapshot_watermark = cursor
            .as_ref()
            .map_or(state.watermark, |cursor| cursor.index_watermark);
        if snapshot_watermark > state.watermark || snapshot_watermark < state.cursor_floor {
            return Err(CatalogError::CursorStale);
        }

        // Namespace authorization happens before candidate lookup and ranking.
        let namespaces = state
            .search_indexes
            .keys()
            .filter(|namespace| {
                access.allows(namespace)
                    && query
                        .namespace
                        .as_ref()
                        .is_none_or(|selected| selected == *namespace)
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let selected_attempts = select_attempts(&state, query, &namespaces, snapshot_watermark);
        let search_candidates = namespaces
            .iter()
            .filter_map(|namespace| state.search_indexes.get(namespace))
            .flat_map(|index| index.candidate_ids(query))
            .collect::<BTreeSet<_>>();

        let mut results = selected_attempts
            .intersection(&search_candidates)
            .filter_map(|attempt_id| build_result(&state, attempt_id, query, snapshot_watermark))
            .filter(|result| matches_filters(result, query))
            .map(bound_packages)
            .collect::<Vec<_>>();
        results.sort_by(|left, right| compare_results(left, right, query.sort));
        if let Some(cursor) = &cursor {
            results.retain(|result| {
                compare_sort_keys(&sort_key(result), &cursor.last, query.sort) == Ordering::Greater
            });
        }

        let has_more = results.len() > limit;
        results.truncate(limit);
        let next_cursor = has_more
            .then(|| {
                results.last().map(|result| {
                    self.cursor_signer
                        .encode(access, query, snapshot_watermark, sort_key(result))
                })
            })
            .flatten()
            .transpose()?;
        Ok(InventoryPageV1 {
            schema_version: CATALOG_SCHEMA_VERSION_V1,
            trigram_index_version: TRIGRAM_INDEX_VERSION_V1,
            index_watermark: snapshot_watermark,
            items: results,
            next_cursor,
        })
    }
}

impl InventoryProjectionStore for InMemoryInventoryStore {
    fn project<'a>(
        &'a self,
        input: InventoryProjectionInputV1,
    ) -> BoxFuture<'a, Result<InventoryProjectionOutcomeV1, CatalogError>> {
        async move { self.project_inner(input) }.boxed()
    }

    fn rebuild(
        &self,
        mut inputs: Vec<InventoryProjectionInputV1>,
    ) -> BoxFuture<'_, Result<(), CatalogError>> {
        async move {
            inputs.sort_by(|left, right| {
                left.completed_at()
                    .cmp(&right.completed_at())
                    .then_with(|| left.stable_order_key().cmp(&right.stable_order_key()))
            });
            let mut state = self
                .state
                .write()
                .map_err(|_| CatalogError::StoreUnavailable)?;
            let mut rebuilt = MemoryState {
                watermark: state.watermark,
                ..MemoryState::default()
            };
            for input in inputs {
                let sequence = rebuilt.watermark.saturating_add(1);
                project_input_at(&mut rebuilt, input, sequence)?;
            }
            if rebuilt.watermark == state.watermark {
                rebuilt.watermark = rebuilt.watermark.saturating_add(1);
            }
            rebuilt.saved_queries = std::mem::take(&mut state.saved_queries);
            rebuilt.cursor_floor = rebuilt.watermark;
            *state = rebuilt;
            Ok(())
        }
        .boxed()
    }

    fn search<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        query: &'a InventoryQueryV1,
        page: &'a InventoryPageRequestV1,
    ) -> BoxFuture<'a, Result<InventoryPageV1, CatalogError>> {
        async move { self.search_inner(access, query, page) }.boxed()
    }

    fn save_query<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        draft: SavedInventoryQueryDraftV1,
    ) -> BoxFuture<'a, Result<SavedInventoryQueryRevisionV1, CatalogError>> {
        async move {
            validate_saved_query(access, &draft)?;
            let mut state = self
                .state
                .write()
                .map_err(|_| CatalogError::StoreUnavailable)?;
            let revisions = state
                .saved_queries
                .entry(draft.query_id.clone())
                .or_default();
            if let Some(latest) = revisions.last()
                && !access.allows(&latest.namespace)
            {
                return Err(CatalogError::Unauthorized);
            }
            let actual = revisions.last().map(|revision| revision.revision);
            if actual != draft.expected_previous_revision {
                return Err(CatalogError::RevisionConflict {
                    expected: draft.expected_previous_revision,
                    actual,
                });
            }
            let revision = SavedInventoryQueryRevisionV1 {
                schema_version: CATALOG_SCHEMA_VERSION_V1,
                query_id: draft.query_id,
                revision: actual.unwrap_or(0).saturating_add(1),
                name: draft.name,
                namespace: draft.namespace,
                query: draft.query,
                created_by: draft.created_by,
                created_at: draft.created_at,
            };
            revisions.push(revision.clone());
            Ok(revision)
        }
        .boxed()
    }

    fn saved_query<'a>(
        &'a self,
        access: &'a InventoryAccessV1,
        query_id: &'a str,
        revision: Option<u64>,
    ) -> BoxFuture<'a, Result<Option<SavedInventoryQueryRevisionV1>, CatalogError>> {
        async move {
            access.validate()?;
            let state = self
                .state
                .read()
                .map_err(|_| CatalogError::StoreUnavailable)?;
            let Some(revisions) = state.saved_queries.get(query_id) else {
                return Ok(None);
            };
            let selected = match revision {
                Some(revision) => revisions
                    .iter()
                    .find(|candidate| candidate.revision == revision),
                None => revisions.last(),
            };
            if selected.is_some_and(|selected| !access.allows(&selected.namespace)) {
                return Err(CatalogError::Unauthorized);
            }
            Ok(selected.cloned())
        }
        .boxed()
    }

    fn remove_artifact_projection<'a>(
        &'a self,
        task_id: &'a crate::coordinator::TaskId,
        artifact_digest: &'a crate::coordinator::Sha256Digest,
    ) -> BoxFuture<'a, Result<usize, CatalogError>> {
        async move {
            let mut state = self
                .state
                .write()
                .map_err(|_| CatalogError::StoreUnavailable)?;
            let attempt_ids = state
                .attempts
                .iter()
                .filter(|(_, attempt)| &attempt.task_id == task_id)
                .map(|(attempt_id, _)| attempt_id.clone())
                .collect::<Vec<_>>();
            for attempt_id in &attempt_ids {
                let attempt = &state.attempts[attempt_id];
                let observation = attempt
                    .observation_id
                    .as_ref()
                    .and_then(|observation_id| state.observations.get(observation_id))
                    .ok_or_else(|| {
                        CatalogError::InvalidEvidence(
                            "artifact task is bound to a non-artifact projection".to_owned(),
                        )
                    })?;
                if &observation.artifact.digest != artifact_digest {
                    return Err(CatalogError::InvalidEvidence(
                        "artifact digest does not match its searchable projection".to_owned(),
                    ));
                }
            }
            remove_attempt_ids(&mut state, &attempt_ids);
            Ok(attempt_ids.len())
        }
        .boxed()
    }

    fn repository_for_alias<'a>(
        &'a self,
        namespace: &'a InventoryNamespaceV1,
        normalized_alias: &'a str,
    ) -> BoxFuture<'a, Result<Option<InventoryRepositoryV1>, CatalogError>> {
        async move {
            namespace.validate()?;
            if normalized_alias.is_empty() || normalize_text(normalized_alias) != normalized_alias {
                return Err(CatalogError::InvalidInput(
                    "repository alias must be non-empty and normalized".to_owned(),
                ));
            }
            let state = self
                .state
                .read()
                .map_err(|_| CatalogError::StoreUnavailable)?;
            let mut matches = state.repositories.values().filter(|repository| {
                &repository.key.namespace == namespace
                    && (repository.normalized_full_name == normalized_alias
                        || repository.aliases.contains(normalized_alias))
            });
            let selected = matches.next().cloned();
            Ok(if matches.next().is_some() {
                None
            } else {
                selected
            })
        }
        .boxed()
    }

    fn retain_since(&self, cutoff: DateTime<Utc>) -> BoxFuture<'_, Result<usize, CatalogError>> {
        async move {
            let mut state = self
                .state
                .write()
                .map_err(|_| CatalogError::StoreUnavailable)?;
            let removed_ids = state
                .attempts
                .iter()
                .filter(|(_, attempt)| attempt.completed_at < cutoff)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            if removed_ids.is_empty() {
                return Ok(0);
            }
            remove_attempt_ids(&mut state, &removed_ids);
            Ok(removed_ids.len())
        }
        .boxed()
    }

    fn watermark(&self) -> BoxFuture<'_, Result<u64, CatalogError>> {
        async move {
            self.state
                .read()
                .map(|state| state.watermark)
                .map_err(|_| CatalogError::StoreUnavailable)
        }
        .boxed()
    }
}

fn project_input_at(
    state: &mut MemoryState,
    input: InventoryProjectionInputV1,
    sequence: u64,
) -> Result<InventoryProjectionOutcomeV1, CatalogError> {
    if sequence <= state.watermark {
        return Err(CatalogError::InvalidInput(
            "projection sequences must be strictly increasing".to_owned(),
        ));
    }
    match input {
        InventoryProjectionInputV1::Observation(envelope) => {
            project_observation(state, envelope, sequence)
        }
        InventoryProjectionInputV1::FailedAttempt(attempt) => {
            project_failed_attempt(state, attempt, sequence)
        }
    }
}

fn project_observation(
    state: &mut MemoryState,
    envelope: InventoryObservationEnvelopeV1,
    sequence: u64,
) -> Result<InventoryProjectionOutcomeV1, CatalogError> {
    let evidence = validate_observation(&envelope)?.clone();
    let repository_key = RepositoryKeyV1 {
        namespace: envelope.namespace.clone(),
        repository_id: envelope.repository_id.clone(),
    };
    let attempt_id = attempt_id(
        &repository_key,
        &envelope.job_id.0,
        &envelope.task_id.0,
        envelope.task_attempt,
    )?;
    let observation_id = digest_json(&(
        "inventory-observation-v1",
        &attempt_id,
        envelope.artifact.digest.as_str(),
    ))?;
    let projection_digest = digest_json(&(
        "inventory-observation-projection-v1",
        &repository_key,
        &envelope.job_id,
        &envelope.task_id,
        envelope.task_attempt,
        &envelope.artifact,
        &envelope.revision,
        &envelope.target_selector,
        envelope.completed_at,
    ))?;
    if let Some(existing) = state.attempts.get(&attempt_id) {
        if existing.observation_id.as_deref() != Some(&observation_id)
            || existing.projection_digest != projection_digest
        {
            return Err(CatalogError::InvalidEvidence(
                "a logical task attempt was projected with different evidence".to_owned(),
            ));
        }
        return Ok(InventoryProjectionOutcomeV1 {
            attempt_id,
            observation_id: Some(observation_id),
            projection_sequence: existing.projection_sequence,
            index_watermark: state.watermark,
            already_projected: true,
        });
    }

    upsert_repository(
        state,
        repository_key.clone(),
        &evidence.repository,
        evidence.visibility,
        envelope.completed_at,
    )?;
    let snapshot_key = RepositorySnapshotKeyV1 {
        repository: repository_key.clone(),
        revision: envelope.revision,
    };
    upsert_snapshot(
        state,
        snapshot_key.clone(),
        evidence.head_committed_at,
        envelope.completed_at,
    );
    let repository = state
        .repositories
        .get(&repository_key)
        .cloned()
        .ok_or(CatalogError::StoreUnavailable)?;

    let status = match evidence.completeness {
        EvidenceCompletenessV1::Complete => InventoryAttemptStatusV1::Complete,
        EvidenceCompletenessV1::Partial | EvidenceCompletenessV1::Unavailable => {
            InventoryAttemptStatusV1::Partial
        }
    };
    let attempt = RepositoryAttemptV1 {
        attempt_id: attempt_id.clone(),
        projection_digest,
        projection_sequence: sequence,
        repository: repository_key.clone(),
        repository_full_name: evidence.repository.clone(),
        normalized_repository_name: normalize_text(&evidence.repository),
        repository_owner: evidence
            .repository
            .split_once('/')
            .map_or("", |(owner, _)| owner)
            .to_owned(),
        normalized_repository_owner: evidence
            .repository
            .split_once('/')
            .map_or_else(String::new, |(owner, _)| normalize_text(owner)),
        repository_visibility: evidence.visibility,
        repository_aliases: repository.aliases,
        snapshot: Some(snapshot_key.clone()),
        job_id: envelope.job_id.clone(),
        task_id: envelope.task_id.clone(),
        task_attempt: envelope.task_attempt,
        completed_at: envelope.completed_at,
        status,
        failure_code: None,
        failure_message: None,
        observation_id: Some(observation_id.clone()),
    };
    let mut limitations = envelope.evidence.limitations.clone();
    limitations.extend(evidence.explanation.limitations.iter().cloned());
    limitations.sort();
    limitations.dedup();
    let observation = TargetObservationV1 {
        observation_id: observation_id.clone(),
        attempt_id: attempt_id.clone(),
        snapshot: snapshot_key.clone(),
        target: envelope.evidence.target,
        requirements: evidence.requirements.clone(),
        exact_resolution_count: evidence.exact_resolution_count,
        recorded_relation: evidence.recorded_relation,
        direct_witness: evidence.direct_witness.clone(),
        transitive_witness: evidence.transitive_witness.clone(),
        msrv: evidence.msrv.clone(),
        strength: evidence.explanation.strength,
        completeness: evidence.completeness,
        limitations,
        globally_exhaustive: envelope.evidence.globally_exhaustive,
        package_inventory_complete: evidence.package_inventory_complete,
        observed_at: envelope.completed_at,
        job_id: envelope.job_id,
        task_id: envelope.task_id,
        task_attempt: envelope.task_attempt,
        artifact: envelope.artifact,
    };
    let packages = evidence
        .packages
        .iter()
        .map(|evidence| PackagePresenceV1 {
            observation_id: observation_id.clone(),
            snapshot: snapshot_key.clone(),
            package: evidence.package.clone(),
            license_expression: evidence.license_expression.clone(),
            inventory_complete: observation.package_inventory_complete,
        })
        .collect::<Vec<_>>();

    state.attempts.insert(attempt_id.clone(), attempt);
    state
        .attempts_by_repository
        .entry(repository_key.clone())
        .or_default()
        .insert(attempt_id.clone());
    state
        .observations
        .insert(observation_id.clone(), observation);
    state.packages.insert(observation_id.clone(), packages);
    recompute_latest(state, &repository_key);
    index_attempt(state, &attempt_id);
    state.watermark = sequence;
    Ok(InventoryProjectionOutcomeV1 {
        attempt_id,
        observation_id: Some(observation_id),
        projection_sequence: sequence,
        index_watermark: state.watermark,
        already_projected: false,
    })
}

fn project_failed_attempt(
    state: &mut MemoryState,
    input: RepositoryAttemptInputV1,
    sequence: u64,
) -> Result<InventoryProjectionOutcomeV1, CatalogError> {
    validate_failed_attempt(&input)?;
    let projection_digest = digest_json(&("inventory-failed-attempt-projection-v1", &input))?;
    let repository_key = RepositoryKeyV1 {
        namespace: input.namespace,
        repository_id: input.repository_id,
    };
    let attempt_id = attempt_id(
        &repository_key,
        &input.job_id.0,
        &input.task_id.0,
        input.task_attempt,
    )?;
    if let Some(existing) = state.attempts.get(&attempt_id) {
        if existing.status != InventoryAttemptStatusV1::Failed
            || existing.projection_digest != projection_digest
        {
            return Err(CatalogError::InvalidEvidence(
                "a logical task attempt was projected with a different outcome".to_owned(),
            ));
        }
        return Ok(InventoryProjectionOutcomeV1 {
            attempt_id,
            observation_id: None,
            projection_sequence: existing.projection_sequence,
            index_watermark: state.watermark,
            already_projected: true,
        });
    }

    upsert_repository(
        state,
        repository_key.clone(),
        &input.repository_full_name,
        input.visibility,
        input.completed_at,
    )?;
    let snapshot = input.revision.map(|revision| {
        let key = RepositorySnapshotKeyV1 {
            repository: repository_key.clone(),
            revision,
        };
        upsert_snapshot(state, key.clone(), None, input.completed_at);
        key
    });
    let repository = state
        .repositories
        .get(&repository_key)
        .cloned()
        .ok_or(CatalogError::StoreUnavailable)?;
    let repository_owner = input
        .repository_full_name
        .split_once('/')
        .map_or("", |(owner, _)| owner)
        .to_owned();
    let attempt = RepositoryAttemptV1 {
        attempt_id: attempt_id.clone(),
        projection_digest,
        projection_sequence: sequence,
        repository: repository_key.clone(),
        repository_full_name: input.repository_full_name.clone(),
        normalized_repository_name: normalize_text(&input.repository_full_name),
        normalized_repository_owner: normalize_text(&repository_owner),
        repository_owner,
        repository_visibility: input.visibility,
        repository_aliases: repository.aliases,
        snapshot,
        job_id: input.job_id,
        task_id: input.task_id,
        task_attempt: input.task_attempt,
        completed_at: input.completed_at,
        status: InventoryAttemptStatusV1::Failed,
        failure_code: Some(input.failure_code),
        failure_message: Some(input.failure_message),
        observation_id: None,
    };
    state.attempts.insert(attempt_id.clone(), attempt);
    state
        .attempts_by_repository
        .entry(repository_key.clone())
        .or_default()
        .insert(attempt_id.clone());
    recompute_latest(state, &repository_key);
    index_attempt(state, &attempt_id);
    state.watermark = sequence;
    Ok(InventoryProjectionOutcomeV1 {
        attempt_id,
        observation_id: None,
        projection_sequence: sequence,
        index_watermark: state.watermark,
        already_projected: false,
    })
}

fn validate_observation(
    envelope: &InventoryObservationEnvelopeV1,
) -> Result<&RepositoryEvidenceV1, CatalogError> {
    if envelope.schema_version != CATALOG_SCHEMA_VERSION_V1 {
        return Err(CatalogError::UnsupportedSchemaVersion(
            envelope.schema_version,
        ));
    }
    envelope.namespace.validate()?;
    envelope.revision.validate()?;
    validate_nonempty("repository_id", &envelope.repository_id)?;
    if !envelope.evidence.schema_is_supported() {
        return Err(CatalogError::InvalidEvidence(
            "canonical evidence schema is unsupported".to_owned(),
        ));
    }
    if envelope.target_selector != format!("={}", envelope.evidence.target.version) {
        return Err(CatalogError::InvalidEvidence(
            "catalog projection accepts exact target selectors only".to_owned(),
        ));
    }
    let [repository] = envelope.evidence.repositories.as_slice() else {
        return Err(CatalogError::InvalidEvidence(
            "a repository task artifact must contain exactly one repository".to_owned(),
        ));
    };
    if repository.repository_id.as_deref() != Some(&envelope.repository_id) {
        return Err(CatalogError::InvalidEvidence(
            "task and evidence repository identities differ".to_owned(),
        ));
    }
    validate_visibility(&envelope.namespace, repository.visibility)?;
    for reference in repository
        .explanation
        .steps
        .iter()
        .filter_map(|step| step.reference.as_ref())
    {
        if reference
            .commit_sha
            .as_ref()
            .is_some_and(|sha| sha != &envelope.revision.commit_sha)
            || reference
                .tree_sha
                .as_ref()
                .is_some_and(|sha| sha != &envelope.revision.tree_sha)
        {
            return Err(CatalogError::InvalidEvidence(
                "evidence references a different immutable revision".to_owned(),
            ));
        }
    }
    Ok(repository)
}

fn validate_failed_attempt(input: &RepositoryAttemptInputV1) -> Result<(), CatalogError> {
    if input.schema_version != CATALOG_SCHEMA_VERSION_V1 {
        return Err(CatalogError::UnsupportedSchemaVersion(input.schema_version));
    }
    input.namespace.validate()?;
    if let Some(revision) = &input.revision {
        revision.validate()?;
    }
    validate_nonempty("repository_id", &input.repository_id)?;
    validate_repository_name(&input.repository_full_name)?;
    validate_nonempty("failure_code", &input.failure_code)?;
    validate_nonempty("failure_message", &input.failure_message)?;
    validate_visibility(&input.namespace, input.visibility)
}

fn validate_visibility(
    namespace: &InventoryNamespaceV1,
    visibility: RepositoryVisibilityV1,
) -> Result<(), CatalogError> {
    if *namespace == InventoryNamespaceV1::Public && visibility != RepositoryVisibilityV1::Public {
        return Err(CatalogError::InvalidEvidence(
            "non-public repository metadata cannot enter the public namespace".to_owned(),
        ));
    }
    Ok(())
}

fn upsert_repository(
    state: &mut MemoryState,
    key: RepositoryKeyV1,
    full_name: &str,
    visibility: RepositoryVisibilityV1,
    observed_at: DateTime<Utc>,
) -> Result<(), CatalogError> {
    let (owner, normalized_full_name, normalized_owner) = validate_repository_name(full_name)?;
    match state.repositories.get_mut(&key) {
        Some(repository) => {
            repository.first_observed_at = repository.first_observed_at.min(observed_at);
            if observed_at >= repository.last_observed_at {
                if repository.normalized_full_name != normalized_full_name {
                    repository
                        .aliases
                        .insert(repository.normalized_full_name.clone());
                }
                repository.full_name = full_name.to_owned();
                repository.normalized_full_name = normalized_full_name;
                repository.owner = owner;
                repository.normalized_owner = normalized_owner;
                repository.visibility = visibility;
                repository.last_observed_at = observed_at;
            } else if repository.normalized_full_name != normalized_full_name {
                repository.aliases.insert(normalized_full_name);
            }
        }
        None => {
            state.repositories.insert(
                key.clone(),
                InventoryRepositoryV1 {
                    key,
                    full_name: full_name.to_owned(),
                    normalized_full_name,
                    owner,
                    normalized_owner,
                    visibility,
                    aliases: BTreeSet::new(),
                    first_observed_at: observed_at,
                    last_observed_at: observed_at,
                },
            );
        }
    }
    Ok(())
}

fn upsert_snapshot(
    state: &mut MemoryState,
    key: RepositorySnapshotKeyV1,
    head_committed_at: Option<DateTime<Utc>>,
    observed_at: DateTime<Utc>,
) {
    state
        .snapshots
        .entry(key.clone())
        .and_modify(|snapshot| {
            snapshot.first_observed_at = snapshot.first_observed_at.min(observed_at);
            snapshot.last_observed_at = snapshot.last_observed_at.max(observed_at);
            if snapshot.head_committed_at.is_none() {
                snapshot.head_committed_at = head_committed_at;
            }
        })
        .or_insert(RepositorySnapshotV1 {
            key,
            head_committed_at,
            first_observed_at: observed_at,
            last_observed_at: observed_at,
        });
}

fn recompute_latest(state: &mut MemoryState, repository: &RepositoryKeyV1) {
    let mut attempts = state
        .attempts_by_repository
        .get(repository)
        .into_iter()
        .flatten()
        .filter_map(|id| state.attempts.get(id))
        .collect::<Vec<_>>();
    attempts.sort_by(|left, right| attempt_order(left, right));
    let latest_attempt_id = attempts.last().map(|attempt| attempt.attempt_id.clone());
    let latest_evidence_id = attempts
        .iter()
        .rev()
        .find_map(|attempt| attempt.observation_id.clone());
    let latest_complete_evidence_id = attempts.iter().rev().find_map(|attempt| {
        let observation_id = attempt.observation_id.as_ref()?;
        state
            .observations
            .get(observation_id)
            .is_some_and(|observation| observation.completeness == EvidenceCompletenessV1::Complete)
            .then(|| observation_id.clone())
    });
    state.latest.insert(
        repository.clone(),
        RepositoryLatestV1 {
            latest_attempt_id,
            latest_evidence_id,
            latest_complete_evidence_id,
        },
    );
}

fn index_attempt(state: &mut MemoryState, attempt_id: &str) {
    let Some(attempt) = state.attempts.get(attempt_id) else {
        return;
    };
    let repository_terms = std::iter::once(attempt.repository_full_name.clone())
        .chain(attempt.repository_aliases.iter().cloned())
        .chain(std::iter::once(attempt.repository_owner.clone()))
        .collect::<Vec<_>>();
    let package_terms = attempt
        .observation_id
        .as_ref()
        .map(|observation_id| {
            let target = state
                .observations
                .get(observation_id)
                .map(|observation| observation.target.name.clone());
            target
                .into_iter()
                .chain(
                    state
                        .packages
                        .get(observation_id)
                        .into_iter()
                        .flatten()
                        .map(|presence| presence.package.name.clone()),
                )
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    state
        .search_indexes
        .entry(attempt.repository.namespace.clone())
        .or_default()
        .upsert(attempt_id, repository_terms, package_terms);
}

fn select_attempts(
    state: &MemoryState,
    query: &InventoryQueryV1,
    namespaces: &BTreeSet<InventoryNamespaceV1>,
    snapshot_watermark: u64,
) -> BTreeSet<String> {
    let mut selected = BTreeSet::new();
    for (repository, attempt_ids) in &state.attempts_by_repository {
        if !namespaces.contains(&repository.namespace) {
            continue;
        }
        let mut attempts = attempt_ids
            .iter()
            .filter_map(|id| state.attempts.get(id))
            .filter(|attempt| {
                attempt.projection_sequence <= snapshot_watermark
                    && query
                        .as_of
                        .is_none_or(|as_of| attempt.completed_at <= as_of)
            })
            .collect::<Vec<_>>();
        attempts.sort_by(|left, right| attempt_order(left, right));
        match query.history {
            InventoryHistoryModeV1::LatestAttempt => {
                selected.extend(attempts.last().map(|attempt| attempt.attempt_id.clone()));
            }
            InventoryHistoryModeV1::LatestEvidence => {
                selected.extend(
                    attempts
                        .iter()
                        .rev()
                        .find(|attempt| attempt.observation_id.is_some())
                        .map(|attempt| attempt.attempt_id.clone()),
                );
            }
            InventoryHistoryModeV1::LastComplete => {
                selected.extend(
                    attempts
                        .iter()
                        .rev()
                        .find(|attempt| {
                            attempt
                                .observation_id
                                .as_ref()
                                .is_some_and(|observation_id| {
                                    state.observations.get(observation_id).is_some_and(
                                        |observation| {
                                            observation.completeness
                                                == EvidenceCompletenessV1::Complete
                                        },
                                    )
                                })
                        })
                        .map(|attempt| attempt.attempt_id.clone()),
                );
            }
            InventoryHistoryModeV1::Observations => {
                selected.extend(
                    attempts
                        .into_iter()
                        .map(|attempt| attempt.attempt_id.clone()),
                );
            }
        }
    }
    selected
}

fn build_result(
    state: &MemoryState,
    attempt_id: &str,
    query: &InventoryQueryV1,
    snapshot_watermark: u64,
) -> Option<InventorySearchResultV1> {
    let attempt = state.attempts.get(attempt_id)?.clone();
    let mut repository = state.repositories.get(&attempt.repository)?.clone();
    repository.full_name = attempt.repository_full_name.clone();
    repository.normalized_full_name = attempt.normalized_repository_name.clone();
    repository.owner = attempt.repository_owner.clone();
    repository.normalized_owner = attempt.normalized_repository_owner.clone();
    repository.visibility = attempt.repository_visibility;
    repository.aliases = attempt.repository_aliases.clone();
    let snapshot = attempt
        .snapshot
        .as_ref()
        .and_then(|key| state.snapshots.get(key))
        .cloned();
    let observation = attempt
        .observation_id
        .as_ref()
        .and_then(|id| state.observations.get(id))
        .cloned();
    let packages = attempt
        .observation_id
        .as_ref()
        .and_then(|id| state.packages.get(id))
        .cloned()
        .unwrap_or_default();
    let latest_attempt = state
        .attempts_by_repository
        .get(&attempt.repository)
        .into_iter()
        .flatten()
        .filter_map(|id| state.attempts.get(id))
        .filter(|candidate| {
            candidate.projection_sequence <= snapshot_watermark
                && query
                    .as_of
                    .is_none_or(|as_of| candidate.completed_at <= as_of)
        })
        .max_by(|left, right| attempt_order(left, right))
        .map(|latest| latest.attempt_id.as_str());
    let freshness = if latest_attempt != Some(attempt_id) {
        InventoryFreshnessV1::Historical
    } else {
        match attempt.status {
            InventoryAttemptStatusV1::Complete => InventoryFreshnessV1::Current,
            InventoryAttemptStatusV1::Partial => InventoryFreshnessV1::RefreshPartial,
            InventoryAttemptStatusV1::Failed => InventoryFreshnessV1::RefreshFailed,
        }
    };
    let relevance = state
        .search_indexes
        .get(&attempt.repository.namespace)?
        .relevance(attempt_id, query)?;
    Some(InventorySearchResultV1 {
        repository,
        attempt,
        snapshot,
        observation,
        packages,
        package_matches_total: 0,
        package_matches_truncated: false,
        freshness,
        relevance,
    })
}

fn bound_packages(mut result: InventorySearchResultV1) -> InventorySearchResultV1 {
    result.package_matches_total = result.packages.len();
    result.package_matches_truncated = result.packages.len() > MAX_PACKAGES_PER_RESULT;
    result.packages.truncate(MAX_PACKAGES_PER_RESULT);
    result
}

fn remove_attempt_ids(state: &mut MemoryState, attempt_ids: &[String]) {
    if attempt_ids.is_empty() {
        return;
    }
    let affected = attempt_ids
        .iter()
        .filter_map(|id| state.attempts.get(id))
        .map(|attempt| attempt.repository.clone())
        .collect::<BTreeSet<_>>();
    for attempt_id in attempt_ids {
        if let Some(attempt) = state.attempts.remove(attempt_id) {
            if let Some(index) = state.search_indexes.get_mut(&attempt.repository.namespace) {
                index.remove(attempt_id);
            }
            if let Some(observation_id) = attempt.observation_id {
                state.observations.remove(&observation_id);
                state.packages.remove(&observation_id);
            }
            if let Some(ids) = state.attempts_by_repository.get_mut(&attempt.repository) {
                ids.remove(attempt_id);
            }
        }
    }
    repair_after_removal(state, &affected);
    state.watermark = state.watermark.saturating_add(1);
    state.cursor_floor = state.watermark;
}

fn repair_after_removal(state: &mut MemoryState, affected: &BTreeSet<RepositoryKeyV1>) {
    let referenced_snapshots = state
        .attempts
        .values()
        .filter_map(|attempt| attempt.snapshot.clone())
        .collect::<BTreeSet<_>>();
    state
        .snapshots
        .retain(|key, _| referenced_snapshots.contains(key));
    for repository in affected {
        let has_attempts = state
            .attempts_by_repository
            .get(repository)
            .is_some_and(|attempts| !attempts.is_empty());
        if has_attempts {
            repair_repository_metadata(state, repository);
            recompute_latest(state, repository);
        } else {
            state.attempts_by_repository.remove(repository);
            state.repositories.remove(repository);
            state.latest.remove(repository);
        }
    }
    state.search_indexes.retain(|_, index| !index.is_empty());
}

fn repair_repository_metadata(state: &mut MemoryState, repository_key: &RepositoryKeyV1) {
    let mut attempt_ids = state
        .attempts_by_repository
        .get(repository_key)
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    attempt_ids.sort_by(|left, right| {
        let left = &state.attempts[left];
        let right = &state.attempts[right];
        left.projection_sequence
            .cmp(&right.projection_sequence)
            .then_with(|| attempt_order(left, right))
    });
    let mut observed_names = BTreeSet::new();
    for attempt_id in &attempt_ids {
        if let Some(attempt) = state.attempts.get_mut(attempt_id) {
            attempt.repository_aliases = observed_names
                .iter()
                .filter(|name| *name != &attempt.normalized_repository_name)
                .cloned()
                .collect();
            observed_names.insert(attempt.normalized_repository_name.clone());
        }
    }
    if let Some(latest) = attempt_ids
        .iter()
        .filter_map(|id| state.attempts.get(id))
        .max_by(|left, right| attempt_order(left, right))
        .cloned()
        && let Some(repository) = state.repositories.get_mut(repository_key)
    {
        repository.full_name = latest.repository_full_name;
        repository.normalized_full_name = latest.normalized_repository_name.clone();
        repository.owner = latest.repository_owner;
        repository.normalized_owner = latest.normalized_repository_owner;
        repository.visibility = latest.repository_visibility;
        repository.aliases = observed_names
            .into_iter()
            .filter(|name| name != &latest.normalized_repository_name)
            .collect();
        repository.first_observed_at = attempt_ids
            .iter()
            .filter_map(|id| state.attempts.get(id))
            .map(|attempt| attempt.completed_at)
            .min()
            .unwrap_or(repository.first_observed_at);
        repository.last_observed_at = attempt_ids
            .iter()
            .filter_map(|id| state.attempts.get(id))
            .map(|attempt| attempt.completed_at)
            .max()
            .unwrap_or(repository.last_observed_at);
    }
    for attempt_id in attempt_ids {
        index_attempt(state, &attempt_id);
    }
}

fn validate_saved_query(
    access: &InventoryAccessV1,
    draft: &SavedInventoryQueryDraftV1,
) -> Result<(), CatalogError> {
    access.validate()?;
    if draft.schema_version != CATALOG_SCHEMA_VERSION_V1 {
        return Err(CatalogError::UnsupportedSchemaVersion(draft.schema_version));
    }
    draft.namespace.validate()?;
    draft.query.validate()?;
    validate_saved_query_id(&draft.query_id)?;
    validate_saved_query_name(&draft.name)?;
    if draft.created_by != access.principal_id {
        return Err(CatalogError::InvalidInput(
            "created_by must match the authenticated principal".to_owned(),
        ));
    }
    if !access.allows(&draft.namespace) {
        return Err(CatalogError::Unauthorized);
    }
    if draft.query.namespace.as_ref() != Some(&draft.namespace) {
        return Err(CatalogError::InvalidInput(
            "saved queries must select exactly their declared namespace".to_owned(),
        ));
    }
    Ok(())
}

fn validate_saved_query_id(value: &str) -> Result<(), CatalogError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CatalogError::InvalidInput(
            "query_id must contain 1-64 ASCII letters, digits, dots, dashes, or underscores"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_saved_query_name(value: &str) -> Result<(), CatalogError> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.chars().count() > 100
        || value.chars().any(char::is_control)
    {
        return Err(CatalogError::InvalidInput(
            "saved query name must contain 1-100 trimmed, printable characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_repository_name(full_name: &str) -> Result<(String, String, String), CatalogError> {
    validate_nonempty("repository_full_name", full_name)?;
    let Some((owner, name)) = full_name.split_once('/') else {
        return Err(CatalogError::InvalidEvidence(
            "repository name must have owner/name form".to_owned(),
        ));
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return Err(CatalogError::InvalidEvidence(
            "repository name must have owner/name form".to_owned(),
        ));
    }
    Ok((
        owner.to_owned(),
        normalize_text(full_name),
        normalize_text(owner),
    ))
}

fn validate_nonempty(field: &str, value: &str) -> Result<(), CatalogError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(CatalogError::InvalidInput(format!(
            "{field} must be non-empty and normalized"
        )));
    }
    Ok(())
}

fn attempt_id(
    repository: &RepositoryKeyV1,
    job_id: &str,
    task_id: &str,
    task_attempt: u32,
) -> Result<String, CatalogError> {
    digest_json(&(
        "repository-attempt-v1",
        repository,
        job_id,
        task_id,
        task_attempt,
    ))
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, CatalogError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        CatalogError::InvalidInput(format!("cannot normalize inventory identity: {error}"))
    })?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn attempt_order(left: &RepositoryAttemptV1, right: &RepositoryAttemptV1) -> Ordering {
    left.completed_at
        .cmp(&right.completed_at)
        .then_with(|| left.task_id.cmp(&right.task_id))
        .then_with(|| left.task_attempt.cmp(&right.task_attempt))
        .then_with(|| left.attempt_id.cmp(&right.attempt_id))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, TimeZone as _};
    use semver::Version;

    use crate::{
        cargo_evidence::{PackageIdentityV1, RecordedRelation},
        coordinator::{ArtifactRefV1, JobId, Sha256Digest, TaskId},
        evidence::{
            DirectRequirementEvidenceV1, EvidenceBundleV1, EvidenceCompletenessV1,
            EvidenceReferenceV1, EvidenceStrengthV1, ExplanationStepKindV1, ExplanationStepV1,
            PackageEvidenceV1, RepositoryEvidenceV1, RepositoryExplanationV1,
            RequirementEvidenceSourceV1,
        },
    };

    use super::super::model::RepositoryRevisionV1;
    use super::*;

    fn time(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, hour, 0, 0).unwrap()
    }

    fn access(profiles: &[&str]) -> InventoryAccessV1 {
        InventoryAccessV1 {
            principal_id: "reader".to_owned(),
            private_credential_profiles: profiles.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn observation(
        namespace: InventoryNamespaceV1,
        repository_id: &str,
        repository: &str,
        completed_at: DateTime<Utc>,
        completeness: EvidenceCompletenessV1,
    ) -> InventoryProjectionInputV1 {
        let target = PackageIdentityV1 {
            name: "fs2".to_owned(),
            version: Version::new(0, 4, 3),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
        };
        let visibility = match &namespace {
            InventoryNamespaceV1::Public => RepositoryVisibilityV1::Public,
            InventoryNamespaceV1::Private { .. } => RepositoryVisibilityV1::Private,
        };
        let revision = RepositoryRevisionV1 {
            commit_sha: format!("commit-{repository_id}-{completed_at}"),
            tree_sha: format!("tree-{repository_id}-{completed_at}"),
            analyzer_profile_digest: "analyzer-v1".to_owned(),
        };
        let evidence = RepositoryEvidenceV1 {
            repository: repository.to_owned(),
            repository_id: Some(repository_id.to_owned()),
            visibility,
            head_committed_at: Some(completed_at - TimeDelta::days(1)),
            completeness,
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
                completeness,
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
            namespace,
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

    fn failed(
        namespace: InventoryNamespaceV1,
        repository_id: &str,
        repository: &str,
        completed_at: DateTime<Utc>,
    ) -> InventoryProjectionInputV1 {
        let visibility = if namespace == InventoryNamespaceV1::Public {
            RepositoryVisibilityV1::Public
        } else {
            RepositoryVisibilityV1::Private
        };
        InventoryProjectionInputV1::FailedAttempt(RepositoryAttemptInputV1 {
            schema_version: CATALOG_SCHEMA_VERSION_V1,
            namespace,
            job_id: JobId(format!("failed-job-{repository_id}")),
            task_id: TaskId(format!("failed-task-{repository_id}")),
            task_attempt: 1,
            repository_id: repository_id.to_owned(),
            repository_full_name: repository.to_owned(),
            visibility,
            revision: None,
            completed_at,
            failure_code: "provider_unavailable".to_owned(),
            failure_message: "provider unavailable".to_owned(),
        })
    }

    #[tokio::test]
    async fn namespace_filtering_precedes_search_and_ranking() {
        let store = InMemoryInventoryStore::new([1; 32]);
        store
            .project(observation(
                InventoryNamespaceV1::Public,
                "1",
                "public/fs2-consumer",
                time(1),
                EvidenceCompletenessV1::Complete,
            ))
            .await
            .unwrap();
        store
            .project(observation(
                InventoryNamespaceV1::Private {
                    credential_profile_id: "company".to_owned(),
                },
                "2",
                "secret/fs2-consumer",
                time(2),
                EvidenceCompletenessV1::Complete,
            ))
            .await
            .unwrap();
        let mut query = InventoryQueryV1::new();
        query.search = Some("fs2-consumer".to_owned());
        let public = store
            .search(&access(&[]), &query, &InventoryPageRequestV1::default())
            .await
            .unwrap();
        assert_eq!(public.items.len(), 1);
        assert_eq!(public.items[0].repository.key.repository_id, "1");

        let all_visible = store
            .search(
                &access(&["company"]),
                &query,
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(all_visible.items.len(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_does_not_present_older_evidence_as_current() {
        let store = InMemoryInventoryStore::new([2; 32]);
        store
            .project(observation(
                InventoryNamespaceV1::Public,
                "1",
                "owner/repo",
                time(1),
                EvidenceCompletenessV1::Complete,
            ))
            .await
            .unwrap();
        store
            .project(failed(
                InventoryNamespaceV1::Public,
                "1",
                "owner/repo",
                time(2),
            ))
            .await
            .unwrap();

        let latest = store
            .search(
                &access(&[]),
                &InventoryQueryV1::new(),
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            latest.items[0].freshness,
            InventoryFreshnessV1::RefreshFailed
        );
        assert!(latest.items[0].observation.is_none());

        let mut evidence_query = InventoryQueryV1::new();
        evidence_query.history = InventoryHistoryModeV1::LatestEvidence;
        let evidence = store
            .search(
                &access(&[]),
                &evidence_query,
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            evidence.items[0].freshness,
            InventoryFreshnessV1::Historical
        );
        assert!(evidence.items[0].observation.is_some());
    }

    #[tokio::test]
    async fn cursor_is_stable_across_projection_and_invalidated_by_retention() {
        let store = InMemoryInventoryStore::new([3; 32]);
        for (id, repository, hour) in [("1", "a/one", 1), ("2", "b/two", 2)] {
            store
                .project(observation(
                    InventoryNamespaceV1::Public,
                    id,
                    repository,
                    time(hour),
                    EvidenceCompletenessV1::Complete,
                ))
                .await
                .unwrap();
        }
        let query = InventoryQueryV1::new();
        let first = store
            .search(
                &access(&[]),
                &query,
                &InventoryPageRequestV1 {
                    limit: Some(1),
                    cursor: None,
                },
            )
            .await
            .unwrap();
        let cursor = first.next_cursor.unwrap();
        let second = store
            .search(
                &access(&[]),
                &query,
                &InventoryPageRequestV1 {
                    limit: Some(1),
                    cursor: Some(cursor.clone()),
                },
            )
            .await
            .unwrap();
        assert_ne!(
            first.items[0].repository.key,
            second.items[0].repository.key
        );

        store
            .project(observation(
                InventoryNamespaceV1::Public,
                "3",
                "c/three",
                time(3),
                EvidenceCompletenessV1::Complete,
            ))
            .await
            .unwrap();
        let continued = store
            .search(
                &access(&[]),
                &query,
                &InventoryPageRequestV1 {
                    limit: Some(1),
                    cursor: Some(cursor.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(continued.items, second.items);
        assert_eq!(continued.index_watermark, first.index_watermark);

        store.retain_since(time(2)).await.unwrap();
        assert_eq!(
            store
                .search(
                    &access(&[]),
                    &query,
                    &InventoryPageRequestV1 {
                        limit: Some(1),
                        cursor: Some(cursor),
                    },
                )
                .await,
            Err(CatalogError::CursorStale)
        );
    }

    #[tokio::test]
    async fn rebuild_is_atomic_and_retention_repairs_latest_state() {
        let store = InMemoryInventoryStore::new([4; 32]);
        let old = observation(
            InventoryNamespaceV1::Public,
            "1",
            "owner/old-name",
            time(1),
            EvidenceCompletenessV1::Complete,
        );
        let recent = observation(
            InventoryNamespaceV1::Public,
            "1",
            "owner/new-name",
            time(2),
            EvidenceCompletenessV1::Complete,
        );
        store.rebuild(vec![recent.clone(), old]).await.unwrap();
        let page = store
            .search(
                &access(&[]),
                &InventoryQueryV1::new(),
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items[0].repository.full_name, "owner/new-name");
        assert!(page.items[0].repository.aliases.contains("owner/old-name"));

        assert_eq!(store.retain_since(time(2)).await.unwrap(), 1);
        let mut history = InventoryQueryV1::new();
        history.history = InventoryHistoryModeV1::Observations;
        let retained = store
            .search(&access(&[]), &history, &InventoryPageRequestV1::default())
            .await
            .unwrap();
        assert_eq!(retained.items.len(), 1);
        assert_eq!(retained.items[0].attempt.completed_at, time(2));
    }

    #[tokio::test]
    async fn artifact_projection_removal_is_digest_bound_and_idempotent() {
        let store = InMemoryInventoryStore::new([6; 32]);
        let input = observation(
            InventoryNamespaceV1::Public,
            "1",
            "owner/repository",
            time(1),
            EvidenceCompletenessV1::Complete,
        );
        let InventoryProjectionInputV1::Observation(envelope) = &input else {
            unreachable!()
        };
        let task_id = envelope.task_id.clone();
        let digest = envelope.artifact.digest.clone();
        store.project(input).await.unwrap();

        let wrong = Sha256Digest::parse("f".repeat(64)).unwrap();
        assert!(matches!(
            store.remove_artifact_projection(&task_id, &wrong).await,
            Err(CatalogError::InvalidEvidence(_))
        ));
        assert_eq!(
            store
                .remove_artifact_projection(&task_id, &digest)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .remove_artifact_projection(&task_id, &digest)
                .await
                .unwrap(),
            0
        );
        assert!(
            store
                .search(
                    &access(&[]),
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
    async fn saved_queries_are_revisioned_and_single_namespace() {
        let store = InMemoryInventoryStore::new([5; 32]);
        let namespace = InventoryNamespaceV1::Private {
            credential_profile_id: "company".to_owned(),
        };
        let mut query = InventoryQueryV1::new();
        query.namespace = Some(namespace.clone());
        let revision = store
            .save_query(
                &access(&["company"]),
                SavedInventoryQueryDraftV1 {
                    schema_version: CATALOG_SCHEMA_VERSION_V1,
                    query_id: "nightly".to_owned(),
                    expected_previous_revision: None,
                    name: "Nightly repositories".to_owned(),
                    namespace,
                    query,
                    created_by: "reader".to_owned(),
                    created_at: time(1),
                },
            )
            .await
            .unwrap();
        assert_eq!(revision.revision, 1);
        assert_eq!(
            store.saved_query(&access(&[]), "nightly", None).await,
            Err(CatalogError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn package_presence_in_each_result_is_bounded() {
        let store = InMemoryInventoryStore::new([6; 32]);
        let mut input = observation(
            InventoryNamespaceV1::Public,
            "1",
            "owner/repo",
            time(1),
            EvidenceCompletenessV1::Complete,
        );
        let InventoryProjectionInputV1::Observation(envelope) = &mut input else {
            unreachable!();
        };
        let repository = envelope.evidence.repositories.first_mut().unwrap();
        repository
            .packages
            .extend((0..150).map(|index| PackageEvidenceV1 {
                package: PackageIdentityV1 {
                    name: format!("package-{index:03}"),
                    version: Version::new(1, 0, 0),
                    source: None,
                },
                license_expression: None,
            }));
        store.project(input).await.unwrap();
        let page = store
            .search(
                &access(&[]),
                &InventoryQueryV1::new(),
                &InventoryPageRequestV1::default(),
            )
            .await
            .unwrap();
        assert_eq!(page.items[0].packages.len(), MAX_PACKAGES_PER_RESULT);
        assert_eq!(page.items[0].package_matches_total, 152);
        assert!(page.items[0].package_matches_truncated);
    }
}
