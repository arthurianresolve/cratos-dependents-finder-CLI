//! Indexed durable search for the Turso inventory Adapter.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use semver::Version;

use super::{
    cursor::{CursorSigner, DecodedCursorV1, InventorySortKeyV1},
    model::{
        CATALOG_SCHEMA_VERSION_V1, CatalogError, InventoryAccessV1, InventoryFreshnessV1,
        InventoryHistoryModeV1, InventoryMatchModeV1, InventoryNamespaceV1, InventoryPageRequestV1,
        InventoryPageV1, InventoryQueryV1, InventoryRepositoryV1, InventorySearchFieldV1,
        InventorySearchResultV1, InventorySortV1, InventorySourceFilterV1, MAX_PACKAGES_PER_RESULT,
        RepositoryAttemptV1, RepositorySnapshotV1, TRIGRAM_INDEX_VERSION_V1, TargetObservationV1,
    },
    search::{compare_results, sort_key},
};

const MIN_FUZZY_SCORE: i64 = 250_000;
const SEARCH_FIELD_REPOSITORY: &str = "repository";
const SEARCH_FIELD_PACKAGE: &str = "package";
const INDEX_BATCH_SIZE: usize = 16;
const MAX_DYNAMIC_BINDINGS: usize = 900;
const HYDRATION_BINDINGS_PER_CANDIDATE: usize = 3;
const MAX_CANDIDATES_PER_HYDRATION: usize =
    (MAX_DYNAMIC_BINDINGS - 1) / HYDRATION_BINDINGS_PER_CANDIDATE;
const ATTEMPT_BINDINGS_PER_CANDIDATE: usize = 4;
const MAX_ATTEMPT_CANDIDATES_PER_HYDRATION: usize =
    MAX_DYNAMIC_BINDINGS / ATTEMPT_BINDINGS_PER_CANDIDATE;
pub(crate) const REBUILD_SEARCH_DOCUMENT_BATCH_SIZE: usize = 4_096;
pub(crate) const REBUILD_SEARCH_WORKING_SET_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn rebuild_search_batch_should_flush(
    document_count: usize,
    estimated_working_set: usize,
    next_document_working_set: usize,
) -> bool {
    document_count > 0
        && (document_count == REBUILD_SEARCH_DOCUMENT_BATCH_SIZE
            || estimated_working_set.saturating_add(next_document_working_set)
                > REBUILD_SEARCH_WORKING_SET_BYTES)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NamespaceQueryKey {
    kind: &'static str,
    credential_profile_id: String,
}

impl From<&InventoryNamespaceV1> for NamespaceQueryKey {
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

#[derive(Clone, Debug)]
struct Candidate {
    namespace_kind: String,
    credential_profile_id: String,
    attempt_id: String,
    relevance: u32,
    freshness: InventoryFreshnessV1,
    has_observation: bool,
}

pub(super) async fn search_with_candidate_observer<Observer>(
    connection: &turso::Connection,
    signer: &CursorSigner,
    access: &InventoryAccessV1,
    query: &InventoryQueryV1,
    page: &InventoryPageRequestV1,
    after_candidates: Observer,
) -> Result<InventoryPageV1, CatalogError>
where
    Observer: FnOnce(&turso::Connection) -> Result<(), CatalogError>,
{
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

    // Decode the principal/scope-bound cursor before touching inventory rows.
    let cursor = page
        .cursor
        .as_deref()
        .map(|encoded| signer.decode(encoded, access, query))
        .transpose()?;
    let current_watermark = metadata_u64(connection, "watermark").await?;
    let cursor_floor = metadata_u64(connection, "cursor_floor").await?;
    let snapshot_watermark = cursor
        .as_ref()
        .map_or(current_watermark, |cursor| cursor.index_watermark);
    if snapshot_watermark > current_watermark || snapshot_watermark < cursor_floor {
        return Err(CatalogError::CursorStale);
    }

    let namespaces = authorized_namespaces(access, query);
    let use_latest = query.as_of.is_none()
        && snapshot_watermark == current_watermark
        && query.history != InventoryHistoryModeV1::Observations;
    let sql = CandidateSql::build(
        &namespaces,
        query,
        cursor.as_ref(),
        snapshot_watermark,
        use_latest,
        limit.saturating_add(1),
    )?;
    let candidates = load_candidates(connection, sql).await?;
    after_candidates(connection)?;
    let mut results = hydrate_candidates(connection, &candidates).await?;
    results.sort_by(|left, right| compare_results(left, right, query.sort));

    let has_more = results.len() > limit;
    results.truncate(limit);
    let next_cursor = has_more
        .then(|| {
            results
                .last()
                .map(|result| signer.encode(access, query, snapshot_watermark, sort_key(result)))
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

fn authorized_namespaces(
    access: &InventoryAccessV1,
    query: &InventoryQueryV1,
) -> BTreeSet<NamespaceQueryKey> {
    if let Some(namespace) = &query.namespace {
        return BTreeSet::from([NamespaceQueryKey::from(namespace)]);
    }
    std::iter::once(NamespaceQueryKey::from(&InventoryNamespaceV1::Public))
        .chain(access.private_credential_profiles.iter().map(|profile| {
            NamespaceQueryKey::from(&InventoryNamespaceV1::Private {
                credential_profile_id: profile.clone(),
            })
        }))
        .collect()
}

struct CandidateSql {
    statement: String,
    params: Vec<turso::Value>,
}

struct SqlBuilder {
    statement: String,
    params: Vec<turso::Value>,
}

impl SqlBuilder {
    fn new() -> Self {
        Self {
            statement: String::new(),
            params: Vec::new(),
        }
    }

    fn bind(&mut self, value: impl Into<turso::Value>) {
        self.params.push(value.into());
        self.statement.push('?');
    }

    fn bind_json<T: serde::Serialize>(&mut self, value: &T) -> Result<(), CatalogError> {
        self.params.push(turso::Value::Text(
            serde_json::to_string(value).map_err(unavailable)?,
        ));
        self.statement.push('?');
        Ok(())
    }

    fn push(&mut self, value: &str) {
        self.statement.push_str(value);
    }

    fn finish(self) -> CandidateSql {
        CandidateSql {
            statement: self.statement,
            params: self.params,
        }
    }
}

impl CandidateSql {
    fn build(
        namespaces: &BTreeSet<NamespaceQueryKey>,
        query: &InventoryQueryV1,
        cursor: Option<&DecodedCursorV1>,
        watermark: u64,
        use_latest: bool,
        capacity: usize,
    ) -> Result<Self, CatalogError> {
        if use_latest && let Some(namespace) = unfiltered_latest_repository_namespace(query) {
            return Self::build_latest_repository_page(namespace, cursor, capacity);
        }

        let mut sql = SqlBuilder::new();
        push_authorized_cte(&mut sql, namespaces);
        if use_latest {
            push_latest_selection(&mut sql, query.history, watermark)?;
        } else {
            push_historical_selection(&mut sql, query, watermark)?;
        }
        push_filtered_ctes(&mut sql, query)?;
        push_ranked_ctes(&mut sql, query)?;
        sql.push(
            " SELECT namespace_kind, credential_profile_id, attempt_id, relevance, freshness,\n\
                     observation_id IS NOT NULL AS has_observation\n\
                   FROM ranked WHERE 1 = 1",
        );
        if let Some(cursor) = cursor {
            push_keyset(&mut sql, &cursor.last, query.sort);
        }
        push_order(&mut sql, query.sort);
        sql.push(" LIMIT ");
        sql.bind(to_i64(capacity as u64)?);
        Ok(sql.finish())
    }

    fn build_latest_repository_page(
        namespace: &InventoryNamespaceV1,
        cursor: Option<&DecodedCursorV1>,
        capacity: usize,
    ) -> Result<Self, CatalogError> {
        let namespace = NamespaceQueryKey::from(namespace);
        let mut sql = SqlBuilder::new();
        sql.push(
            "SELECT attempts.namespace_kind, attempts.credential_profile_id,\n\
                    attempts.attempt_id, 0 AS relevance,\n\
                    CASE\n\
                      WHEN attempts.status = 'complete' THEN 'current'\n\
                      WHEN attempts.status = 'partial' THEN 'refresh_partial'\n\
                      ELSE 'refresh_failed'\n\
                    END AS freshness,\n\
                    attempts.observation_id IS NOT NULL AS has_observation\n\
               FROM catalog_attempts AS attempts\n\
                    INDEXED BY catalog_attempts_search_order\n\
               JOIN catalog_latest AS latest\n\
                 ON latest.namespace_kind = attempts.namespace_kind\n\
                AND latest.credential_profile_id = attempts.credential_profile_id\n\
                AND latest.repository_id = attempts.repository_id\n\
                AND latest.latest_attempt_id = attempts.attempt_id\n\
              WHERE attempts.namespace_kind = ",
        );
        sql.bind(namespace.kind.to_owned());
        sql.push(" AND attempts.credential_profile_id = ");
        sql.bind(namespace.credential_profile_id);
        if let Some(cursor) = cursor {
            // This predicate is implied by the full keyset condition below, but
            // gives SQLite the leading range bound it needs to seek within the
            // repository-order index instead of rescanning from the first row.
            sql.push(" AND attempts.normalized_repository_name >= ");
            sql.bind(cursor.last.normalized_repository.clone());
            push_keyset(&mut sql, &cursor.last, InventorySortV1::RepositoryAsc);
        }
        push_order(&mut sql, InventorySortV1::RepositoryAsc);
        sql.push(" LIMIT ");
        sql.bind(to_i64(capacity as u64)?);
        Ok(sql.finish())
    }
}

fn unfiltered_latest_repository_namespace(
    query: &InventoryQueryV1,
) -> Option<&InventoryNamespaceV1> {
    let namespace = query.namespace.as_ref()?;
    let mut expected = InventoryQueryV1::new();
    expected.namespace = Some(namespace.clone());
    expected.sort = InventorySortV1::RepositoryAsc;
    (query == &expected).then_some(namespace)
}

fn push_authorized_cte(sql: &mut SqlBuilder, namespaces: &BTreeSet<NamespaceQueryKey>) {
    sql.push("WITH authorized(namespace_kind, credential_profile_id) AS (VALUES ");
    for (index, namespace) in namespaces.iter().enumerate() {
        if index > 0 {
            sql.push(",");
        }
        sql.push("(");
        sql.bind(namespace.kind.to_owned());
        sql.push(",");
        sql.bind(namespace.credential_profile_id.clone());
        sql.push(")");
    }
    sql.push(")");
}

fn push_latest_selection(
    sql: &mut SqlBuilder,
    history: InventoryHistoryModeV1,
    watermark: u64,
) -> Result<(), CatalogError> {
    let pointer = match history {
        InventoryHistoryModeV1::LatestAttempt => "attempts.attempt_id = latest.latest_attempt_id",
        InventoryHistoryModeV1::LatestEvidence => {
            "attempts.observation_id = latest.latest_evidence_id"
        }
        InventoryHistoryModeV1::LastComplete => {
            "attempts.observation_id = latest.latest_complete_evidence_id"
        }
        InventoryHistoryModeV1::Observations => return Err(CatalogError::StoreUnavailable),
    };
    sql.push(
        ", selected AS (\n\
         SELECT attempts.*, latest.latest_attempt_id\n\
           FROM authorized\n\
           JOIN catalog_latest AS latest\n\
             ON latest.namespace_kind = authorized.namespace_kind\n\
            AND latest.credential_profile_id = authorized.credential_profile_id\n\
           JOIN catalog_attempts AS attempts\n\
             ON attempts.namespace_kind = latest.namespace_kind\n\
            AND attempts.credential_profile_id = latest.credential_profile_id\n\
            AND attempts.repository_id = latest.repository_id\n\
            AND ",
    );
    sql.push(pointer);
    sql.push(" WHERE attempts.projection_sequence <= ");
    sql.bind(to_i64(watermark)?);
    sql.push(")");
    Ok(())
}

fn push_historical_selection(
    sql: &mut SqlBuilder,
    query: &InventoryQueryV1,
    watermark: u64,
) -> Result<(), CatalogError> {
    sql.push(
        ", eligible AS (\n\
         SELECT attempts.*, observations.completeness,\n\
                FIRST_VALUE(attempts.attempt_id) OVER repository_order AS latest_attempt_id,\n\
                ROW_NUMBER() OVER repository_order AS attempt_rank,\n\
                SUM(CASE WHEN attempts.observation_id IS NOT NULL THEN 1 ELSE 0 END)\n\
                    OVER repository_order AS evidence_rank,\n\
                SUM(CASE WHEN observations.completeness = 'complete' THEN 1 ELSE 0 END)\n\
                    OVER repository_order AS complete_rank\n\
           FROM authorized\n\
           JOIN catalog_attempts AS attempts\n\
             ON attempts.namespace_kind = authorized.namespace_kind\n\
            AND attempts.credential_profile_id = authorized.credential_profile_id\n\
           LEFT JOIN catalog_observations AS observations\n\
             ON observations.namespace_kind = attempts.namespace_kind\n\
            AND observations.credential_profile_id = attempts.credential_profile_id\n\
            AND observations.observation_id = attempts.observation_id\n\
          WHERE attempts.projection_sequence <= ",
    );
    sql.bind(to_i64(watermark)?);
    if let Some(as_of) = query.as_of {
        sql.push(" AND attempts.completed_at <= ");
        sql.bind(as_of.to_rfc3339());
    }
    sql.push(
        " WINDOW repository_order AS (\n\
              PARTITION BY attempts.namespace_kind, attempts.credential_profile_id,\n\
                           attempts.repository_id\n\
              ORDER BY attempts.completed_at DESC, attempts.task_id DESC,\n\
                       attempts.task_attempt DESC, attempts.attempt_id DESC\n\
              ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)\n\
         ), selected AS (SELECT * FROM eligible WHERE ",
    );
    match query.history {
        InventoryHistoryModeV1::LatestAttempt => sql.push("attempt_rank = 1"),
        InventoryHistoryModeV1::LatestEvidence => {
            sql.push("observation_id IS NOT NULL AND evidence_rank = 1")
        }
        InventoryHistoryModeV1::LastComplete => {
            sql.push("completeness = 'complete' AND complete_rank = 1")
        }
        InventoryHistoryModeV1::Observations => sql.push("1 = 1"),
    }
    sql.push(")");
    Ok(())
}

fn push_filtered_ctes(sql: &mut SqlBuilder, query: &InventoryQueryV1) -> Result<(), CatalogError> {
    sql.push(
        ", enriched AS (\n\
         SELECT selected.namespace_kind, selected.credential_profile_id,\n\
                selected.attempt_id, selected.repository_id, selected.observation_id,\n\
                selected.normalized_repository_name, selected.normalized_repository_owner,\n\
                selected.repository_visibility, selected.job_id, selected.completed_at,\n\
                selected.status, selected.snapshot_commit_sha, selected.snapshot_tree_sha,\n\
                selected.snapshot_analyzer_profile_digest, selected.latest_attempt_id,\n\
                observations.normalized_target_name, observations.target_version,\n\
                observations.target_source, observations.recorded_relation,\n\
                observations.msrv_sort_key, observations.strength,\n\
                observations.completeness AS observation_completeness,\n\
                CASE\n\
                  WHEN selected.attempt_id <> selected.latest_attempt_id THEN 'historical'\n\
                  WHEN selected.status = 'complete' THEN 'current'\n\
                  WHEN selected.status = 'partial' THEN 'refresh_partial'\n\
                  ELSE 'refresh_failed'\n\
                END AS freshness\n\
           FROM selected\n\
           LEFT JOIN catalog_observations AS observations\n\
             ON observations.namespace_kind = selected.namespace_kind\n\
            AND observations.credential_profile_id = selected.credential_profile_id\n\
            AND observations.observation_id = selected.observation_id\n\
         ), filtered AS (SELECT * FROM enriched WHERE 1 = 1",
    );

    if !query.repository_ids.is_empty() {
        let values = query.repository_ids.iter().collect::<Vec<_>>();
        sql.push(" AND repository_id IN (SELECT value FROM json_each(");
        sql.bind_json(&values)?;
        sql.push("))");
    }
    if let Some(owner) = &query.repository_owner {
        sql.push(" AND normalized_repository_owner = ");
        sql.bind(normalize_text(owner));
    }
    push_enum_set_filter(
        sql,
        "repository_visibility",
        query.repository_visibilities.iter(),
    )?;
    if !query.job_ids.is_empty() {
        let values = query
            .job_ids
            .iter()
            .map(|value| value.0.as_str())
            .collect::<Vec<_>>();
        sql.push(" AND job_id IN (SELECT value FROM json_each(");
        sql.bind_json(&values)?;
        sql.push("))");
    }
    if let Some(after) = query.observed_after {
        sql.push(" AND completed_at >= ");
        sql.bind(after.to_rfc3339());
    }
    if let Some(before) = query.observed_before {
        sql.push(" AND completed_at <= ");
        sql.bind(before.to_rfc3339());
    }
    push_enum_set_filter(sql, "freshness", query.freshness.iter())?;

    if has_evidence_filter(query) {
        sql.push(" AND observation_id IS NOT NULL");
    }
    if let Some(name) = &query.target_name {
        sql.push(" AND normalized_target_name = ");
        sql.bind(normalize_text(name));
    }
    if let Some(version) = &query.target_version {
        sql.push(" AND target_version = ");
        sql.bind(version.to_string());
    }
    push_source_filter(sql, "target_source", &query.target_source);
    push_enum_slice_filter(sql, "recorded_relation", &query.recorded_relations)?;
    if let Some(minimum) = &query.min_msrv {
        sql.push(" AND msrv_sort_key >= ");
        sql.bind(semver_sort_key(minimum));
    }
    if let Some(maximum) = &query.max_msrv {
        sql.push(" AND msrv_sort_key <= ");
        sql.bind(semver_sort_key(maximum));
    }
    push_enum_set_filter(sql, "strength", query.strengths.iter())?;
    push_enum_set_filter(sql, "observation_completeness", query.completeness.iter())?;
    if let Some(commit_sha) = &query.commit_sha {
        sql.push(" AND snapshot_commit_sha = ");
        sql.bind(commit_sha.clone());
    }
    if let Some(tree_sha) = &query.tree_sha {
        sql.push(" AND snapshot_tree_sha = ");
        sql.bind(tree_sha.clone());
    }
    if let Some(digest) = &query.analyzer_profile_digest {
        sql.push(" AND snapshot_analyzer_profile_digest = ");
        sql.bind(digest.clone());
    }
    push_requirement_filter(sql, query)?;
    push_package_filter(sql, query)?;
    if !query.limitation_codes.is_empty() {
        let codes = query.limitation_codes.iter().collect::<Vec<_>>();
        sql.push(" AND NOT EXISTS (SELECT 1 FROM json_each(");
        sql.bind_json(&codes)?;
        sql.push(
            ") AS requested WHERE NOT EXISTS (\n\
                SELECT 1 FROM catalog_limitations AS limitations\n\
                 WHERE limitations.namespace_kind = enriched.namespace_kind\n\
                   AND limitations.credential_profile_id = enriched.credential_profile_id\n\
                   AND limitations.observation_id = enriched.observation_id\n\
                   AND limitations.code = requested.value))",
        );
    }
    sql.push(")");
    Ok(())
}

fn push_enum_set_filter<'a, T>(
    sql: &mut SqlBuilder,
    column: &str,
    values: impl Iterator<Item = &'a T>,
) -> Result<(), CatalogError>
where
    T: serde::Serialize + 'a,
{
    let values = values.map(enum_text).collect::<Result<Vec<_>, _>>()?;
    if !values.is_empty() {
        sql.push(" AND ");
        sql.push(column);
        sql.push(" IN (SELECT value FROM json_each(");
        sql.bind_json(&values)?;
        sql.push("))");
    }
    Ok(())
}

fn push_enum_slice_filter<T: serde::Serialize>(
    sql: &mut SqlBuilder,
    column: &str,
    values: &[T],
) -> Result<(), CatalogError> {
    push_enum_set_filter(sql, column, values.iter())
}

fn push_source_filter(sql: &mut SqlBuilder, column: &str, filter: &InventorySourceFilterV1) {
    match filter {
        InventorySourceFilterV1::Any => {}
        InventorySourceFilterV1::Local => {
            sql.push(" AND ");
            sql.push(column);
            sql.push(" IS NULL");
        }
        InventorySourceFilterV1::Exact(value) => {
            sql.push(" AND ");
            sql.push(column);
            sql.push(" = ");
            sql.bind(value.clone());
        }
    }
}

fn push_requirement_filter(
    sql: &mut SqlBuilder,
    query: &InventoryQueryV1,
) -> Result<(), CatalogError> {
    if query.requirement.is_none()
        && query.requirement_sources.is_empty()
        && query.requirement_accepts_target.is_none()
        && query.explicit_exact_pin.is_none()
    {
        return Ok(());
    }
    sql.push(
        " AND EXISTS (SELECT 1 FROM catalog_requirements AS requirements\n\
          WHERE requirements.namespace_kind = enriched.namespace_kind\n\
            AND requirements.credential_profile_id = enriched.credential_profile_id\n\
            AND requirements.observation_id = enriched.observation_id",
    );
    if let Some(requirement) = &query.requirement {
        sql.push(" AND requirements.requirement = ");
        sql.bind(requirement.clone());
    }
    if !query.requirement_sources.is_empty() {
        let values = query
            .requirement_sources
            .iter()
            .map(enum_text)
            .collect::<Result<Vec<_>, _>>()?;
        sql.push(" AND requirements.source IN (SELECT value FROM json_each(");
        sql.bind_json(&values)?;
        sql.push("))");
    }
    if let Some(accepts) = query.requirement_accepts_target {
        sql.push(" AND requirements.accepts_target = ");
        sql.bind(if accepts { 1_i64 } else { 0 });
    }
    if let Some(exact) = query.explicit_exact_pin {
        sql.push(" AND requirements.explicit_exact_pin = ");
        sql.bind(if exact { 1_i64 } else { 0 });
    }
    sql.push(")");
    Ok(())
}

fn push_package_filter(sql: &mut SqlBuilder, query: &InventoryQueryV1) -> Result<(), CatalogError> {
    if query.package_name.is_none()
        && query.package_version.is_none()
        && query.package_source == InventorySourceFilterV1::Any
    {
        return Ok(());
    }
    sql.push(
        " AND EXISTS (SELECT 1 FROM catalog_packages AS packages\n\
          WHERE packages.namespace_kind = enriched.namespace_kind\n\
            AND packages.credential_profile_id = enriched.credential_profile_id\n\
            AND packages.observation_id = enriched.observation_id",
    );
    if let Some(name) = &query.package_name {
        sql.push(" AND packages.normalized_package_name = ");
        sql.bind(normalize_text(name));
    }
    if let Some(version) = &query.package_version {
        sql.push(" AND packages.package_version = ");
        sql.bind(version.to_string());
    }
    match &query.package_source {
        InventorySourceFilterV1::Any => {}
        InventorySourceFilterV1::Local => sql.push(" AND packages.package_source IS NULL"),
        InventorySourceFilterV1::Exact(value) => {
            sql.push(" AND packages.package_source = ");
            sql.bind(value.clone());
        }
    }
    sql.push(")");
    Ok(())
}

fn push_ranked_ctes(sql: &mut SqlBuilder, query: &InventoryQueryV1) -> Result<(), CatalogError> {
    let Some(search) = query.search.as_deref() else {
        sql.push(", ranked AS (SELECT filtered.*, 0 AS relevance FROM filtered)");
        return Ok(());
    };
    let search = normalize_text(search);
    let field_predicate = match query.search_field {
        InventorySearchFieldV1::Any => "1 = 1",
        InventorySearchFieldV1::Repository => "terms.field = 'repository'",
        InventorySearchFieldV1::Package => "terms.field = 'package'",
    };
    if query.match_mode == InventoryMatchModeV1::Fuzzy && search.chars().count() >= 3 {
        let terms_field_predicate = match query.search_field {
            InventorySearchFieldV1::Any => "1 = 1",
            InventorySearchFieldV1::Repository => "terms.field = 'repository'",
            InventorySearchFieldV1::Package => "terms.field = 'package'",
        };
        let trigrams = trigrams(&search);
        sql.push(", query_trigrams(trigram) AS (VALUES ");
        for (index, trigram) in trigrams.iter().enumerate() {
            if index > 0 {
                sql.push(",");
            }
            sql.push("(");
            sql.bind(trigram.clone());
            sql.push(")");
        }
        sql.push(
            "), term_intersections AS (\n\
             SELECT terms.namespace_kind, terms.credential_profile_id,\n\
                    terms.attempt_id, terms.field, terms.term,\n\
                    COUNT(query_trigrams.trigram) AS intersection_count\n\
               FROM query_trigrams\n\
               CROSS JOIN authorized\n\
               CROSS JOIN catalog_search_terms AS terms\n\
               CROSS JOIN json_each(terms.trigrams_json) AS term_trigrams\n\
              WHERE terms.namespace_kind = authorized.namespace_kind\n\
                AND terms.credential_profile_id = authorized.credential_profile_id\n\
                AND term_trigrams.value = query_trigrams.trigram AND ",
        );
        sql.push(terms_field_predicate);
        sql.push(
            " GROUP BY terms.namespace_kind, terms.credential_profile_id,\n\
                       terms.attempt_id, terms.field, terms.term),\n\
             search_scores AS (\n\
             SELECT intersections.namespace_kind,\n\
                    intersections.credential_profile_id, intersections.attempt_id,\n\
                    MAX(intersections.intersection_count * 1000000 /\n\
                        (terms.trigram_count + ",
        );
        sql.bind(to_i64(trigrams.len() as u64)?);
        sql.push(
            " - intersections.intersection_count)) AS relevance\n\
               FROM term_intersections AS intersections\n\
               JOIN catalog_search_terms AS terms\n\
                 ON terms.namespace_kind = intersections.namespace_kind\n\
                AND terms.credential_profile_id = intersections.credential_profile_id\n\
                AND terms.attempt_id = intersections.attempt_id\n\
                AND terms.field = intersections.field\n\
                AND terms.term = intersections.term\n\
              GROUP BY intersections.namespace_kind,\n\
                       intersections.credential_profile_id, intersections.attempt_id),\n\
             ranked AS (SELECT filtered.*, search_scores.relevance\n\
               FROM search_scores JOIN filtered USING\n\
                    (namespace_kind, credential_profile_id, attempt_id)\n\
               WHERE search_scores.relevance >= ",
        );
        sql.bind(MIN_FUZZY_SCORE);
        sql.push(")");
        return Ok(());
    }

    if query.match_mode == InventoryMatchModeV1::Substring && search.chars().count() >= 3 {
        sql.push(
            ", search_scores AS (\n\
             SELECT terms.namespace_kind, terms.credential_profile_id, terms.attempt_id,\n\
                    MAX(MAX(0, 2000000 - terms.term_byte_len)) AS relevance\n\
               FROM authorized\n\
               JOIN catalog_search_terms AS terms\n\
                 ON terms.namespace_kind = authorized.namespace_kind\n\
                AND terms.credential_profile_id = authorized.credential_profile_id\n\
              WHERE ",
        );
        sql.push(field_predicate);
        sql.push(" AND instr(terms.term, ");
        sql.bind(search);
        sql.push(
            ") > 0\n\
              GROUP BY terms.namespace_kind, terms.credential_profile_id, terms.attempt_id),\n\
             ranked AS (SELECT filtered.*, search_scores.relevance FROM search_scores\n\
              JOIN filtered USING (namespace_kind, credential_profile_id, attempt_id))",
        );
        return Ok(());
    }

    sql.push(
        ", search_scores AS (\n\
         SELECT terms.namespace_kind, terms.credential_profile_id, terms.attempt_id, MAX(",
    );
    match query.match_mode {
        InventoryMatchModeV1::Exact => sql.push("4000000"),
        InventoryMatchModeV1::Prefix => sql.push("MAX(0, 3000000 - terms.term_byte_len)"),
        InventoryMatchModeV1::Substring => sql.push("MAX(0, 2000000 - terms.term_byte_len)"),
        InventoryMatchModeV1::Fuzzy => sql.push("500000"),
    }
    sql.push(
        ") AS relevance FROM authorized JOIN catalog_search_terms AS terms\n\
          ON terms.namespace_kind = authorized.namespace_kind\n\
         AND terms.credential_profile_id = authorized.credential_profile_id WHERE ",
    );
    sql.push(field_predicate);
    match query.match_mode {
        InventoryMatchModeV1::Exact => {
            sql.push(" AND terms.term = ");
            sql.bind(search);
        }
        InventoryMatchModeV1::Prefix => {
            sql.push(" AND terms.term >= ");
            sql.bind(search.clone());
            if let Some(upper_bound) = prefix_upper_bound(&search) {
                sql.push(" AND terms.term < ");
                sql.bind(upper_bound);
            }
            sql.push(" AND instr(terms.term, ");
            sql.bind(search);
            sql.push(") = 1");
        }
        InventoryMatchModeV1::Substring | InventoryMatchModeV1::Fuzzy => {
            sql.push(" AND instr(terms.term, ");
            sql.bind(search);
            sql.push(") > 0");
        }
    }
    sql.push(
        " GROUP BY terms.namespace_kind, terms.credential_profile_id, terms.attempt_id),\n\
         ranked AS (SELECT filtered.*, search_scores.relevance FROM search_scores\n\
          JOIN filtered USING (namespace_kind, credential_profile_id, attempt_id))",
    );
    Ok(())
}

fn push_keyset(sql: &mut SqlBuilder, key: &InventorySortKeyV1, sort: InventorySortV1) {
    sql.push(" AND (");
    match sort {
        InventorySortV1::Relevance => {
            sql.push("relevance < ");
            sql.bind(i64::from(key.relevance));
            sql.push(" OR (relevance = ");
            sql.bind(i64::from(key.relevance));
            sql.push(" AND (normalized_repository_name > ");
            sql.bind(key.normalized_repository.clone());
            sql.push(" OR (normalized_repository_name = ");
            sql.bind(key.normalized_repository.clone());
            push_desc_time_and_id(sql, key);
            sql.push(")))");
        }
        InventorySortV1::RepositoryAsc => {
            sql.push("normalized_repository_name > ");
            sql.bind(key.normalized_repository.clone());
            sql.push(" OR (normalized_repository_name = ");
            sql.bind(key.normalized_repository.clone());
            push_desc_time_and_id(sql, key);
            sql.push(")");
        }
        InventorySortV1::ObservedAtDesc => {
            sql.push("completed_at < ");
            sql.bind(key.completed_at.to_rfc3339());
            sql.push(" OR (completed_at = ");
            sql.bind(key.completed_at.to_rfc3339());
            sql.push(" AND (normalized_repository_name > ");
            sql.bind(key.normalized_repository.clone());
            sql.push(" OR (normalized_repository_name = ");
            sql.bind(key.normalized_repository.clone());
            sql.push(" AND attempt_id > ");
            sql.bind(key.attempt_id.clone());
            sql.push(")))");
        }
        InventorySortV1::MsrvAsc => match &key.msrv {
            Some(version) => {
                let version = semver_sort_key(version);
                sql.push("msrv_sort_key IS NULL OR msrv_sort_key > ");
                sql.bind(version.clone());
                sql.push(" OR (msrv_sort_key = ");
                sql.bind(version);
                sql.push(" AND (normalized_repository_name > ");
                sql.bind(key.normalized_repository.clone());
                sql.push(" OR (normalized_repository_name = ");
                sql.bind(key.normalized_repository.clone());
                push_desc_time_and_id(sql, key);
                sql.push("))))");
            }
            None => {
                sql.push("msrv_sort_key IS NULL AND (normalized_repository_name > ");
                sql.bind(key.normalized_repository.clone());
                sql.push(" OR (normalized_repository_name = ");
                sql.bind(key.normalized_repository.clone());
                push_desc_time_and_id(sql, key);
                sql.push("))");
            }
        },
    }
    sql.push(")");
}

fn push_desc_time_and_id(sql: &mut SqlBuilder, key: &InventorySortKeyV1) {
    sql.push(" AND (completed_at < ");
    sql.bind(key.completed_at.to_rfc3339());
    sql.push(" OR (completed_at = ");
    sql.bind(key.completed_at.to_rfc3339());
    sql.push(" AND attempt_id > ");
    sql.bind(key.attempt_id.clone());
    sql.push("))");
}

fn push_order(sql: &mut SqlBuilder, sort: InventorySortV1) {
    match sort {
        InventorySortV1::Relevance => sql.push(
            " ORDER BY relevance DESC, normalized_repository_name ASC,\n\
             completed_at DESC, attempt_id ASC",
        ),
        InventorySortV1::RepositoryAsc => {
            sql.push(" ORDER BY normalized_repository_name ASC, completed_at DESC, attempt_id ASC")
        }
        InventorySortV1::ObservedAtDesc => {
            sql.push(" ORDER BY completed_at DESC, normalized_repository_name ASC, attempt_id ASC")
        }
        InventorySortV1::MsrvAsc => sql.push(
            " ORDER BY msrv_sort_key IS NULL ASC, msrv_sort_key ASC,\n\
             normalized_repository_name ASC, completed_at DESC, attempt_id ASC",
        ),
    }
}

async fn load_candidates(
    connection: &turso::Connection,
    sql: CandidateSql,
) -> Result<Vec<Candidate>, CatalogError> {
    let mut rows = connection
        .query(&sql.statement, sql.params)
        .await
        .map_err(unavailable)?;
    let mut candidates = Vec::new();
    while let Some(row) = rows.next().await.map_err(unavailable)? {
        let relevance: i64 = row.get(3).map_err(unavailable)?;
        candidates.push(Candidate {
            namespace_kind: row.get(0).map_err(unavailable)?,
            credential_profile_id: row.get(1).map_err(unavailable)?,
            attempt_id: row.get(2).map_err(unavailable)?,
            relevance: u32::try_from(relevance).map_err(unavailable)?,
            freshness: parse_freshness(&row.get::<String>(4).map_err(unavailable)?)?,
            has_observation: row.get::<i64>(5).map_err(unavailable)? != 0,
        });
    }
    Ok(candidates)
}

async fn hydrate_candidates(
    connection: &turso::Connection,
    candidates: &[Candidate],
) -> Result<Vec<InventorySearchResultV1>, CatalogError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut attempt_only = Vec::new();
    let mut observed = Vec::new();
    for candidate in candidates {
        if candidate.has_observation {
            observed.push(candidate.clone());
        } else {
            attempt_only.push(candidate.clone());
        }
    }
    let mut results = Vec::with_capacity(candidates.len());
    results.extend(hydrate_attempt_candidates(connection, &attempt_only).await?);
    for candidates in observed.chunks(MAX_CANDIDATES_PER_HYDRATION) {
        results.extend(hydrate_candidate_batch(connection, candidates).await?);
    }
    Ok(results)
}

async fn hydrate_attempt_candidates(
    connection: &turso::Connection,
    candidates: &[Candidate],
) -> Result<Vec<InventorySearchResultV1>, CatalogError> {
    let mut results = Vec::with_capacity(candidates.len());
    for candidates in candidates.chunks(MAX_ATTEMPT_CANDIDATES_PER_HYDRATION) {
        results.extend(hydrate_attempt_candidate_batch(connection, candidates).await?);
    }
    Ok(results)
}

async fn hydrate_attempt_candidate_batch(
    connection: &turso::Connection,
    candidates: &[Candidate],
) -> Result<Vec<InventorySearchResultV1>, CatalogError> {
    let mut sql = requested_candidates_sql(candidates)?;
    sql.push(
        "), requested_attempts AS (\n\
         SELECT requested.request_ordinal, attempts.attempt_id, attempts.attempt_json,\n\
                attempts.snapshot_commit_sha, attempts.snapshot_tree_sha,\n\
                attempts.snapshot_analyzer_profile_digest,\n\
                attempts.namespace_kind, attempts.credential_profile_id,\n\
                attempts.observation_id, attempts.repository_id\n\
           FROM requested\n\
          CROSS JOIN catalog_attempts AS attempts\n\
                     INDEXED BY sqlite_autoindex_catalog_attempts_1\n\
             ON attempts.namespace_kind = requested.namespace_kind\n\
            AND attempts.credential_profile_id = requested.credential_profile_id\n\
            AND attempts.attempt_id = requested.attempt_id)\n\
         SELECT attempts.attempt_id, attempts.attempt_json, repositories.repository_json,\n\
                snapshots.snapshot_json,\n\
                NULL AS observation_json, NULL AS package_json,\n\
                (SELECT group_concat(aliases.normalized_alias, char(31))\n\
                   FROM catalog_repository_aliases AS aliases\n\
                  WHERE aliases.namespace_kind = attempts.namespace_kind\n\
                    AND aliases.credential_profile_id = attempts.credential_profile_id\n\
                    AND aliases.repository_id = attempts.repository_id),\n\
                repositories.first_observed_at, repositories.last_observed_at,\n\
                snapshots.first_observed_at, snapshots.last_observed_at,\n\
                0 AS package_count,\n\
                attempts.namespace_kind, attempts.credential_profile_id,\n\
                attempts.request_ordinal\n\
           FROM requested_attempts AS attempts\n\
          CROSS JOIN catalog_repositories AS repositories\n\
                     INDEXED BY sqlite_autoindex_catalog_repositories_1\n\
             ON repositories.namespace_kind = attempts.namespace_kind\n\
            AND repositories.credential_profile_id = attempts.credential_profile_id\n\
            AND repositories.repository_id = attempts.repository_id\n\
           LEFT JOIN catalog_snapshots AS snapshots\n\
             ON snapshots.namespace_kind = attempts.namespace_kind\n\
            AND snapshots.credential_profile_id = attempts.credential_profile_id\n\
            AND snapshots.repository_id = attempts.repository_id\n\
            AND snapshots.commit_sha = attempts.snapshot_commit_sha\n\
            AND snapshots.tree_sha = attempts.snapshot_tree_sha\n\
            AND snapshots.analyzer_profile_digest = attempts.snapshot_analyzer_profile_digest\n",
    );
    collect_hydrated_rows(connection, sql.finish(), candidates).await
}

fn requested_candidates_sql(candidates: &[Candidate]) -> Result<SqlBuilder, CatalogError> {
    let mut sql = SqlBuilder::new();
    sql.push(
        "WITH requested(request_ordinal, namespace_kind, credential_profile_id, attempt_id) AS (\n\
         VALUES ",
    );
    for (ordinal, candidate) in candidates.iter().enumerate() {
        if ordinal > 0 {
            sql.push(",");
        }
        sql.push("(");
        sql.bind(to_i64(ordinal as u64)?);
        sql.push(",");
        sql.bind(candidate.namespace_kind.clone());
        sql.push(",");
        sql.bind(candidate.credential_profile_id.clone());
        sql.push(",");
        sql.bind(candidate.attempt_id.clone());
        sql.push(")");
    }
    Ok(sql)
}

async fn hydrate_candidate_batch(
    connection: &turso::Connection,
    candidates: &[Candidate],
) -> Result<Vec<InventorySearchResultV1>, CatalogError> {
    let mut sql = requested_candidates_sql(candidates)?;
    sql.push(
        "), package_counts AS (\n\
         SELECT packages.namespace_kind, packages.credential_profile_id,\n\
                packages.observation_id, COUNT(*) AS package_count\n\
           FROM requested\n\
          CROSS JOIN catalog_attempts AS counted\n\
                     INDEXED BY sqlite_autoindex_catalog_attempts_1\n\
             ON counted.namespace_kind = requested.namespace_kind\n\
            AND counted.credential_profile_id = requested.credential_profile_id\n\
            AND counted.attempt_id = requested.attempt_id\n\
           JOIN catalog_packages AS packages\n\
             ON packages.namespace_kind = counted.namespace_kind\n\
            AND packages.credential_profile_id = counted.credential_profile_id\n\
            AND packages.observation_id = counted.observation_id\n\
          GROUP BY packages.namespace_kind, packages.credential_profile_id,\n\
                   packages.observation_id)\n\
         SELECT attempts.attempt_id, attempts.attempt_json, repositories.repository_json,\n\
                snapshots.snapshot_json, observations.observation_json, packages.package_json,\n\
                (SELECT group_concat(aliases.normalized_alias, char(31))\n\
                   FROM catalog_repository_aliases AS aliases\n\
                  WHERE aliases.namespace_kind = attempts.namespace_kind\n\
                    AND aliases.credential_profile_id = attempts.credential_profile_id\n\
                    AND aliases.repository_id = attempts.repository_id),\n\
                repositories.first_observed_at, repositories.last_observed_at,\n\
                 snapshots.first_observed_at, snapshots.last_observed_at,\n\
                 COALESCE(package_counts.package_count, 0),\n\
                 attempts.namespace_kind, attempts.credential_profile_id,\n\
                 requested.request_ordinal\n\
           FROM requested\n\
          CROSS JOIN catalog_attempts AS attempts\n\
                     INDEXED BY sqlite_autoindex_catalog_attempts_1\n\
             ON attempts.namespace_kind = requested.namespace_kind\n\
            AND attempts.credential_profile_id = requested.credential_profile_id\n\
            AND attempts.attempt_id = requested.attempt_id\n\
           JOIN catalog_repositories AS repositories\n\
                INDEXED BY sqlite_autoindex_catalog_repositories_1\n\
             ON repositories.namespace_kind = attempts.namespace_kind\n\
            AND repositories.credential_profile_id = attempts.credential_profile_id\n\
            AND repositories.repository_id = attempts.repository_id\n\
           LEFT JOIN catalog_snapshots AS snapshots\n\
             ON snapshots.namespace_kind = attempts.namespace_kind\n\
            AND snapshots.credential_profile_id = attempts.credential_profile_id\n\
            AND snapshots.repository_id = attempts.repository_id\n\
            AND snapshots.commit_sha = attempts.snapshot_commit_sha\n\
            AND snapshots.tree_sha = attempts.snapshot_tree_sha\n\
            AND snapshots.analyzer_profile_digest = attempts.snapshot_analyzer_profile_digest\n\
           LEFT JOIN catalog_observations AS observations\n\
             ON observations.namespace_kind = attempts.namespace_kind\n\
            AND observations.credential_profile_id = attempts.credential_profile_id\n\
            AND observations.observation_id = attempts.observation_id\n\
           LEFT JOIN package_counts ON package_counts.namespace_kind = observations.namespace_kind\n\
            AND package_counts.credential_profile_id = observations.credential_profile_id\n\
            AND package_counts.observation_id = observations.observation_id\n\
           LEFT JOIN catalog_packages AS packages\n\
             ON packages.namespace_kind = observations.namespace_kind\n\
            AND packages.credential_profile_id = observations.credential_profile_id\n\
            AND packages.observation_id = observations.observation_id\n\
            AND packages.ordinal < ",
    );
    sql.bind(to_i64(MAX_PACKAGES_PER_RESULT as u64)?);
    collect_hydrated_rows(connection, sql.finish(), candidates).await
}

async fn collect_hydrated_rows(
    connection: &turso::Connection,
    query: CandidateSql,
    candidates: &[Candidate],
) -> Result<Vec<InventorySearchResultV1>, CatalogError> {
    let mut rows = connection
        .query(&query.statement, query.params)
        .await
        .map_err(unavailable)?;
    let metadata = candidate_metadata_by_ordinal(candidates);
    let mut groups: Vec<Option<CandidateGroup>> = std::iter::repeat_with(|| None)
        .take(candidates.len())
        .collect();
    while let Some(row) = rows.next().await.map_err(unavailable)? {
        let ordinal = request_ordinal_from_row(&row)?;
        let (relevance, freshness) = metadata
            .get(ordinal)
            .copied()
            .ok_or(CatalogError::StoreUnavailable)?;
        if groups[ordinal].is_none() {
            groups[ordinal] = Some(CandidateGroup::from_row(&row, (relevance, freshness))?);
        }
        groups[ordinal]
            .as_mut()
            .expect("group must exist")
            .push_package(&row)?;
    }
    ordered_groups_from_ordinal(groups)
}

type CandidateMetadata = Vec<(u32, InventoryFreshnessV1)>;

fn candidate_metadata_by_ordinal(candidates: &[Candidate]) -> CandidateMetadata {
    let mut metadata = Vec::with_capacity(candidates.len());
    metadata.extend(
        candidates
            .iter()
            .map(|candidate| (candidate.relevance, candidate.freshness)),
    );
    metadata
}

fn request_ordinal_from_row(row: &turso::Row) -> Result<usize, CatalogError> {
    usize::try_from(row.get::<i64>(14).map_err(unavailable)?).map_err(unavailable)
}

fn ordered_groups_from_ordinal(
    mut groups: Vec<Option<CandidateGroup>>,
) -> Result<Vec<InventorySearchResultV1>, CatalogError> {
    let mut ordered = Vec::with_capacity(groups.len());
    for group in groups.iter_mut() {
        ordered.push(group.take().ok_or(CatalogError::StoreUnavailable)?.finish());
    }
    Ok(ordered)
}

struct CandidateGroup {
    result: InventorySearchResultV1,
    package_count: usize,
}

impl CandidateGroup {
    fn from_row(
        row: &turso::Row,
        (relevance, freshness): (u32, InventoryFreshnessV1),
    ) -> Result<Self, CatalogError> {
        let attempt: RepositoryAttemptV1 = parse_json(row, 1)?;
        let mut repository: InventoryRepositoryV1 = parse_json(row, 2)?;
        repository
            .full_name
            .clone_from(&attempt.repository_full_name);
        repository
            .normalized_full_name
            .clone_from(&attempt.normalized_repository_name);
        repository.owner.clone_from(&attempt.repository_owner);
        repository
            .normalized_owner
            .clone_from(&attempt.normalized_repository_owner);
        repository.visibility = attempt.repository_visibility;
        repository.aliases = row
            .get::<Option<String>>(6)
            .map_err(unavailable)?
            .into_iter()
            .flat_map(|aliases| {
                aliases
                    .split('\u{1f}')
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .chain(attempt.repository_aliases.iter().cloned())
            .filter(|alias| alias != &attempt.normalized_repository_name)
            .collect();
        repository.first_observed_at = parse_timestamp(row, 7)?;
        repository.last_observed_at = parse_timestamp(row, 8)?;

        let mut snapshot: Option<RepositorySnapshotV1> = parse_optional_json(row, 3)?;
        if let Some(snapshot) = &mut snapshot {
            snapshot.first_observed_at = parse_timestamp(row, 9)?;
            snapshot.last_observed_at = parse_timestamp(row, 10)?;
        }
        let observation: Option<TargetObservationV1> = parse_optional_json(row, 4)?;
        let package_count =
            usize::try_from(row.get::<i64>(11).map_err(unavailable)?).map_err(unavailable)?;
        Ok(Self {
            result: InventorySearchResultV1 {
                repository,
                attempt,
                snapshot,
                observation,
                packages: Vec::with_capacity(package_count.min(MAX_PACKAGES_PER_RESULT)),
                package_matches_total: package_count,
                package_matches_truncated: package_count > MAX_PACKAGES_PER_RESULT,
                freshness,
                relevance,
            },
            package_count,
        })
    }

    fn push_package(&mut self, row: &turso::Row) -> Result<(), CatalogError> {
        if self.result.packages.len() < self.package_count
            && let Some(package) = parse_optional_json(row, 5)?
        {
            self.result.packages.push(package);
        }
        Ok(())
    }

    fn finish(self) -> InventorySearchResultV1 {
        self.result
    }
}

pub(crate) async fn persist_search_document(
    connection: &turso::Connection,
    namespace_kind: &str,
    credential_profile_id: &str,
    attempt: &RepositoryAttemptV1,
    observation: Option<&TargetObservationV1>,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "INSERT INTO catalog_search_documents (
                 namespace_kind, credential_profile_id, attempt_id, ready
             ) VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(namespace_kind, credential_profile_id, attempt_id) DO UPDATE SET ready = 0",
            turso::params![namespace_kind, credential_profile_id, attempt.attempt_id.as_str()],
        )
        .await
        .map_err(unavailable)?;
    connection
        .execute(
            "DELETE FROM catalog_search_terms
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND attempt_id = ?3",
            turso::params![
                namespace_kind,
                credential_profile_id,
                attempt.attempt_id.as_str()
            ],
        )
        .await
        .map_err(unavailable)?;
    connection
        .execute(
            "DELETE FROM catalog_search_trigrams
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND attempt_id = ?3",
            turso::params![
                namespace_kind,
                credential_profile_id,
                attempt.attempt_id.as_str()
            ],
        )
        .await
        .map_err(unavailable)?;

    let repository_terms = std::iter::once(attempt.repository_full_name.as_str())
        .chain(attempt.repository_aliases.iter().map(String::as_str))
        .chain(std::iter::once(attempt.repository_owner.as_str()));
    persist_terms(
        connection,
        namespace_kind,
        credential_profile_id,
        &attempt.attempt_id,
        SEARCH_FIELD_REPOSITORY,
        repository_terms,
    )
    .await?;
    if let Some(observation) = observation {
        persist_terms(
            connection,
            namespace_kind,
            credential_profile_id,
            &attempt.attempt_id,
            SEARCH_FIELD_PACKAGE,
            std::iter::once(observation.target.name.as_str()),
        )
        .await?;
        let mut after_ordinal = -1_i64;
        loop {
            let mut rows = connection
                .query(
                    "SELECT ordinal, package_name FROM catalog_packages
                     WHERE namespace_kind = ?1 AND credential_profile_id = ?2
                       AND observation_id = ?3 AND ordinal > ?4
                     ORDER BY ordinal LIMIT ?5",
                    turso::params![
                        namespace_kind,
                        credential_profile_id,
                        observation.observation_id.as_str(),
                        after_ordinal,
                        to_i64(INDEX_BATCH_SIZE as u64)?
                    ],
                )
                .await
                .map_err(unavailable)?;
            let mut batch = Vec::with_capacity(INDEX_BATCH_SIZE);
            while let Some(row) = rows.next().await.map_err(unavailable)? {
                after_ordinal = row.get(0).map_err(unavailable)?;
                batch.push(row.get::<String>(1).map_err(unavailable)?);
            }
            if batch.is_empty() {
                break;
            }
            persist_terms(
                connection,
                namespace_kind,
                credential_profile_id,
                &attempt.attempt_id,
                SEARCH_FIELD_PACKAGE,
                batch.iter().map(String::as_str),
            )
            .await?;
        }
    }
    connection
        .execute(
            "UPDATE catalog_search_documents SET ready = 1
             WHERE namespace_kind = ?1 AND credential_profile_id = ?2 AND attempt_id = ?3",
            turso::params![
                namespace_kind,
                credential_profile_id,
                attempt.attempt_id.as_str()
            ],
        )
        .await
        .map_err(unavailable)?;
    Ok(())
}

pub(crate) struct RebuildSearchDocument {
    namespace_kind: String,
    credential_profile_id: String,
    attempt_id: String,
    repository_terms: BTreeSet<String>,
    package_terms: BTreeSet<String>,
}

impl RebuildSearchDocument {
    pub(crate) fn new(
        namespace_kind: &str,
        credential_profile_id: &str,
        attempt: &RepositoryAttemptV1,
        observation: Option<&TargetObservationV1>,
        package_names: Vec<&str>,
    ) -> Self {
        let repository_terms = std::iter::once(attempt.repository_full_name.as_str())
            .chain(attempt.repository_aliases.iter().map(String::as_str))
            .chain(std::iter::once(attempt.repository_owner.as_str()))
            .map(normalize_text)
            .filter(|term| !term.is_empty())
            .collect();
        let package_terms = observation
            .into_iter()
            .flat_map(|observation| {
                std::iter::once(observation.target.name.as_str())
                    .chain(package_names.iter().copied())
            })
            .map(normalize_text)
            .filter(|term| !term.is_empty())
            .collect();
        Self {
            namespace_kind: namespace_kind.to_owned(),
            credential_profile_id: credential_profile_id.to_owned(),
            attempt_id: attempt.attempt_id.clone(),
            repository_terms,
            package_terms,
        }
    }

    pub(crate) fn estimated_working_set_bytes(&self) -> usize {
        self.repository_terms
            .iter()
            .chain(&self.package_terms)
            .fold(std::mem::size_of::<Self>(), |total, term| {
                let trigram_count = term.chars().count().saturating_sub(2).max(1);
                total
                    .saturating_add(term.len())
                    .saturating_add(trigram_count.saturating_mul(64))
            })
    }
}

struct RebuildSearchTerm {
    document: usize,
    field: &'static str,
    term: String,
    trigram_count: usize,
    trigrams_json: String,
}

pub(crate) async fn persist_rebuild_search_documents(
    connection: &turso::Connection,
    documents: Vec<RebuildSearchDocument>,
) -> Result<(), CatalogError> {
    for batch in documents.chunks(REBUILD_SEARCH_DOCUMENT_BATCH_SIZE) {
        persist_rebuild_search_batch(connection, batch).await?;
    }
    Ok(())
}

async fn persist_rebuild_search_batch(
    connection: &turso::Connection,
    documents: &[RebuildSearchDocument],
) -> Result<(), CatalogError> {
    let mut document_order = (0..documents.len()).collect::<Vec<_>>();
    document_order.sort_unstable_by(|left, right| {
        let left = &documents[*left];
        let right = &documents[*right];
        (
            left.namespace_kind.as_str(),
            left.credential_profile_id.as_str(),
            left.attempt_id.as_str(),
        )
            .cmp(&(
                right.namespace_kind.as_str(),
                right.credential_profile_id.as_str(),
                right.attempt_id.as_str(),
            ))
    });
    for document_order in document_order.chunks(MAX_DYNAMIC_BINDINGS / 4) {
        let rows = document_order
            .iter()
            .map(|document| {
                let document = &documents[*document];
                vec![
                    turso::Value::Text(document.namespace_kind.clone()),
                    turso::Value::Text(document.credential_profile_id.clone()),
                    turso::Value::Text(document.attempt_id.clone()),
                    turso::Value::Integer(1),
                ]
            })
            .collect();
        execute_rebuild_rows(
            connection,
            "INSERT INTO catalog_search_documents (
                 namespace_kind, credential_profile_id, attempt_id, ready
             )",
            4,
            rows,
        )
        .await?;
    }

    let mut terms = Vec::new();
    for (document, projection) in documents.iter().enumerate() {
        for (field, values) in [
            (SEARCH_FIELD_REPOSITORY, &projection.repository_terms),
            (SEARCH_FIELD_PACKAGE, &projection.package_terms),
        ] {
            for term in values {
                let term_trigrams = trigrams(term);
                terms.push(RebuildSearchTerm {
                    document,
                    field,
                    term: term.clone(),
                    trigram_count: term_trigrams.len(),
                    trigrams_json: serde_json::to_string(&term_trigrams).map_err(unavailable)?,
                });
            }
        }
    }
    terms.sort_unstable_by(|left, right| {
        let left_document = &documents[left.document];
        let right_document = &documents[right.document];
        (
            left_document.namespace_kind.as_str(),
            left_document.credential_profile_id.as_str(),
            left_document.attempt_id.as_str(),
            left.field,
            left.term.as_str(),
        )
            .cmp(&(
                right_document.namespace_kind.as_str(),
                right_document.credential_profile_id.as_str(),
                right_document.attempt_id.as_str(),
                right.field,
                right.term.as_str(),
            ))
    });
    for terms in terms.chunks(MAX_DYNAMIC_BINDINGS / 8) {
        let rows = terms
            .iter()
            .map(|term| {
                let document = &documents[term.document];
                Ok(vec![
                    turso::Value::Text(document.namespace_kind.clone()),
                    turso::Value::Text(document.credential_profile_id.clone()),
                    turso::Value::Text(document.attempt_id.clone()),
                    turso::Value::Text(term.field.to_owned()),
                    turso::Value::Text(term.term.clone()),
                    turso::Value::Integer(to_i64(term.term.len() as u64)?),
                    turso::Value::Integer(to_i64(term.trigram_count as u64)?),
                    turso::Value::Text(term.trigrams_json.clone()),
                ])
            })
            .collect::<Result<Vec<_>, CatalogError>>()?;
        execute_rebuild_rows(
            connection,
            "INSERT OR IGNORE INTO catalog_search_terms (
                 namespace_kind, credential_profile_id, attempt_id, field,
                 term, term_byte_len, trigram_count, trigrams_json
             )",
            8,
            rows,
        )
        .await?;
    }
    Ok(())
}

async fn execute_rebuild_rows(
    connection: &turso::Connection,
    prefix: &str,
    column_count: usize,
    rows: Vec<Vec<turso::Value>>,
) -> Result<(), CatalogError> {
    if column_count == 0 || column_count > MAX_DYNAMIC_BINDINGS {
        return Err(CatalogError::StoreUnavailable);
    }
    if rows.is_empty() {
        return Ok(());
    }
    if rows.len() > MAX_DYNAMIC_BINDINGS / column_count
        || rows.iter().any(|row| row.len() != column_count)
    {
        return Err(CatalogError::StoreUnavailable);
    }
    let row_count = rows.len();
    let params = rows.into_iter().flatten().collect::<Vec<_>>();
    let statement = rebuild_insert_statement(prefix, column_count, row_count);
    let mut statement = connection
        .prepare_cached(&statement)
        .await
        .map_err(unavailable)?;
    statement.execute(params).await.map_err(unavailable)?;
    Ok(())
}

fn rebuild_insert_statement(prefix: &str, column_count: usize, row_count: usize) -> String {
    let row = format!("({})", vec!["?"; column_count].join(","));
    format!(
        "{prefix} VALUES {rows}",
        rows = (0..row_count)
            .map(|_| row.as_str())
            .collect::<Vec<_>>()
            .join(",")
    )
}

async fn persist_terms<'a>(
    connection: &turso::Connection,
    namespace_kind: &str,
    credential_profile_id: &str,
    attempt_id: &str,
    field: &str,
    terms: impl IntoIterator<Item = &'a str>,
) -> Result<(), CatalogError> {
    let terms = terms
        .into_iter()
        .map(normalize_text)
        .filter(|term| !term.is_empty())
        .collect::<BTreeSet<_>>();
    for term in terms {
        let term_trigrams = trigrams(&term);
        let trigrams_json = serde_json::to_string(&term_trigrams).map_err(unavailable)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO catalog_search_terms (
                     namespace_kind, credential_profile_id, attempt_id, field,
                     term, term_byte_len, trigram_count, trigrams_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                turso::params![
                    namespace_kind,
                    credential_profile_id,
                    attempt_id,
                    field,
                    term.as_str(),
                    to_i64(term.len() as u64)?,
                    to_i64(term_trigrams.len() as u64)?,
                    trigrams_json
                ],
            )
            .await
            .map_err(unavailable)?;
    }
    Ok(())
}

fn has_evidence_filter(query: &InventoryQueryV1) -> bool {
    query.target_name.is_some()
        || query.target_version.is_some()
        || query.target_source != InventorySourceFilterV1::Any
        || query.package_name.is_some()
        || query.package_version.is_some()
        || query.package_source != InventorySourceFilterV1::Any
        || query.requirement.is_some()
        || !query.requirement_sources.is_empty()
        || query.requirement_accepts_target.is_some()
        || query.explicit_exact_pin.is_some()
        || !query.recorded_relations.is_empty()
        || query.min_msrv.is_some()
        || query.max_msrv.is_some()
        || !query.strengths.is_empty()
        || !query.completeness.is_empty()
        || !query.limitation_codes.is_empty()
        || query.commit_sha.is_some()
        || query.tree_sha.is_some()
        || query.analyzer_profile_digest.is_some()
}

fn enum_text<T: serde::Serialize>(value: &T) -> Result<String, CatalogError> {
    let encoded = serde_json::to_string(value).map_err(unavailable)?;
    Ok(encoded.trim_matches('"').to_owned())
}

fn parse_json<T: serde::de::DeserializeOwned>(
    row: &turso::Row,
    index: usize,
) -> Result<T, CatalogError> {
    let encoded: String = row.get(index).map_err(unavailable)?;
    serde_json::from_str(&encoded).map_err(unavailable)
}

fn parse_optional_json<T: serde::de::DeserializeOwned>(
    row: &turso::Row,
    index: usize,
) -> Result<Option<T>, CatalogError> {
    row.get::<Option<String>>(index)
        .map_err(unavailable)?
        .map(|encoded| serde_json::from_str(&encoded).map_err(unavailable))
        .transpose()
}

fn parse_timestamp(row: &turso::Row, index: usize) -> Result<DateTime<Utc>, CatalogError> {
    let encoded: String = row.get(index).map_err(unavailable)?;
    DateTime::parse_from_rfc3339(&encoded)
        .map(|value| value.with_timezone(&Utc))
        .map_err(unavailable)
}

fn parse_freshness(value: &str) -> Result<InventoryFreshnessV1, CatalogError> {
    match value {
        "current" => Ok(InventoryFreshnessV1::Current),
        "refresh_partial" => Ok(InventoryFreshnessV1::RefreshPartial),
        "refresh_failed" => Ok(InventoryFreshnessV1::RefreshFailed),
        "historical" => Ok(InventoryFreshnessV1::Historical),
        _ => Err(CatalogError::StoreUnavailable),
    }
}

pub(crate) fn normalize_text(value: &str) -> String {
    value
        .trim()
        .chars()
        .flat_map(char::to_lowercase)
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, '/' | '-' | '_' | '.') {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn prefix_upper_bound(value: &str) -> Option<String> {
    let mut characters = value.chars().collect::<Vec<_>>();
    for index in (0..characters.len()).rev() {
        let mut next = u32::from(characters[index]).checked_add(1)?;
        if (0xd800..=0xdfff).contains(&next) {
            next = 0xe000;
        }
        if let Some(next) = char::from_u32(next) {
            characters.truncate(index);
            let mut upper = characters.into_iter().collect::<String>();
            upper.push(next);
            return Some(upper);
        }
    }
    None
}

#[cfg(test)]
fn trailing_trigram(value: &str) -> Option<String> {
    let characters = value.chars().collect::<Vec<_>>();
    (characters.len() >= 3).then(|| characters[characters.len() - 3..].iter().collect())
}

fn trigrams(value: &str) -> BTreeSet<String> {
    let characters = value.chars().collect::<Vec<_>>();
    if characters.len() < 3 {
        return characters
            .first()
            .map(|_| value.to_owned())
            .into_iter()
            .collect();
    }
    characters
        .windows(3)
        .map(|window| window.iter().collect())
        .collect()
}

pub(crate) fn semver_sort_key(version: &Version) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + version.pre.len());
    key.extend(version.major.to_be_bytes());
    key.extend(version.minor.to_be_bytes());
    key.extend(version.patch.to_be_bytes());
    if version.pre.is_empty() {
        key.push(2);
        return key;
    }
    key.push(1);
    for identifier in version.pre.split('.') {
        if identifier.bytes().all(|byte| byte.is_ascii_digit()) {
            key.push(1);
            key.extend((identifier.len() as u64).to_be_bytes());
        } else {
            key.push(2);
        }
        key.extend(identifier.as_bytes());
        key.push(0);
    }
    key.push(0);
    key
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

fn to_i64(value: u64) -> Result<i64, CatalogError> {
    i64::try_from(value).map_err(unavailable)
}

fn unavailable<E: std::fmt::Debug>(_error: E) -> CatalogError {
    CatalogError::StoreUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_repository_pages_use_the_ordered_latest_index() {
        let mut query = InventoryQueryV1::new();
        query.namespace = Some(InventoryNamespaceV1::Public);
        query.sort = InventorySortV1::RepositoryAsc;
        let namespaces = authorized_namespaces(
            &InventoryAccessV1 {
                principal_id: "reader".to_owned(),
                private_credential_profiles: BTreeSet::new(),
            },
            &query,
        );

        let sql = CandidateSql::build(&namespaces, &query, None, 42, true, 1_001).unwrap();

        assert!(
            sql.statement
                .contains("INDEXED BY catalog_attempts_search_order")
        );
        assert!(
            !sql.statement
                .contains("catalog_attempts_projection_sequence")
        );
        assert!(!sql.statement.contains("WITH authorized"));

        let cursor = DecodedCursorV1 {
            index_watermark: 42,
            last: InventorySortKeyV1 {
                relevance: 0,
                normalized_repository: "owner/repository".to_owned(),
                completed_at: Utc::now(),
                msrv: None,
                attempt_id: "attempt".to_owned(),
            },
        };
        let sql = CandidateSql::build(&namespaces, &query, Some(&cursor), 42, true, 1_001).unwrap();
        assert!(
            sql.statement
                .contains("attempts.normalized_repository_name >= ?")
        );

        query.repository_owner = Some("owner".to_owned());
        let sql = CandidateSql::build(&namespaces, &query, None, 42, true, 1_001).unwrap();
        assert!(sql.statement.contains("WITH authorized"));

        query.repository_owner = None;
        query.sort = InventorySortV1::Relevance;
        query.search = Some("owner/repository".to_owned());
        query.search_field = InventorySearchFieldV1::Repository;
        query.match_mode = InventoryMatchModeV1::Exact;
        let sql = CandidateSql::build(&namespaces, &query, None, 42, true, 100).unwrap();
        assert!(
            sql.statement
                .contains("FROM authorized JOIN catalog_search_terms")
        );
        assert!(
            !sql.statement
                .contains("FROM filtered JOIN catalog_search_terms")
        );

        query.match_mode = InventoryMatchModeV1::Fuzzy;
        query.search = Some("owner/repositorx".to_owned());
        let sql = CandidateSql::build(&namespaces, &query, None, 42, true, 100).unwrap();
        let trigrams = sql.statement.find("FROM query_trigrams").unwrap();
        let authorized = sql.statement.find("CROSS JOIN authorized").unwrap();
        let terms = sql
            .statement
            .find("CROSS JOIN catalog_search_terms AS terms")
            .unwrap();
        assert!(
            trigrams < authorized && authorized < terms,
            "query trigrams and authorized namespaces must precede term expansion"
        );
        assert!(sql.statement.contains("json_each(terms.trigrams_json)"));
        assert!(
            !sql.statement
                .contains("catalog_search_trigrams AS postings")
        );
        let grouped = sql.statement.find("GROUP BY terms.namespace_kind").unwrap();
        let intersections = sql
            .statement
            .find("FROM term_intersections AS intersections")
            .unwrap();
        let term_lookup = sql
            .statement
            .rfind("JOIN catalog_search_terms AS terms")
            .unwrap();
        assert!(
            grouped < intersections && intersections < term_lookup,
            "fuzzy search must look up each term after posting intersections are grouped"
        );

        query.match_mode = InventoryMatchModeV1::Substring;
        query.search = Some("owner/repository".to_owned());
        let sql = CandidateSql::build(&namespaces, &query, None, 42, true, 100).unwrap();
        assert!(
            !sql.statement
                .contains("catalog_search_trigrams AS postings")
        );
        assert!(sql.statement.contains("instr(terms.term, ?) > 0"));
    }

    #[test]
    fn prefix_upper_bounds_preserve_unicode_ordering() {
        assert_eq!(prefix_upper_bound("abc").as_deref(), Some("abd"));
        assert_eq!(
            prefix_upper_bound("a\u{d7ff}").as_deref(),
            Some("a\u{e000}")
        );
        assert_eq!(prefix_upper_bound("a\u{10ffff}").as_deref(), Some("b"));
        assert_eq!(prefix_upper_bound("\u{10ffff}"), None);
        assert_eq!(trailing_trigram("ab"), None);
        assert_eq!(trailing_trigram("owner/repo").as_deref(), Some("epo"));
        assert_eq!(trailing_trigram("a🦀z").as_deref(), Some("a🦀z"));
    }

    #[test]
    fn hydration_batches_respect_the_portable_binding_budget() {
        const {
            assert!(
                MAX_CANDIDATES_PER_HYDRATION * HYDRATION_BINDINGS_PER_CANDIDATE
                    < MAX_DYNAMIC_BINDINGS
            );
            assert!(
                (MAX_CANDIDATES_PER_HYDRATION + 1) * HYDRATION_BINDINGS_PER_CANDIDATE + 1
                    > MAX_DYNAMIC_BINDINGS
            );
            assert!(
                MAX_ATTEMPT_CANDIDATES_PER_HYDRATION * ATTEMPT_BINDINGS_PER_CANDIDATE
                    == MAX_DYNAMIC_BINDINGS
            );
        }

        let candidates = (0..MAX_ATTEMPT_CANDIDATES_PER_HYDRATION + 1)
            .map(|index| Candidate {
                namespace_kind: "public".to_owned(),
                credential_profile_id: String::new(),
                attempt_id: format!("attempt-{index}"),
                relevance: 0,
                freshness: InventoryFreshnessV1::RefreshFailed,
                has_observation: false,
            })
            .collect::<Vec<_>>();
        let chunks = candidates
            .chunks(MAX_ATTEMPT_CANDIDATES_PER_HYDRATION)
            .map(|chunk| requested_candidates_sql(chunk).expect("valid request sql"))
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].params.len(), MAX_DYNAMIC_BINDINGS);
        assert_eq!(chunks[1].params.len(), ATTEMPT_BINDINGS_PER_CANDIDATE);
        assert!(
            !chunks[0]
                .statement
                .contains(" UNION ALL SELECT attempts.attempt_id")
        );
    }

    #[test]
    fn package_heavy_rebuild_batches_flush_on_weight_before_document_count() {
        let document = RebuildSearchDocument {
            namespace_kind: "public".to_owned(),
            credential_profile_id: String::new(),
            attempt_id: "package-heavy".to_owned(),
            repository_terms: BTreeSet::from(["owner/repository".to_owned()]),
            package_terms: (0..2_000)
                .map(|index| format!("package-with-a-deliberately-long-name-{index:04}"))
                .collect(),
        };
        let document_bytes = document.estimated_working_set_bytes();
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        while !rebuild_search_batch_should_flush(count, bytes, document_bytes) {
            count += 1;
            bytes = bytes.saturating_add(document_bytes);
        }
        assert!(count < REBUILD_SEARCH_DOCUMENT_BATCH_SIZE);
        assert!(bytes <= REBUILD_SEARCH_WORKING_SET_BYTES);
        assert!(bytes.saturating_add(document_bytes) > REBUILD_SEARCH_WORKING_SET_BYTES);
    }

    #[test]
    fn semver_keys_preserve_semver_precedence() {
        let versions = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.9.0",
            "1.10.0",
        ]
        .map(|value| Version::parse(value).unwrap());
        for pair in versions.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(semver_sort_key(&pair[0]) < semver_sort_key(&pair[1]));
        }
    }
}
