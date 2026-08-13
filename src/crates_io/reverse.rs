//! Reverse-dependency evidence and sparse-index enrichment.

use anyhow::{Context, Result, anyhow, ensure};
use futures::{StreamExt, stream};

use super::{
    CratesIoClient, DependencyDeclaration, INDEX_FETCH_CONCURRENCY, RequestClass,
    ReverseDependenciesPage, ReverseDependencyCandidate, endpoint_url, extract_index_declarations,
    has_another_reverse_page, join_reverse_page, representative_declaration, sparse_index_path,
};

impl CratesIoClient {
    /// Fetch and enrich every page exposed by crates.io's reverse-dependency API.
    ///
    /// The returned records have [`super::REVERSE_DEPENDENCY_SCOPE`]. The two
    /// arrays in the API response are joined by `version_id`; their positions
    /// are unrelated. Each result is then enriched from the sparse index so
    /// duplicate, renamed, target-specific, build, and dev declarations are retained.
    pub async fn reverse_dependencies(
        &self,
        target_crate: &str,
    ) -> Result<Vec<ReverseDependencyCandidate>> {
        self.reverse_dependencies_limited(target_crate, None).await
    }

    /// Fetch reverse dependencies while stopping once `limit` records are found.
    ///
    /// The limit is applied before sparse-index enrichment, so a bounded scan
    /// does not download or enrich the full ecosystem candidate set.
    pub async fn reverse_dependencies_limited(
        &self,
        target_crate: &str,
        limit: Option<usize>,
    ) -> Result<Vec<ReverseDependencyCandidate>> {
        ensure!(
            !target_crate.trim().is_empty(),
            "target crate name must not be empty"
        );
        if limit == Some(0) {
            return Ok(Vec::new());
        }

        let mut page_number = 1usize;
        let mut candidates = Vec::new();
        let mut seen_versions = std::collections::HashSet::new();
        let mut records_seen = 0usize;

        loop {
            let mut url = endpoint_url(
                &self.inner.api_base,
                &["crates", target_crate, "reverse_dependencies"],
            )?;
            url.query_pairs_mut()
                .append_pair("page", &page_number.to_string())
                .append_pair(
                    "per_page",
                    &self.inner.reverse_dependencies_per_page.to_string(),
                );

            let response = self.get(url.clone(), RequestClass::Api).await?;
            let response: ReverseDependenciesPage = super::decode_json(response, &url).await?;
            let reported_total = response.meta.total;
            let page_len = response.dependencies.len();
            let joined = join_reverse_page(response)?;
            records_seen = records_seen.saturating_add(page_len);

            for candidate in joined {
                if seen_versions.insert(candidate.version_id) {
                    candidates.push(candidate);
                    if limit.is_some_and(|limit| candidates.len() >= limit) {
                        break;
                    }
                }
            }

            if limit.is_some_and(|limit| candidates.len() >= limit)
                || !has_another_reverse_page(
                    page_len,
                    records_seen,
                    reported_total,
                    self.inner.reverse_dependencies_per_page,
                )
            {
                break;
            }

            page_number = page_number
                .checked_add(1)
                .ok_or_else(|| anyhow!("reverse-dependency page number overflow"))?;
        }

        if let Some(limit) = limit {
            candidates.truncate(limit);
        }

        Ok(self.enrich_declarations(candidates).await)
    }

    pub(super) async fn enrich_declarations(
        &self,
        candidates: Vec<ReverseDependencyCandidate>,
    ) -> Vec<ReverseDependencyCandidate> {
        let work = candidates
            .into_iter()
            .enumerate()
            .map(|(position, mut candidate)| {
                let client = self.clone();
                async move {
                    match client
                        .sparse_index_declarations(
                            &candidate.dependent_name,
                            &candidate.dependent_version,
                            &candidate.representative.crate_id,
                        )
                        .await
                    {
                        Ok(declarations) => candidate.declarations = declarations,
                        Err(error) => {
                            candidate.declarations =
                                vec![representative_declaration(&candidate.representative)];
                            candidate.declaration_enrichment_error = Some(format!("{error:#}"));
                        }
                    }
                    (position, candidate)
                }
            });

        let mut enriched: Vec<_> = stream::iter(work)
            .buffer_unordered(INDEX_FETCH_CONCURRENCY)
            .collect()
            .await;
        enriched.sort_unstable_by_key(|(position, _)| *position);
        enriched
            .into_iter()
            .map(|(_, candidate)| candidate)
            .collect()
    }

    async fn sparse_index_declarations(
        &self,
        dependent_name: &str,
        dependent_version: &str,
        target_crate: &str,
    ) -> Result<Vec<DependencyDeclaration>> {
        let path = sparse_index_path(dependent_name)?;
        let url = endpoint_url(&self.inner.index_base, &path.split('/').collect::<Vec<_>>())?;
        let response = self.get(url.clone(), RequestClass::Index).await?;
        let body = super::decode_text(response, &url).await?;
        extract_index_declarations(&body, dependent_version, target_crate).with_context(|| {
            format!(
                "failed to enrich {dependent_name} {dependent_version} from sparse index `{url}`"
            )
        })
    }
}
