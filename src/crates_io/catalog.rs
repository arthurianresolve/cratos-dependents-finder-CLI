//! Catalog lookup over the crates.io API.

use anyhow::{Result, ensure};
use reqwest::StatusCode;

use super::{
    CrateEnvelope, CratesIoClient, REVERSE_DEPENDENCIES_PER_PAGE, RequestClass, SearchResponse,
    canonical_crate_name, decode_json, endpoint_url,
};
use crate::model::CrateSummary;

impl CratesIoClient {
    /// Look up a crate by canonical crates.io identity.
    ///
    /// crates.io treats ASCII case and `-` versus `_` differences as the same
    /// identity. A missing crate is returned as `None`; other HTTP errors fail.
    pub async fn lookup_exact(&self, name: &str) -> Result<Option<CrateSummary>> {
        ensure!(!name.trim().is_empty(), "crate name must not be empty");

        let url = endpoint_url(&self.inner.api_base, &["crates", name])?;
        let response = self.get(url.clone(), RequestClass::Api).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let envelope: CrateEnvelope = decode_json(response, &url).await?;
        ensure!(
            canonical_crate_name(&envelope.krate.name) == canonical_crate_name(name),
            "crates.io returned `{}` for exact lookup `{name}`",
            envelope.krate.name
        );
        Ok(Some(envelope.krate.into()))
    }

    /// Search crates.io and return up to `limit` server-ranked candidates.
    ///
    /// crates.io search is relevance/substring based, not an edit-distance or
    /// repository-name lookup. Callers should rank these candidates locally.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<CrateSummary>> {
        if limit == 0 || query.trim().is_empty() {
            return Ok(Vec::new());
        }

        let per_page = limit.min(REVERSE_DEPENDENCIES_PER_PAGE);
        let mut url = endpoint_url(&self.inner.api_base, &["crates"])?;
        url.query_pairs_mut()
            .append_pair("q", query)
            .append_pair("sort", "relevance")
            .append_pair("include_yanked", "no")
            .append_pair("page", "1")
            .append_pair("per_page", &per_page.to_string());

        let response = self.get(url.clone(), RequestClass::Api).await?;
        let response: SearchResponse = decode_json(response, &url).await?;
        Ok(response
            .crates
            .into_iter()
            .take(limit)
            .map(Into::into)
            .collect())
    }
}
