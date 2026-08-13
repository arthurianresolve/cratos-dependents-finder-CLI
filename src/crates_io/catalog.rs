//! Catalog lookup over the crates.io API and sparse index.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, ensure};
use reqwest::StatusCode;
use semver::Version;
use serde::{Deserialize, Serialize};

use super::{
    CrateEnvelope, CratesIoClient, REVERSE_DEPENDENCIES_PER_PAGE, RequestClass, SearchResponse,
    canonical_crate_name, decode_json, decode_text, endpoint_url, sparse_index_path,
};
use crate::{model::CrateSummary, secure_cache::sha256_hex, version_selector::PublishedVersionV1};

/// Complete release inventory read from one crates.io sparse-index response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrateVersionCatalog {
    pub crate_name: String,
    pub versions: Vec<PublishedVersionV1>,
    /// SHA-256 of the exact UTF-8 sparse-index response bytes.
    pub sha256: String,
}

#[derive(Deserialize)]
struct CatalogEntry {
    name: String,
    vers: String,
    #[serde(default)]
    yanked: bool,
}

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

    /// Fetch the complete published release universe for one crate.
    ///
    /// Yanked releases are retained because existing lockfiles may continue to
    /// resolve them. The response digest can be bound into range evidence or a
    /// reuse fingerprint.
    pub async fn version_catalog(&self, name: &str) -> Result<CrateVersionCatalog> {
        ensure!(!name.trim().is_empty(), "crate name must not be empty");
        let path = sparse_index_path(name)?;
        let url = endpoint_url(&self.inner.index_base, &path.split('/').collect::<Vec<_>>())?;
        let response = self.get(url.clone(), RequestClass::Index).await?;
        let body = decode_text(response, &url).await?;
        parse_version_catalog(name, &body)
    }
}

fn parse_version_catalog(name: &str, body: &str) -> Result<CrateVersionCatalog> {
    let mut versions = BTreeMap::<Version, bool>::new();
    for (line_number, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: CatalogEntry = serde_json::from_str(line)
            .with_context(|| format!("invalid sparse-index JSON on line {}", line_number + 1))?;
        ensure!(
            canonical_crate_name(&entry.name) == canonical_crate_name(name),
            "sparse-index line {} contains crate `{}` instead of `{name}`",
            line_number + 1,
            entry.name
        );
        let version = Version::parse(&entry.vers).with_context(|| {
            format!(
                "invalid sparse-index release `{}` on line {}",
                entry.vers,
                line_number + 1
            )
        })?;
        if let Some(existing) = versions.insert(version.clone(), entry.yanked) {
            ensure!(
                existing == entry.yanked,
                "sparse index contains conflicting yanked state for release `{version}`"
            );
        }
    }
    ensure!(
        !versions.is_empty(),
        "sparse index for `{name}` contains no releases"
    );
    Ok(CrateVersionCatalog {
        crate_name: canonical_crate_name(name),
        versions: versions
            .into_iter()
            .map(|(version, yanked)| PublishedVersionV1 { version, yanked })
            .collect(),
        sha256: sha256_hex(body.as_bytes()),
    })
}

#[cfg(test)]
mod version_catalog_tests {
    use std::time::Duration;

    use super::*;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[test]
    fn catalog_is_sorted_deduplicated_and_retains_yanked_releases() {
        let body = concat!(
            r#"{"name":"demo","vers":"1.2.0","yanked":false}"#,
            "\n",
            r#"{"name":"demo","vers":"1.0.0","yanked":true}"#,
            "\n",
            r#"{"name":"demo","vers":"1.2.0","yanked":false}"#,
            "\n",
        );
        let catalog = parse_version_catalog("demo", body).unwrap();

        assert_eq!(
            catalog.versions,
            vec![
                PublishedVersionV1 {
                    version: Version::new(1, 0, 0),
                    yanked: true,
                },
                PublishedVersionV1 {
                    version: Version::new(1, 2, 0),
                    yanked: false,
                },
            ]
        );
        assert_eq!(
            parse_version_catalog(
                "Demo_Crate",
                r#"{"name":"demo-crate","vers":"1.0.0","yanked":false}"#,
            )
            .unwrap()
            .crate_name,
            "demo_crate"
        );
        assert_eq!(
            catalog.sha256,
            parse_version_catalog("demo", body).unwrap().sha256
        );
        assert_ne!(
            catalog.sha256,
            parse_version_catalog("demo", &format!("{body}\n"))
                .unwrap()
                .sha256
        );
    }

    #[test]
    fn catalog_rejects_conflicting_duplicate_release_metadata() {
        let body = concat!(
            r#"{"name":"demo","vers":"1.0.0","yanked":false}"#,
            "\n",
            r#"{"name":"demo","vers":"1.0.0","yanked":true}"#,
        );
        assert!(parse_version_catalog("demo", body).is_err());
    }

    #[test]
    fn catalog_rejects_rows_for_another_crate() {
        let body = r#"{"name":"different","vers":"1.0.0","yanked":false}"#;
        assert!(parse_version_catalog("demo", body).is_err());
    }

    #[tokio::test]
    async fn client_fetches_the_complete_sparse_index_catalog_once() {
        let server = MockServer::start().await;
        let body = concat!(
            r#"{"name":"fs2","vers":"0.4.3","yanked":false}"#,
            "\n",
            r#"{"name":"fs2","vers":"0.5.0","yanked":true}"#,
            "\n",
        );
        Mock::given(method("GET"))
            .and(path("/index/3/f/fs2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let client = CratesIoClient::with_configuration(
            Url::parse(&format!("{}/api/", server.uri())).unwrap(),
            Url::parse(&format!("{}/index/", server.uri())).unwrap(),
            Duration::ZERO,
            100,
        )
        .unwrap();

        let catalog = client.version_catalog("fs2").await.unwrap();

        assert_eq!(catalog.versions.len(), 2);
        assert_eq!(catalog.versions[0].version, Version::new(0, 4, 3));
        assert!(catalog.versions[1].yanked);
    }
}
