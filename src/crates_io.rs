use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use futures::{StreamExt, stream};
use reqwest::{StatusCode, Url, header::RETRY_AFTER};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{sync::Mutex, time::Instant};

use crate::model::CrateSummary;

const CRATES_IO_API: &str = "https://crates.io/api/v1/";
const CRATES_IO_INDEX: &str = "https://index.crates.io/";
const API_REQUEST_INTERVAL: Duration = Duration::from_secs(1);
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const API_RESPONSE_LIMIT: usize = 32 * 1024 * 1024;
const SPARSE_INDEX_RESPONSE_LIMIT: usize = 64 * 1024 * 1024;
const MAX_TRANSIENT_RETRIES: usize = 2;
const REVERSE_DEPENDENCIES_PER_PAGE: usize = 100;
const INDEX_FETCH_CONCURRENCY: usize = 8;
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (crate dependency inventory CLI)"
);

/// Scope of crates.io's reverse-dependency endpoint as currently implemented.
///
/// The endpoint is not a historical list of every published dependent release.
/// It contains dependent crates whose current, non-yanked default version has a
/// direct dependency declaration on the requested crate.
pub const REVERSE_DEPENDENCY_SCOPE: &str =
    "current non-yanked crates.io default versions with a direct dependency declaration";

/// A dependency row chosen by crates.io to represent a reverse dependency.
///
/// crates.io currently collapses multiple matching declarations in one
/// dependent version to a single representative row. Use [`DependencyDeclaration`]
/// on [`ReverseDependencyCandidate`] for the complete declaration set.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepresentativeDependency {
    pub id: u64,
    pub version_id: u64,
    pub crate_id: String,
    pub req: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default = "default_true")]
    pub default_features: bool,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default = "default_dependency_kind")]
    pub kind: String,
    /// Total downloads of the dependent crate in current crates.io responses.
    #[serde(default)]
    pub downloads: u64,
}

/// One matching declaration from the dependent release's sparse-index entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DependencyDeclaration {
    /// The dependency name visible to the dependent package (possibly an alias).
    pub dependency_name: String,
    /// The actual crates.io package identity after resolving an index `package` rename.
    pub package_name: String,
    pub req: String,
    pub kind: String,
    pub optional: bool,
    pub target: Option<String>,
    pub registry: Option<String>,
}

/// A direct dependent discovered from crates.io's current-default-version view.
#[derive(Clone, Debug, Serialize)]
pub struct ReverseDependencyCandidate {
    pub version_id: u64,
    pub dependent_name: String,
    pub dependent_version: String,
    pub dependent_yanked: bool,
    pub repository: Option<String>,
    pub dependent_downloads: u64,
    pub representative: RepresentativeDependency,
    /// All declarations for the requested target in this exact dependent version.
    pub declarations: Vec<DependencyDeclaration>,
    /// Why sparse-index enrichment failed, if declarations contain only the
    /// representative-row fallback.
    pub declaration_enrichment_error: Option<String>,
}

/// A crates.io client with a process-local, clone-shared API throttle.
#[derive(Clone)]
pub struct CratesIoClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    http: reqwest::Client,
    api_base: Url,
    index_base: Url,
    next_api_request: Mutex<Instant>,
    api_request_interval: Duration,
    reverse_dependencies_per_page: usize,
}

impl CratesIoClient {
    pub fn new() -> Result<Self> {
        Self::with_configuration(
            Url::parse(CRATES_IO_API).context("invalid crates.io API URL")?,
            Url::parse(CRATES_IO_INDEX).context("invalid crates.io index URL")?,
            API_REQUEST_INTERVAL,
            REVERSE_DEPENDENCIES_PER_PAGE,
        )
    }

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

    /// Fetch and enrich every page exposed by crates.io's reverse-dependency API.
    ///
    /// The returned records have [`REVERSE_DEPENDENCY_SCOPE`]. The two arrays in
    /// the API response are joined by `version_id`; their positions are unrelated.
    /// Each result is then enriched from the sparse index so duplicate, renamed,
    /// target-specific, build, and dev declarations are retained.
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
        let mut seen_versions = HashSet::new();

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
            let response: ReverseDependenciesPage = decode_json(response, &url).await?;
            let reported_total = response.meta.total;
            let page_len = response.dependencies.len();
            let joined = join_reverse_page(response)?;

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
                    candidates.len(),
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

    async fn enrich_declarations(
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
        let body = decode_text(response, &url).await?;
        extract_index_declarations(&body, dependent_version, target_crate).with_context(|| {
            format!(
                "failed to enrich {dependent_name} {dependent_version} from sparse index `{url}`"
            )
        })
    }

    async fn get(&self, url: Url, class: RequestClass) -> Result<reqwest::Response> {
        for attempt in 0..=MAX_TRANSIENT_RETRIES {
            if class == RequestClass::Api {
                self.wait_for_api_slot().await;
            }

            // Transport failures are intentionally not retried. Only a concrete
            // transient HTTP status is eligible for the short retry policy.
            let response = self
                .inner
                .http
                .get(url.clone())
                .send()
                .await
                .with_context(|| format!("GET `{url}` failed"))?;

            if !is_transient(response.status()) || attempt == MAX_TRANSIENT_RETRIES {
                return Ok(response);
            }

            let Some(retry_delay) = retry_delay(&response, attempt) else {
                return Ok(response);
            };
            // Consume the body before reusing the pooled connection.
            let _ = response.bytes().await;
            tokio::time::sleep(retry_delay).await;
        }

        unreachable!("bounded retry loop always returns")
    }

    async fn wait_for_api_slot(&self) {
        let mut next_request = self.inner.next_api_request.lock().await;
        let now = Instant::now();
        if *next_request > now {
            tokio::time::sleep(*next_request - now).await;
        }
        *next_request = Instant::now() + self.inner.api_request_interval;
    }

    pub(crate) fn with_configuration(
        api_base: Url,
        index_base: Url,
        api_request_interval: Duration,
        reverse_dependencies_per_page: usize,
    ) -> Result<Self> {
        ensure!(
            (1..=REVERSE_DEPENDENCIES_PER_PAGE).contains(&reverse_dependencies_per_page),
            "reverse-dependency page size must be between 1 and 100"
        );

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(HTTP_TIMEOUT)
            .build()
            .context("failed to build crates.io HTTP client")?;

        Ok(Self {
            inner: Arc::new(ClientInner {
                http,
                api_base,
                index_base,
                next_api_request: Mutex::new(Instant::now()),
                api_request_interval,
                reverse_dependencies_per_page,
            }),
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RequestClass {
    Api,
    Index,
}

#[derive(Debug, Deserialize)]
struct CrateEnvelope {
    #[serde(rename = "crate")]
    krate: ApiCrate,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    crates: Vec<ApiCrate>,
}

#[derive(Debug, Deserialize)]
struct ApiCrate {
    name: String,
    max_version: String,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    downloads: u64,
}

impl From<ApiCrate> for CrateSummary {
    fn from(value: ApiCrate) -> Self {
        Self {
            name: value.name,
            max_version: value.max_version,
            repository: value.repository.map(sanitize_repository_url),
            homepage: value.homepage,
            description: value.description,
            downloads: value.downloads,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ReverseDependenciesPage {
    #[serde(default)]
    dependencies: Vec<RepresentativeDependency>,
    #[serde(default)]
    versions: Vec<ApiDependentVersion>,
    meta: ReverseDependenciesMeta,
}

#[derive(Debug, Deserialize)]
struct ReverseDependenciesMeta {
    total: usize,
}

#[derive(Debug, Deserialize)]
struct ApiDependentVersion {
    id: u64,
    #[serde(rename = "crate")]
    dependent_name: String,
    #[serde(rename = "num")]
    dependent_version: String,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SparseIndexEntry {
    vers: String,
    #[serde(default)]
    deps: Vec<SparseIndexDependency>,
}

#[derive(Debug, Deserialize)]
struct SparseIndexDependency {
    name: String,
    req: String,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    registry: Option<String>,
}

fn join_reverse_page(page: ReverseDependenciesPage) -> Result<Vec<ReverseDependencyCandidate>> {
    let mut versions = HashMap::with_capacity(page.versions.len());
    for version in page.versions {
        let version_id = version.id;
        ensure!(
            versions.insert(version_id, version).is_none(),
            "crates.io reverse-dependency page contains duplicate version ID {version_id}"
        );
    }

    page.dependencies
        .into_iter()
        .map(|representative| {
            let version = versions.get(&representative.version_id).with_context(|| {
                format!(
                    "crates.io reverse-dependency row {} references missing version ID {}",
                    representative.id, representative.version_id
                )
            })?;
            let dependent_downloads = representative.downloads;

            Ok(ReverseDependencyCandidate {
                version_id: version.id,
                dependent_name: version.dependent_name.clone(),
                dependent_version: version.dependent_version.clone(),
                dependent_yanked: version.yanked,
                repository: version.repository.clone().map(sanitize_repository_url),
                dependent_downloads,
                representative,
                declarations: Vec::new(),
                declaration_enrichment_error: None,
            })
        })
        .collect()
}

fn sanitize_repository_url(value: String) -> String {
    if value.chars().any(char::is_control) {
        return "[repository URL omitted: invalid control character]".to_owned();
    }
    let Ok(mut url) = Url::parse(&value) else {
        return value;
    };
    if !url.username().is_empty() {
        let _ = url.set_username("");
    }
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.into()
}

fn representative_declaration(representative: &RepresentativeDependency) -> DependencyDeclaration {
    DependencyDeclaration {
        dependency_name: representative.crate_id.clone(),
        package_name: representative.crate_id.clone(),
        req: representative.req.clone(),
        kind: representative.kind.clone(),
        optional: representative.optional,
        target: representative.target.clone(),
        registry: None,
    }
}

fn has_another_reverse_page(
    page_len: usize,
    unique_collected: usize,
    reported_total: usize,
    per_page: usize,
) -> bool {
    page_len == per_page && unique_collected < reported_total
}

fn extract_index_declarations(
    body: &str,
    dependent_version: &str,
    target_crate: &str,
) -> Result<Vec<DependencyDeclaration>> {
    let mut selected = None;
    for (line_number, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry: SparseIndexEntry = serde_json::from_str(line)
            .with_context(|| format!("invalid sparse-index JSON on line {}", line_number + 1))?;
        if entry.vers == dependent_version {
            selected = Some(entry);
            break;
        }
    }

    let entry =
        selected.with_context(|| format!("sparse index has no release `{dependent_version}`"))?;
    let target_identity = canonical_crate_name(target_crate);
    let declarations = entry
        .deps
        .into_iter()
        .filter_map(|dependency| {
            let package_name = dependency
                .package
                .clone()
                .unwrap_or_else(|| dependency.name.clone());
            (canonical_crate_name(&package_name) == target_identity).then(|| {
                DependencyDeclaration {
                    dependency_name: dependency.name,
                    package_name,
                    req: dependency.req,
                    kind: dependency.kind.unwrap_or_else(default_dependency_kind),
                    optional: dependency.optional,
                    target: dependency.target,
                    registry: dependency.registry,
                }
            })
        })
        .collect::<Vec<_>>();

    ensure!(
        !declarations.is_empty(),
        "sparse-index release `{dependent_version}` has no declaration for `{target_crate}`"
    );
    Ok(declarations)
}

/// crates.io's canonical comparison form for package identities.
pub fn canonical_crate_name(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

/// Return the documented sparse-index path for a crates.io package name.
pub fn sparse_index_path(name: &str) -> Result<String> {
    ensure!(!name.is_empty(), "crate name must not be empty");
    ensure!(
        name.is_ascii()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid crates.io package name `{name}`"
    );

    let lower = name.to_ascii_lowercase();
    let path = match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    };
    Ok(path)
}

fn endpoint_url(base: &Url, segments: &[&str]) -> Result<Url> {
    let mut url = base.clone();
    let mut path = url
        .path_segments_mut()
        .map_err(|()| anyhow!("URL `{base}` cannot be a base URL"))?;
    path.pop_if_empty();
    for segment in segments {
        path.push(segment);
    }
    drop(path);
    Ok(url)
}

async fn decode_json<T: DeserializeOwned>(response: reqwest::Response, url: &Url) -> Result<T> {
    let status = response.status();
    let bytes = read_limited(response, url, API_RESPONSE_LIMIT).await?;
    if !status.is_success() {
        bail!(
            "GET `{url}` returned {status}: {}",
            response_excerpt(&bytes)
        );
    }
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON response from `{url}`"))
}

async fn decode_text(response: reqwest::Response, url: &Url) -> Result<String> {
    let status = response.status();
    let bytes = read_limited(response, url, SPARSE_INDEX_RESPONSE_LIMIT).await?;
    if !status.is_success() {
        bail!(
            "GET `{url}` returned {status}: {}",
            response_excerpt(&bytes)
        );
    }
    String::from_utf8(bytes).with_context(|| format!("non-UTF-8 response from `{url}`"))
}

async fn read_limited(mut response: reqwest::Response, url: &Url, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read response from `{url}`"))?
    {
        ensure!(
            body.len().saturating_add(chunk.len()) <= limit,
            "response from `{url}` exceeds the {limit}-byte decoded-body cap"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn response_excerpt(body: &[u8]) -> String {
    const LIMIT: usize = 512;
    let end = body.len().min(LIMIT);
    let mut excerpt = String::from_utf8_lossy(&body[..end]).into_owned();
    if body.len() > LIMIT {
        excerpt.push_str("...");
    }
    excerpt
}

fn is_transient(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn retry_delay(response: &reqwest::Response, attempt: usize) -> Option<Duration> {
    const MAX_RETRY_AFTER_SECONDS: u64 = 5;
    if let Some(retry_after) = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    {
        return retry_after
            .parse::<u64>()
            .ok()
            .filter(|seconds| *seconds <= MAX_RETRY_AFTER_SECONDS)
            .map(Duration::from_secs);
    }

    Some(Duration::from_millis(250 * (attempt as u64 + 1)))
}

fn default_true() -> bool {
    true
}

fn default_dependency_kind() -> String {
    "normal".to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    use super::*;

    #[test]
    fn repository_metadata_drops_url_credentials_queries_and_fragments() {
        let sanitized = sanitize_repository_url(
            "https://user:secret@github.com/example/project?token=secret#fragment".to_owned(),
        );
        assert_eq!(sanitized, "https://github.com/example/project");
        assert!(!sanitized.contains("secret"));
        assert_eq!(
            sanitize_repository_url("https://github.com/example/project\nforged".to_owned()),
            "[repository URL omitted: invalid control character]"
        );
    }

    fn representative(id: u64, version_id: u64) -> RepresentativeDependency {
        RepresentativeDependency {
            id,
            version_id,
            crate_id: "fs2".to_owned(),
            req: "^0.4.3".to_owned(),
            optional: false,
            default_features: true,
            features: Vec::new(),
            target: None,
            kind: "normal".to_owned(),
            downloads: id * 100,
        }
    }

    fn dependent_version(id: u64, name: &str) -> ApiDependentVersion {
        ApiDependentVersion {
            id,
            dependent_name: name.to_owned(),
            dependent_version: "1.0.0".to_owned(),
            yanked: false,
            repository: Some(format!("https://github.com/example/{name}")),
        }
    }

    #[test]
    fn reverse_page_join_uses_version_id_not_array_position() {
        let page = ReverseDependenciesPage {
            dependencies: vec![representative(2, 20), representative(1, 10)],
            versions: vec![
                dependent_version(10, "alpha"),
                dependent_version(20, "beta"),
            ],
            meta: ReverseDependenciesMeta { total: 2 },
        };

        let joined = join_reverse_page(page).unwrap();
        assert_eq!(joined[0].dependent_name, "beta");
        assert_eq!(joined[0].version_id, 20);
        assert_eq!(joined[1].dependent_name, "alpha");
        assert_eq!(joined[1].version_id, 10);
    }

    #[test]
    fn pagination_stops_on_total_or_short_page() {
        assert!(has_another_reverse_page(100, 100, 201, 100));
        assert!(!has_another_reverse_page(100, 100, 100, 100));
        assert!(!has_another_reverse_page(99, 99, 201, 100));
        assert!(!has_another_reverse_page(0, 0, 1, 100));
    }

    #[test]
    fn canonical_names_and_sparse_index_paths_follow_cargo_rules() {
        assert_eq!(canonical_crate_name("Serde-JSON"), "serde_json");
        assert_eq!(canonical_crate_name("serde_json"), "serde_json");
        assert_eq!(sparse_index_path("a").unwrap(), "1/a");
        assert_eq!(sparse_index_path("AB").unwrap(), "2/ab");
        assert_eq!(sparse_index_path("Fs2").unwrap(), "3/f/fs2");
        assert_eq!(sparse_index_path("Serde").unwrap(), "se/rd/serde");
        assert!(sparse_index_path("").is_err());
        assert!(sparse_index_path("owner/repo").is_err());
    }

    #[test]
    fn sparse_index_extraction_keeps_renamed_and_duplicate_declarations() {
        let body = [
            json!({"name":"consumer","vers":"0.9.0","deps":[]}).to_string(),
            json!({
                "name": "consumer",
                "vers": "1.0.0",
                "deps": [
                    {"name":"filesystem","package":"fs2","req":"=0.4.3","kind":"normal","optional":false,"target":null,"registry":null},
                    {"name":"fs2","req":"^0.4.3","kind":"build","optional":true,"target":"cfg(windows)","registry":null},
                    {"name":"fs4","req":"1","kind":"normal","optional":false}
                ],
                "unknown_future_field": true
            })
            .to_string(),
        ]
        .join("\n");

        let declarations = extract_index_declarations(&body, "1.0.0", "FS2").unwrap();
        assert_eq!(declarations.len(), 2);
        assert_eq!(declarations[0].dependency_name, "filesystem");
        assert_eq!(declarations[0].package_name, "fs2");
        assert_eq!(declarations[0].req, "=0.4.3");
        assert_eq!(declarations[1].kind, "build");
        assert!(declarations[1].optional);
        assert_eq!(declarations[1].target.as_deref(), Some("cfg(windows)"));
    }

    #[tokio::test]
    async fn reverse_dependencies_fetches_every_page_and_enriches() {
        let server = MockServer::start().await;
        let api_path = "/api/v1/crates/fs2/reverse_dependencies";

        Mock::given(method("GET"))
            .and(path(api_path))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dependencies": [
                    {"id":2,"version_id":20,"crate_id":"fs2","req":"^0.4.3","kind":"normal","downloads":200},
                    {"id":1,"version_id":10,"crate_id":"fs2","req":"^0.4.3","kind":"normal","downloads":100}
                ],
                "versions": [
                    {"id":10,"crate":"alpha","num":"1.0.0","yanked":false,"repository":"https://github.com/example/alpha"},
                    {"id":20,"crate":"beta","num":"1.0.0","yanked":false,"repository":"https://github.com/example/beta"}
                ],
                "meta":{"total":3},
                "unknown": "ignored"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(api_path))
            .and(query_param("page", "2"))
            .and(query_param("per_page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dependencies": [
                    {"id":3,"version_id":30,"crate_id":"fs2","req":"=0.4.3","kind":"dev","downloads":50}
                ],
                "versions": [
                    {"id":30,"crate":"gamma","num":"1.0.0","yanked":false,"repository":null}
                ],
                "meta":{"total":3}
            })))
            .expect(1)
            .mount(&server)
            .await;

        for (name, dependency) in [
            (
                "alpha",
                json!({"name":"fs2","req":"^0.4.3","kind":"normal","optional":false}),
            ),
            (
                "beta",
                json!({"name":"filesystem","package":"fs2","req":"=0.4.3","kind":"build","optional":true}),
            ),
            (
                "gamma",
                json!({"name":"fs2","req":"^0.4","kind":"dev","optional":false}),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/index/{}", sparse_index_path(name).unwrap())))
                .respond_with(ResponseTemplate::new(200).set_body_string(
                    json!({"name":name,"vers":"1.0.0","deps":[dependency]}).to_string(),
                ))
                .expect(1)
                .mount(&server)
                .await;
        }

        let client = CratesIoClient::with_configuration(
            Url::parse(&format!("{}/api/v1/", server.uri())).unwrap(),
            Url::parse(&format!("{}/index/", server.uri())).unwrap(),
            Duration::ZERO,
            2,
        )
        .unwrap();

        let candidates = client.reverse_dependencies("fs2").await.unwrap();
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].dependent_name, "beta");
        assert_eq!(candidates[0].version_id, 20);
        assert_eq!(candidates[0].declarations[0].dependency_name, "filesystem");
        assert!(candidates[0].declaration_enrichment_error.is_none());
        assert_eq!(candidates[1].dependent_name, "alpha");
        assert_eq!(candidates[2].dependent_name, "gamma");
        assert_eq!(candidates[2].representative.kind, "dev");
    }

    #[tokio::test]
    async fn reverse_dependency_limit_stops_before_more_pages_and_enrichment() {
        let server = MockServer::start().await;
        let api_path = "/api/v1/crates/fs2/reverse_dependencies";
        Mock::given(method("GET"))
            .and(path(api_path))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dependencies": [
                    {"id":1,"version_id":10,"crate_id":"fs2","req":"^0.4.3","kind":"normal","downloads":100},
                    {"id":2,"version_id":20,"crate_id":"fs2","req":"^0.4.3","kind":"normal","downloads":90}
                ],
                "versions": [
                    {"id":10,"crate":"alpha","num":"1.0.0","yanked":false,"repository":null},
                    {"id":20,"crate":"beta","num":"1.0.0","yanked":false,"repository":null}
                ],
                "meta":{"total":3}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/index/{}",
                sparse_index_path("alpha").unwrap()
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    json!({"name":"alpha","vers":"1.0.0","deps":[{"name":"fs2","req":"^0.4.3"}]})
                        .to_string(),
                ),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = CratesIoClient::with_configuration(
            Url::parse(&format!("{}/api/v1/", server.uri())).unwrap(),
            Url::parse(&format!("{}/index/", server.uri())).unwrap(),
            Duration::ZERO,
            2,
        )
        .unwrap();
        let candidates = client
            .reverse_dependencies_limited("fs2", Some(1))
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].dependent_name, "alpha");
    }

    #[tokio::test]
    async fn sparse_index_failure_retains_representative_evidence() {
        let server = MockServer::start().await;
        let client = CratesIoClient::with_configuration(
            Url::parse(&format!("{}/api/v1/", server.uri())).unwrap(),
            Url::parse(&format!("{}/index/", server.uri())).unwrap(),
            Duration::ZERO,
            2,
        )
        .unwrap();
        let page = ReverseDependenciesPage {
            dependencies: vec![representative(1, 10)],
            versions: vec![dependent_version(10, "alpha")],
            meta: ReverseDependenciesMeta { total: 1 },
        };
        let candidates = join_reverse_page(page).unwrap();

        let enriched = client.enrich_declarations(candidates).await;
        assert_eq!(enriched.len(), 1);
        assert_eq!(enriched[0].declarations.len(), 1);
        assert_eq!(enriched[0].declarations[0].package_name, "fs2");
        assert_eq!(enriched[0].declarations[0].req, "^0.4.3");
        assert!(enriched[0].declaration_enrichment_error.is_some());
    }

    #[tokio::test]
    async fn does_not_retry_before_a_long_retry_after_delay() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/fs2"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "60")
                    .set_body_json(json!({"error":"rate limited"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = CratesIoClient::with_configuration(
            Url::parse(&format!("{}/api/v1/", server.uri())).unwrap(),
            Url::parse(&format!("{}/index/", server.uri())).unwrap(),
            Duration::ZERO,
            2,
        )
        .unwrap();
        let error = client.lookup_exact("fs2").await.unwrap_err();
        assert!(error.to_string().contains("429"));
    }

    #[tokio::test]
    async fn lookup_and_search_ignore_unknown_optional_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/FS2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "crate": {
                    "name":"fs2",
                    "max_version":"0.4.3",
                    "downloads":123,
                    "repository":"https://github.com/danburkert/fs2-rs",
                    "future_field": {"anything":true}
                },
                "versions": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/crates"))
            .and(query_param("q", "fs"))
            .and(query_param("sort", "relevance"))
            .and(query_param("include_yanked", "no"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "crates":[
                    {"name":"fs2","max_version":"0.4.3","unknown":1},
                    {"name":"fs4","max_version":"1.0.0","downloads":5}
                ],
                "meta":{"total":2,"unknown":true}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = CratesIoClient::with_configuration(
            Url::parse(&format!("{}/api/v1/", server.uri())).unwrap(),
            Url::parse(&format!("{}/index/", server.uri())).unwrap(),
            Duration::ZERO,
            2,
        )
        .unwrap();

        let exact = client.lookup_exact("FS2").await.unwrap().unwrap();
        assert_eq!(exact.name, "fs2");
        assert_eq!(exact.downloads, 123);

        let results = client.search("fs", 2).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].downloads, 0);
        assert_eq!(results[1].name, "fs4");
    }
}
