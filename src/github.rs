use std::{error::Error as StdError, fmt, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use reqwest::{
    Client, Response, StatusCode,
    header::{
        ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT,
    },
    redirect::Policy,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;

const GITHUB_API_BASE: &str = "https://api.github.com/";
const GITHUB_API_VERSION: &str = "2026-03-10";
const JSON_MEDIA_TYPE: &str = "application/vnd.github+json";
const RAW_MEDIA_TYPE: &str = "application/vnd.github.raw+json";
const MAX_ATTEMPTS: usize = 3;
const MAX_SHORT_RETRY_AFTER: Duration = Duration::from_secs(5);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ERROR_BODY_LIMIT: u64 = 16 * 1024;
const JSON_RESPONSE_LIMIT: u64 = 16 * 1024 * 1024;
const JSON_BLOB_OVERHEAD: u64 = 64 * 1024;
const REST_SEARCH_LIMIT: usize = 1_000;
const REST_SEARCH_PAGE_SIZE: usize = 100;

/// An owner/name pair identifying a repository on github.com.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct GitHubRepo {
    pub owner: String,
    pub name: String,
}

impl GitHubRepo {
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Option<Self> {
        let owner = owner.into();
        let name = name.into();
        let name = strip_dot_git(&name).to_owned();
        if valid_owner(&owner) && valid_repo_name(&name) {
            Some(Self { owner, name })
        } else {
            None
        }
    }

    /// Parse `owner/repo` or a common github.com repository URL.
    pub fn parse(input: &str) -> Option<Self> {
        parse_github_repo(input)
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

impl fmt::Display for GitHubRepo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

impl FromStr for GitHubRepo {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if github_url_has_disallowed_components(value) {
            bail!(
                "GitHub repository URLs must not contain credentials, a query string, or a fragment"
            );
        }
        parse_github_repo(value)
            .ok_or_else(|| anyhow!("not a canonical github.com repository identifier: {value}"))
    }
}

/// Parse a GitHub repository identifier without treating a bare name as a repository.
pub fn parse_github_repo(input: &str) -> Option<GitHubRepo> {
    let input = input.trim();
    if input.is_empty() || input.chars().any(char::is_control) {
        return None;
    }

    if let Some((username, path)) = github_scp_like_parts(input) {
        if username != "git" || path.contains('?') || path.contains('#') {
            return None;
        }
        return repo_from_path(path, false);
    }

    if !input.contains("://") {
        return repo_from_path(input, true);
    }

    if github_url_has_disallowed_components(input) {
        return None;
    }
    let url = Url::parse(input).ok()?;
    let scheme = url.scheme().strip_prefix("git+").unwrap_or(url.scheme());
    if !matches!(scheme, "http" | "https" | "ssh" | "git") {
        return None;
    }

    let host = url.host_str()?.trim_end_matches('.');
    let segments = url
        .path_segments()?
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if host.eq_ignore_ascii_case("github.com") || host.eq_ignore_ascii_case("www.github.com") {
        let owner = *segments.first()?;
        let name = *segments.get(1)?;
        if reserved_github_route(owner) {
            return None;
        }
        return GitHubRepo::new(owner, name);
    }

    if host.eq_ignore_ascii_case("api.github.com")
        && segments
            .first()
            .is_some_and(|part| part.eq_ignore_ascii_case("repos"))
    {
        return GitHubRepo::new(*segments.get(1)?, *segments.get(2)?);
    }

    None
}

/// Return whether a github.com URL contains components which must never be
/// retained as a repository identifier or echoed as an ordinary search term.
///
/// The `git` username is part of GitHub's canonical SSH clone form, rather
/// than a credential. HTTP(S) userinfo, passwords, queries, and fragments are
/// rejected because they commonly carry credentials or other sensitive data.
pub fn github_url_has_disallowed_components(input: &str) -> bool {
    if let Some((username, path)) = github_scp_like_parts(input.trim()) {
        return username != "git" || path.contains('?') || path.contains('#');
    }
    let Ok(url) = Url::parse(input.trim()) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    if !matches_github_host(host) {
        return false;
    }

    let scheme = url.scheme().strip_prefix("git+").unwrap_or(url.scheme());
    let username = url.username();
    let canonical_ssh_user = matches!(scheme, "ssh" | "git") && username == "git";
    let disallowed_userinfo =
        url.password().is_some() || (!username.is_empty() && !canonical_ssh_user);

    disallowed_userinfo || url.query().is_some() || url.fragment().is_some()
}

fn github_scp_like_parts(input: &str) -> Option<(&str, &str)> {
    let (username, remainder) = input.split_once('@')?;
    let (host, path) = remainder.split_once(':')?;
    host.eq_ignore_ascii_case("github.com")
        .then_some((username, path))
}

fn matches_github_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case("github.com")
        || host.eq_ignore_ascii_case("www.github.com")
        || host.eq_ignore_ascii_case("api.github.com")
}

fn repo_from_path(path: &str, require_exactly_two_segments: bool) -> Option<GitHubRepo> {
    let path = path.trim_matches('/');
    let segments = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 2 || (require_exactly_two_segments && segments.len() != 2) {
        return None;
    }
    GitHubRepo::new(segments[0], segments[1])
}

fn strip_dot_git(name: &str) -> &str {
    name.strip_suffix(".git").unwrap_or(name)
}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 39
        && owner.is_ascii()
        && owner.starts_with(|ch: char| ch.is_ascii_alphanumeric())
        && owner.ends_with(|ch: char| ch.is_ascii_alphanumeric())
        && owner
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn valid_repo_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name.is_ascii()
        && name != "."
        && name != ".."
        && !name.contains('%')
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn reserved_github_route(owner: &str) -> bool {
    const RESERVED: &[&str] = &[
        "about",
        "codespaces",
        "collections",
        "enterprise",
        "explore",
        "features",
        "issues",
        "join",
        "login",
        "marketplace",
        "new",
        "notifications",
        "orgs",
        "pricing",
        "pulls",
        "search",
        "settings",
        "site",
        "sponsors",
        "topics",
        "users",
    ];
    RESERVED
        .iter()
        .any(|route| owner.eq_ignore_ascii_case(route))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubOwner {
    pub login: String,
    pub id: u64,
    pub html_url: Url,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubRepository {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub html_url: Url,
    pub owner: GitHubOwner,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub pushed_at: Option<DateTime<Utc>>,
}

impl GitHubRepository {
    pub fn repo(&self) -> GitHubRepo {
        GitHubRepo {
            owner: self.owner.login.clone(),
            name: self.name.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubRepositorySummary {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub html_url: Url,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub private: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct GitHubHead {
    pub sha: String,
    pub tree_sha: String,
    pub committed_at: DateTime<Utc>,
    pub authored_at: Option<DateTime<Utc>>,
    pub html_url: Option<Url>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubTree {
    pub sha: String,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub tree: Vec<GitHubTreeEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubTreeEntry {
    pub path: String,
    pub mode: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub sha: String,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub url: Option<Url>,
}

impl GitHubTreeEntry {
    pub fn is_blob(&self) -> bool {
        self.kind == "blob"
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubCodeSearchItem {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub url: Url,
    pub html_url: Url,
    pub repository: GitHubRepositorySummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct GitHubSearchResult<T> {
    pub total_count: u64,
    pub incomplete_results: bool,
    pub items: Vec<T>,
}

impl<T> Default for GitHubSearchResult<T> {
    fn default() -> Self {
        Self {
            total_count: 0,
            incomplete_results: false,
            items: Vec::new(),
        }
    }
}

impl<T> GitHubSearchResult<T> {
    pub fn returned_count(&self) -> usize {
        self.items.len()
    }

    pub fn bounded(&self) -> bool {
        self.total_count > self.items.len() as u64 || self.incomplete_results
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubRateLimit {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub used: Option<u64>,
    pub reset_epoch: Option<u64>,
    pub resource: Option<String>,
    pub retry_after: Option<String>,
}

impl GitHubRateLimit {
    fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let details = Self {
            limit: numeric_header(headers, "x-ratelimit-limit"),
            remaining: numeric_header(headers, "x-ratelimit-remaining"),
            used: numeric_header(headers, "x-ratelimit-used"),
            reset_epoch: numeric_header(headers, "x-ratelimit-reset"),
            resource: text_header(headers, "x-ratelimit-resource"),
            retry_after: headers
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        };
        if details.limit.is_some()
            || details.remaining.is_some()
            || details.used.is_some()
            || details.reset_epoch.is_some()
            || details.resource.is_some()
            || details.retry_after.is_some()
        {
            Some(details)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub struct GitHubApiError {
    pub status: StatusCode,
    pub message: String,
    pub documentation_url: Option<String>,
    pub rate_limit: Option<GitHubRateLimit>,
}

impl fmt::Display for GitHubApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitHub API returned {}: {}", self.status, self.message)?;
        if let Some(rate) = &self.rate_limit {
            write!(f, " [rate limit")?;
            if let Some(resource) = &rate.resource {
                write!(f, " resource={resource}")?;
            }
            if let Some(remaining) = rate.remaining {
                write!(f, " remaining={remaining}")?;
                if let Some(limit) = rate.limit {
                    write!(f, "/{limit}")?;
                }
            }
            if let Some(used) = rate.used {
                write!(f, " used={used}")?;
            }
            if let Some(reset) = rate.reset_epoch {
                write!(f, " reset_epoch={reset}")?;
            }
            if let Some(retry_after) = &rate.retry_after {
                write!(f, " retry_after={retry_after}")?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

impl StdError for GitHubApiError {}

/// A small REST client for read-only GitHub inventory operations.
#[derive(Clone)]
pub struct GitHubClient {
    client: Client,
    api_base: Url,
    token: Option<Arc<str>>,
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Result<Self> {
        Self::with_api_base(
            token,
            Url::parse(GITHUB_API_BASE).expect("static URL is valid"),
        )
    }

    pub(crate) fn with_api_base(token: Option<String>, api_base: Url) -> Result<Self> {
        ensure!(
            !api_base.cannot_be_a_base(),
            "GitHub API base URL cannot be a base URL"
        );

        let token = token
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(Arc::<str>::from);
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
                " dependency-inventory"
            )),
        );
        headers.insert(ACCEPT, HeaderValue::from_static(JSON_MEDIA_TYPE));
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        if let Some(secret) = &token {
            let mut authorization = HeaderValue::from_str(&format!("Bearer {secret}"))
                .context("GitHub token is not valid as an HTTP authorization value")?;
            authorization.set_sensitive(true);
            headers.insert(AUTHORIZATION, authorization);
        }

        let client = Client::builder()
            .default_headers(headers)
            .redirect(Policy::limited(5))
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .context("failed to build GitHub HTTP client")?;
        Ok(Self {
            client,
            api_base,
            token,
        })
    }

    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    pub async fn repository(&self, repo: &GitHubRepo) -> Result<GitHubRepository> {
        let url = self.endpoint(["repos", repo.owner.as_str(), repo.name.as_str()])?;
        let repository: GitHubRepository = self
            .get_json(url)
            .await
            .with_context(|| format!("failed to read GitHub repository {repo}"))?;
        Ok(repository)
    }

    pub async fn default_branch_head(&self, repository: &GitHubRepository) -> Result<GitHubHead> {
        let branch = repository
            .default_branch
            .as_deref()
            .filter(|branch| !branch.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "GitHub repository {} has no default branch",
                    repository.full_name
                )
            })?;
        self.branch_head(&repository.repo(), branch).await
    }

    pub async fn branch_head(&self, repo: &GitHubRepo, branch: &str) -> Result<GitHubHead> {
        ensure!(!branch.is_empty(), "GitHub branch name cannot be empty");
        let url = self.endpoint([
            "repos",
            repo.owner.as_str(),
            repo.name.as_str(),
            "commits",
            branch,
        ])?;
        let response: CommitResponse = self
            .get_json(url)
            .await
            .with_context(|| format!("failed to read {repo} branch {branch}"))?;
        let committed_at = response
            .commit
            .committer
            .as_ref()
            .or(response.commit.author.as_ref())
            .map(|signature| signature.date)
            .ok_or_else(|| anyhow!("GitHub commit {} has no commit timestamp", response.sha))?;
        Ok(GitHubHead {
            sha: response.sha,
            tree_sha: response.commit.tree.sha,
            committed_at,
            authored_at: response.commit.author.map(|signature| signature.date),
            html_url: response.html_url,
        })
    }

    pub async fn recursive_tree(&self, repo: &GitHubRepo, tree_sha: &str) -> Result<GitHubTree> {
        ensure!(!tree_sha.is_empty(), "GitHub tree SHA cannot be empty");
        let mut url = self.endpoint([
            "repos",
            repo.owner.as_str(),
            repo.name.as_str(),
            "git",
            "trees",
            tree_sha,
        ])?;
        url.query_pairs_mut().append_pair("recursive", "1");
        self.get_json(url)
            .await
            .with_context(|| format!("failed to read recursive Git tree {tree_sha} for {repo}"))
    }

    pub async fn blob_by_sha(
        &self,
        repo: &GitHubRepo,
        blob_sha: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        ensure!(!blob_sha.is_empty(), "GitHub blob SHA cannot be empty");
        let url = self.endpoint([
            "repos",
            repo.owner.as_str(),
            repo.name.as_str(),
            "git",
            "blobs",
            blob_sha,
        ])?;
        let response = self.send_get(url, RAW_MEDIA_TYPE).await?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let declared_json_envelope = content_type
            .as_deref()
            .is_some_and(is_json_envelope_content_type);
        let body = read_limited(response, encoded_blob_limit(max_bytes))
            .await
            .with_context(|| {
                format!("GitHub blob {blob_sha} for {repo} exceeds the download cap")
            })?;

        let looks_like_json = body
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(b'{');
        let envelope = if declared_json_envelope || looks_like_json {
            match serde_json::from_slice::<BlobResponse>(&body) {
                Ok(envelope) => Some(envelope),
                Err(error) if declared_json_envelope => {
                    return Err(error)
                        .with_context(|| format!("GitHub blob {blob_sha} returned invalid JSON"));
                }
                Err(_) => None,
            }
        } else {
            None
        };
        if let Some(envelope) = envelope {
            ensure!(
                envelope.encoding.eq_ignore_ascii_case("base64"),
                "GitHub blob {blob_sha} uses unsupported encoding {}",
                envelope.encoding
            );
            if let Some(size) = envelope.size {
                ensure!(
                    size <= max_bytes,
                    "GitHub blob {blob_sha} is {size} bytes, exceeding the {max_bytes}-byte cap"
                );
            }
            let decoded = decode_base64(&envelope.content)
                .with_context(|| format!("GitHub blob {blob_sha} has invalid base64 content"))?;
            ensure!(
                decoded.len() as u64 <= max_bytes,
                "GitHub blob {blob_sha} is {} bytes, exceeding the {max_bytes}-byte cap",
                decoded.len()
            );
            return Ok(decoded);
        }

        ensure!(
            body.len() as u64 <= max_bytes,
            "GitHub blob {blob_sha} is {} bytes, exceeding the {max_bytes}-byte cap",
            body.len()
        );
        Ok(body)
    }

    /// Run the legacy REST code search, bounded to at most 1,000 returned files.
    pub async fn search_code(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<GitHubSearchResult<GitHubCodeSearchItem>> {
        ensure!(
            self.is_authenticated(),
            "GitHub REST code search requires authentication"
        );
        self.search("code", query, limit).await
    }

    /// Search repository names using GitHub's best-match ordering.
    pub async fn search_repositories_by_name(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<GitHubSearchResult<GitHubRepository>> {
        let name = name.trim();
        ensure!(
            !name.is_empty(),
            "GitHub repository search name cannot be empty"
        );
        ensure!(
            !name.chars().any(char::is_control),
            "GitHub repository search name contains a control character"
        );
        let mut result: GitHubSearchResult<GitHubRepository> = self
            .search("repositories", &format!("{name} in:name is:public"), limit)
            .await?;
        // Keep the public-only boundary even if a future API behavior change or
        // an intermediary ignores the visibility qualifier.
        result.items.retain(|repository| !repository.private);
        Ok(result)
    }

    async fn search<T>(
        &self,
        kind: &str,
        query: &str,
        limit: usize,
    ) -> Result<GitHubSearchResult<T>>
    where
        T: DeserializeOwned,
    {
        ensure!(
            !query.trim().is_empty(),
            "GitHub search query cannot be empty"
        );
        ensure!(
            limit <= REST_SEARCH_LIMIT,
            "GitHub REST search returns at most {REST_SEARCH_LIMIT} results per query"
        );
        if limit == 0 {
            return Ok(GitHubSearchResult {
                total_count: 0,
                incomplete_results: false,
                items: Vec::new(),
            });
        }

        let mut result = GitHubSearchResult {
            total_count: 0,
            incomplete_results: false,
            items: Vec::with_capacity(limit),
        };
        let mut page = 1usize;
        while result.items.len() < limit {
            let page_size = (limit - result.items.len()).min(REST_SEARCH_PAGE_SIZE);
            let mut url = self.endpoint(["search", kind])?;
            url.query_pairs_mut()
                .append_pair("q", query)
                .append_pair("per_page", &page_size.to_string())
                .append_pair("page", &page.to_string());
            let page_result: SearchResponse<T> = self
                .get_json(url)
                .await
                .with_context(|| format!("GitHub {kind} search failed"))?;
            result.total_count = result.total_count.max(page_result.total_count);
            result.incomplete_results |= page_result.incomplete_results;
            let returned = page_result.items.len();
            result.items.extend(page_result.items);
            if returned < page_size || result.items.len() as u64 >= result.total_count {
                break;
            }
            page += 1;
        }
        result.items.truncate(limit);
        Ok(result)
    }

    async fn get_json<T: DeserializeOwned>(&self, url: Url) -> Result<T> {
        let path = url.path().to_owned();
        let response = self.send_get(url, JSON_MEDIA_TYPE).await?;
        let body = read_limited(response, JSON_RESPONSE_LIMIT)
            .await
            .with_context(|| format!("failed to read bounded GitHub JSON response for {path}"))?;
        serde_json::from_slice(&body)
            .with_context(|| format!("GitHub returned invalid JSON for {path}"))
    }

    async fn send_get(&self, url: Url, accept: &'static str) -> Result<Response> {
        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .client
                .get(url.clone())
                .header(ACCEPT, accept)
                .send()
                .await
                .with_context(|| format!("GitHub request failed for {}", url.path()))?;
            if response.status().is_success() {
                return Ok(response);
            }

            if attempt + 1 < MAX_ATTEMPTS {
                match retry_action(response.status(), response.headers(), attempt, Utc::now()) {
                    RetryAction::RetryAfter(delay) => {
                        drop(response);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    RetryAction::DoNotWaitForFarReset | RetryAction::DoNotRetry => {}
                }
            }
            return Err(self.api_error(response).await.into());
        }
        unreachable!("GitHub request retry loop always returns")
    }

    async fn api_error(&self, mut response: Response) -> GitHubApiError {
        let status = response.status();
        let rate_limit = GitHubRateLimit::from_headers(response.headers());
        let body = read_error_body(&mut response).await;
        let envelope = serde_json::from_slice::<ApiErrorResponse>(&body).ok();
        let raw_message = envelope
            .as_ref()
            .and_then(|error| error.message.clone())
            .unwrap_or_else(|| {
                let text = String::from_utf8_lossy(&body);
                if text.trim().is_empty() {
                    status
                        .canonical_reason()
                        .unwrap_or("request failed")
                        .to_owned()
                } else {
                    text.chars().take(512).collect()
                }
            });
        GitHubApiError {
            status,
            message: self.redact(&raw_message),
            documentation_url: envelope.and_then(|error| error.documentation_url),
            rate_limit,
        }
    }

    fn redact(&self, value: &str) -> String {
        self.token.as_ref().map_or_else(
            || value.to_owned(),
            |token| value.replace(token.as_ref(), "[REDACTED]"),
        )
    }

    fn endpoint<'a>(&self, segments: impl IntoIterator<Item = &'a str>) -> Result<Url> {
        let mut url = self.api_base.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|()| anyhow!("GitHub API base URL cannot accept path segments"))?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }
}

#[derive(Debug, Deserialize)]
struct CommitResponse {
    sha: String,
    #[serde(default)]
    html_url: Option<Url>,
    commit: CommitDetails,
}

#[derive(Debug, Deserialize)]
struct CommitDetails {
    #[serde(default)]
    author: Option<CommitSignature>,
    #[serde(default)]
    committer: Option<CommitSignature>,
    tree: TreePointer,
}

#[derive(Debug, Deserialize)]
struct CommitSignature {
    date: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct TreePointer {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct BlobResponse {
    content: String,
    encoding: String,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse<T> {
    total_count: u64,
    #[serde(default)]
    incomplete_results: bool,
    items: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    documentation_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryAction {
    RetryAfter(Duration),
    DoNotWaitForFarReset,
    DoNotRetry,
}

fn retry_action(
    status: StatusCode,
    headers: &HeaderMap,
    attempt: usize,
    now: DateTime<Utc>,
) -> RetryAction {
    let transient =
        status == StatusCode::TOO_MANY_REQUESTS || matches!(status.as_u16(), 500 | 502 | 503 | 504);
    if !transient {
        return RetryAction::DoNotRetry;
    }

    if let Some(retry_after) = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    {
        let delay = retry_after
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
            .or_else(|| {
                DateTime::parse_from_rfc2822(retry_after).ok().map(|then| {
                    let milliseconds = (then.with_timezone(&Utc) - now).num_milliseconds().max(0);
                    Duration::from_millis(milliseconds as u64)
                })
            });
        if let Some(delay) = delay {
            return if delay <= MAX_SHORT_RETRY_AFTER {
                RetryAction::RetryAfter(delay)
            } else {
                RetryAction::DoNotWaitForFarReset
            };
        }
    }

    let multiplier = 1u64 << attempt.min(3);
    RetryAction::RetryAfter(Duration::from_millis(100 * multiplier))
}

fn numeric_header(headers: &HeaderMap, name: &'static str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}

fn text_header(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_owned)
}

async fn read_limited(mut response: Response, max_bytes: u64) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure!(
            length <= max_bytes,
            "response declared {length} bytes, exceeding the {max_bytes}-byte cap"
        );
    }
    let mut body = Vec::new();
    let mut received = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed while reading GitHub response")?
    {
        received = received.saturating_add(chunk.len() as u64);
        ensure!(
            received <= max_bytes,
            "response exceeded the {max_bytes}-byte cap while downloading"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_error_body(response: &mut Response) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < ERROR_BODY_LIMIT as usize {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = ERROR_BODY_LIMIT as usize - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    body
}

fn encoded_blob_limit(max_bytes: u64) -> u64 {
    max_bytes
        .saturating_mul(2)
        .saturating_add(JSON_BLOB_OVERHEAD)
}

fn is_json_envelope_content_type(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    (media_type == "application/json" || media_type.ends_with("+json"))
        && !media_type.contains(".raw+")
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    let compact = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    ensure!(
        compact.len() % 4 == 0,
        "base64 length is not a multiple of four"
    );
    let mut decoded = Vec::with_capacity(compact.len() / 4 * 3);
    let chunks = compact.chunks_exact(4);
    let chunk_count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        let last = index + 1 == chunk_count;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        ensure!(a < 64 && b < 64, "invalid base64 padding");
        let c = base64_value(chunk[2])?;
        let d = base64_value(chunk[3])?;
        decoded.push((a << 2) | (b >> 4));

        if c == 64 {
            ensure!(last && d == 64 && b & 0x0f == 0, "invalid base64 padding");
            continue;
        }
        decoded.push((b << 4) | (c >> 2));
        if d == 64 {
            ensure!(last && c & 0x03 == 0, "invalid base64 padding");
            continue;
        }
        decoded.push((c << 6) | d);
    }
    Ok(decoded)
}

fn base64_value(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Ok(64),
        _ => bail!("invalid base64 character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    fn test_client(server: &MockServer, token: Option<String>) -> GitHubClient {
        GitHubClient::with_api_base(
            token,
            Url::parse(&format!("{}/", server.uri())).expect("wiremock URL is valid"),
        )
        .expect("test client builds")
    }

    fn repository_json(owner: &str, name: &str, id: u64) -> serde_json::Value {
        json!({
            "id": id,
            "name": name,
            "full_name": format!("{owner}/{name}"),
            "html_url": format!("https://github.com/{owner}/{name}"),
            "owner": {
                "login": owner,
                "id": 7,
                "html_url": format!("https://github.com/{owner}")
            },
            "default_branch": "main",
            "fork": false,
            "archived": false,
            "disabled": false,
            "private": false,
            "pushed_at": "2026-08-01T12:00:00Z"
        })
    }

    #[test]
    fn parses_canonical_repository_forms() {
        for input in [
            "danburkert/fs2-rs",
            "https://github.com/danburkert/fs2-rs",
            "https://www.github.com/danburkert/fs2-rs.git/",
            "git+https://github.com/danburkert/fs2-rs.git",
            "ssh://git@github.com/danburkert/fs2-rs.git",
            "git@github.com:danburkert/fs2-rs.git",
            "https://github.com/danburkert/fs2-rs/tree/main",
            "https://api.github.com/repos/danburkert/fs2-rs",
        ] {
            let parsed =
                parse_github_repo(input).unwrap_or_else(|| panic!("did not parse {input}"));
            assert_eq!(parsed.full_name(), "danburkert/fs2-rs");
        }
    }

    #[test]
    fn rejects_bare_names_and_lookalike_hosts() {
        for input in [
            "fs2-rs",
            "https://github.example/danburkert/fs2-rs",
            "https://evilgithub.com/danburkert/fs2-rs",
            "https://github.com/search/code",
            "owner/repo/extra",
            "owner with spaces/repo",
            "https://user:secret@github.com/danburkert/fs2-rs",
            "https://github.com/danburkert/fs2-rs?access_token=secret",
            "https://github.com/danburkert/fs2-rs#secret",
            "ssh://other-user@github.com/danburkert/fs2-rs.git",
            "token@github.com:danburkert/fs2-rs.git",
            "git@github.com:danburkert/fs2-rs.git?token=secret",
        ] {
            assert!(
                parse_github_repo(input).is_none(),
                "unexpectedly parsed {input}"
            );
        }
    }

    #[test]
    fn detects_sensitive_url_components_without_rejecting_canonical_ssh_user() {
        assert!(github_url_has_disallowed_components(
            "https://user:secret@github.com/acme/widget"
        ));
        assert!(github_url_has_disallowed_components(
            "https://github.com/acme/widget?token=secret"
        ));
        assert!(github_url_has_disallowed_components(
            "https://github.com/acme/widget#secret"
        ));
        assert!(!github_url_has_disallowed_components(
            "ssh://git@github.com/acme/widget.git"
        ));
        assert!(github_url_has_disallowed_components(
            "token@github.com:acme/widget.git"
        ));
        let secret = "MY_FAKE_SECRET";
        let error = format!("https://user:{secret}@github.com/acme/widget")
            .parse::<GitHubRepo>()
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret));
    }

    #[tokio::test]
    async fn follows_repository_redirect_and_sends_required_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/old/project"))
            .and(header("accept", JSON_MEDIA_TYPE))
            .and(header("x-github-api-version", GITHUB_API_VERSION))
            .and(header(
                "user-agent",
                "crate-dependent-repos/0.1.0 dependency-inventory",
            ))
            .respond_with(
                ResponseTemplate::new(301)
                    .insert_header("location", format!("{}/repositories/42", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repositories/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(repository_json("new", "project", 42)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let repository = test_client(&server, None)
            .repository(&GitHubRepo::new("old", "project").unwrap())
            .await
            .unwrap();
        assert_eq!(repository.id, 42);
        assert_eq!(repository.full_name, "new/project");
    }

    #[tokio::test]
    async fn preserves_private_visibility_for_callers_to_enforce_scope() {
        let server = MockServer::start().await;
        let mut private_repository = repository_json("acme", "private-widget", 42);
        private_repository["private"] = json!(true);
        Mock::given(method("GET"))
            .and(path("/repos/acme/private-widget"))
            .respond_with(ResponseTemplate::new(200).set_body_json(private_repository))
            .expect(1)
            .mount(&server)
            .await;

        let repository = test_client(&server, Some("broad-token".to_owned()))
            .repository(&GitHubRepo::new("acme", "private-widget").unwrap())
            .await
            .unwrap();
        assert!(repository.private);
    }

    #[tokio::test]
    async fn reads_default_head_and_explicit_truncated_tree() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/commits/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sha": "head-sha",
                "html_url": "https://github.com/acme/widget/commit/head-sha",
                "commit": {
                    "author": {"date": "2026-07-31T11:00:00Z"},
                    "committer": {"date": "2026-08-01T12:00:00Z"},
                    "tree": {"sha": "tree-sha"}
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/git/trees/tree-sha"))
            .and(query_param("recursive", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sha": "tree-sha",
                "truncated": true,
                "tree": [{
                    "path": "Cargo.lock",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "blob-sha",
                    "size": 123
                }]
            })))
            .mount(&server)
            .await;

        let client = test_client(&server, None);
        let repository: GitHubRepository =
            serde_json::from_value(repository_json("acme", "widget", 1)).unwrap();
        let head = client.default_branch_head(&repository).await.unwrap();
        assert_eq!(head.sha, "head-sha");
        assert_eq!(head.tree_sha, "tree-sha");
        assert_eq!(head.committed_at.to_rfc3339(), "2026-08-01T12:00:00+00:00");

        let tree = client
            .recursive_tree(&repository.repo(), &head.tree_sha)
            .await
            .unwrap();
        assert!(tree.truncated);
        assert_eq!(tree.tree.len(), 1);
        assert!(tree.tree[0].is_blob());
    }

    #[tokio::test]
    async fn accepts_raw_and_base64_blob_responses_and_enforces_cap() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/git/blobs/raw"))
            .and(header("accept", RAW_MEDIA_TYPE))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", RAW_MEDIA_TYPE)
                    .set_body_bytes(b"hello"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/git/blobs/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sha": "json",
                "size": 5,
                "encoding": "base64",
                "content": "aGVs\nbG8="
            })))
            .mount(&server)
            .await;

        let client = test_client(&server, None);
        let repo = GitHubRepo::new("acme", "widget").unwrap();
        assert_eq!(client.blob_by_sha(&repo, "raw", 5).await.unwrap(), b"hello");
        assert_eq!(
            client.blob_by_sha(&repo, "json", 5).await.unwrap(),
            b"hello"
        );
        let error = client.blob_by_sha(&repo, "raw", 4).await.unwrap_err();
        assert!(error.to_string().contains("4-byte cap"));
    }

    #[tokio::test]
    async fn reports_rate_limits_and_redacts_token_without_waiting_for_far_retry() {
        let server = MockServer::start().await;
        let token = "github-secret-token";
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "60")
                    .insert_header("x-ratelimit-limit", "10")
                    .insert_header("x-ratelimit-remaining", "0")
                    .insert_header("x-ratelimit-used", "10")
                    .insert_header("x-ratelimit-reset", "1786236496")
                    .insert_header("x-ratelimit-resource", "code_search")
                    .set_body_json(json!({"message": format!("blocked token {token}")})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let error = test_client(&server, Some(token.to_owned()))
            .repository(&GitHubRepo::new("acme", "widget").unwrap())
            .await
            .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(!rendered.contains(token));
        assert!(rendered.contains("remaining=0/10"));
        assert!(rendered.contains("retry_after=60"));
    }

    #[tokio::test]
    async fn bounds_searches_and_keeps_incomplete_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search/code"))
            .and(query_param("q", "fs2 0.4.3 filename:Cargo.lock"))
            .and(query_param("per_page", "1"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_count": 12096,
                "incomplete_results": true,
                "items": [{
                    "name": "Cargo.lock",
                    "path": "Cargo.lock",
                    "sha": "blob",
                    "url": "https://api.github.com/repos/acme/widget/contents/Cargo.lock",
                    "html_url": "https://github.com/acme/widget/blob/main/Cargo.lock",
                    "repository": {
                        "id": 1,
                        "name": "widget",
                        "full_name": "acme/widget",
                        "html_url": "https://github.com/acme/widget",
                        "fork": false,
                        "private": false
                    }
                }]
            })))
            .mount(&server)
            .await;

        let client = test_client(&server, Some("token".to_owned()));
        let result = client
            .search_code("fs2 0.4.3 filename:Cargo.lock", 1)
            .await
            .unwrap();
        assert_eq!(result.total_count, 12_096);
        assert_eq!(result.returned_count(), 1);
        assert!(result.incomplete_results);
        assert!(result.bounded());
        assert!(client.search_code("fs2", 1_001).await.is_err());
    }

    #[tokio::test]
    async fn searches_repository_names_with_best_match_query() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search/repositories"))
            .and(query_param("q", "fs2-rs in:name is:public"))
            .and(query_param("per_page", "2"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_count": 1,
                "incomplete_results": false,
                "items": [repository_json("danburkert", "fs2-rs", 42)]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = test_client(&server, None)
            .search_repositories_by_name("fs2-rs", 2)
            .await
            .unwrap();
        assert_eq!(result.total_count, 1);
        assert_eq!(result.items[0].full_name, "danburkert/fs2-rs");
        assert!(!result.bounded());
    }

    #[test]
    fn retries_only_transient_statuses_and_short_delays() {
        let now = DateTime::parse_from_rfc3339("2026-08-09T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("2"));
        assert_eq!(
            retry_action(StatusCode::TOO_MANY_REQUESTS, &headers, 0, now),
            RetryAction::RetryAfter(Duration::from_secs(2))
        );
        headers.insert(RETRY_AFTER, HeaderValue::from_static("60"));
        assert_eq!(
            retry_action(StatusCode::TOO_MANY_REQUESTS, &headers, 0, now),
            RetryAction::DoNotWaitForFarReset
        );
        assert_eq!(
            retry_action(StatusCode::FORBIDDEN, &HeaderMap::new(), 0, now),
            RetryAction::DoNotRetry
        );
        assert_eq!(
            retry_action(StatusCode::BAD_GATEWAY, &HeaderMap::new(), 1, now),
            RetryAction::RetryAfter(Duration::from_millis(200))
        );
    }

    #[test]
    fn base64_decoder_validates_padding() {
        assert_eq!(decode_base64("Zg==").unwrap(), b"f");
        assert_eq!(decode_base64("Zm8=").unwrap(), b"fo");
        assert_eq!(decode_base64("Zm9v\n").unwrap(), b"foo");
        assert!(decode_base64("Z===").is_err());
        assert!(decode_base64("Zm9v=").is_err());
    }
}
