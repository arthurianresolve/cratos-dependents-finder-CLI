use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result, bail};
use strsim::jaro_winkler;

use crate::{
    crates_io::{CratesIoClient, canonical_crate_name},
    github::{
        GitHubClient, GitHubRepo, GitHubRepository, GitHubSearchResult, GitHubTreeEntry,
        github_url_has_disallowed_components, parse_github_repo,
    },
    model::{CrateSummary, RankedCrate, ResolutionResult},
};

const MANIFEST_DISCOVERY_LIMIT: usize = 16;
const MANIFEST_DISCOVERY_FILE_LIMIT: u64 = 512 * 1024;

#[derive(Clone, Debug)]
pub struct ResolveOptions {
    pub limit: usize,
    pub explicit_crate: Option<String>,
    pub accept_closest: bool,
}

pub async fn resolve_target(
    crates_io: &CratesIoClient,
    github: &GitHubClient,
    query: &str,
    options: ResolveOptions,
) -> Result<ResolutionResult> {
    let query = query.trim();
    validate_query(query)?;

    if let Some(explicit) = options.explicit_crate.as_deref() {
        let selected = crates_io
            .lookup_exact(explicit)
            .await?
            .with_context(|| format!("crates.io has no crate named `{explicit}`"))?;
        return Ok(exact_result(query, selected, "explicit_crate"));
    }

    if let Some(repo) = parse_github_repo(query) {
        return resolve_repository(crates_io, github, query, &repo, options.limit).await;
    }

    if let Some(exact) = crates_io.lookup_exact(query).await? {
        return Ok(exact_result(query, exact, "exact_crate"));
    }

    let mut diagnostics = Vec::new();
    let repository_matches = match github.search_repositories_by_name(query, 10).await {
        Ok(matches) => {
            if matches.bounded() {
                diagnostics.push(format!(
                    "GitHub repository-name search was bounded: returned {} of {} reported results",
                    matches.returned_count(),
                    matches.total_count
                ));
            }
            Some(matches)
        }
        Err(error) => {
            diagnostics.push(format!(
                "GitHub repository-name search was unavailable; crate ranking continued without it: {error:#}"
            ));
            None
        }
    };

    if let Some(matches) = &repository_matches {
        let exact_repositories = exact_named_repositories(query, &matches.items);
        if let Some(exact_repository) = unique_unbounded_exact_repository(query, matches) {
            let repo = exact_repository.repo();
            match resolve_repository(crates_io, github, query, &repo, options.limit).await {
                Ok(mut resolution)
                    if resolution.selected.is_some() || !resolution.alternatives.is_empty() =>
                {
                    resolution.resolution_method = match resolution.resolution_method.as_str() {
                        "repository_metadata" => "repository_name_metadata".to_owned(),
                        "repository_metadata_ambiguous" => {
                            "repository_name_metadata_ambiguous".to_owned()
                        }
                        other => format!("repository_name_{other}"),
                    };
                    diagnostics.append(&mut resolution.diagnostics);
                    resolution.diagnostics = diagnostics;
                    return Ok(resolution);
                }
                Ok(mut resolution) => {
                    diagnostics.append(&mut resolution.diagnostics);
                    diagnostics.push(
                        "the sole exact repository-name result did not map to a published crate; falling back to crate-name ranking"
                            .to_owned(),
                    );
                }
                Err(error) => diagnostics.push(format!(
                    "the exact repository-name result could not be inspected; falling back to crate-name ranking: {error:#}"
                )),
            }
        } else if !exact_repositories.is_empty() && matches.bounded() {
            diagnostics.push(format!(
                "the bounded GitHub result page contained {} exact public repository-name match(es), so uniqueness was not established; use owner/repo or explicitly accept a closest crate",
                exact_repositories.len()
            ));
        } else if exact_repositories.len() > 1 {
            diagnostics.push(format!(
                "{} public GitHub repositories in the bounded result set have this exact name; use owner/repo to disambiguate",
                exact_repositories.len()
            ));
        }
    }

    let terms = search_terms(query);
    let candidates = search_candidates(crates_io, &terms, options.limit.max(10)).await?;
    let mut ranked = rank_candidates(query, candidates, None);
    ranked.truncate(options.limit);
    Ok(ranked_resolution(
        query,
        ranked,
        options.accept_closest,
        diagnostics,
    ))
}

fn validate_query(query: &str) -> Result<()> {
    if query.is_empty() {
        bail!("crate or repository query must not be empty");
    }
    if github_url_has_disallowed_components(query) {
        bail!("GitHub repository URLs must not contain credentials, a query string, or a fragment");
    }
    Ok(())
}

async fn resolve_repository(
    crates_io: &CratesIoClient,
    github: &GitHubClient,
    input: &str,
    repo: &GitHubRepo,
    limit: usize,
) -> Result<ResolutionResult> {
    let repository = github.repository(repo).await.with_context(|| {
        format!(
            "resolving GitHub repository identity for `{}`",
            repo.full_name()
        )
    })?;
    ensure_public_repository(&repository)?;
    let canonical_repo = repository.repo();
    let terms = search_terms(&repository.name);
    let mut candidates = search_candidates(crates_io, &terms, limit.max(100))
        .await?
        .into_iter()
        .filter(|candidate| crate_belongs_to_repo(candidate, &canonical_repo))
        .map(|candidate| (canonical_crate_name(&candidate.name), candidate))
        .collect::<HashMap<_, _>>();

    let mut diagnostics = Vec::new();
    match repository_manifest_package_names(github, &repository).await {
        Ok(discovery) => {
            diagnostics.extend(discovery.diagnostics);
            let mut manifest_additions = 0usize;
            for package_name in discovery.package_names {
                let identity = canonical_crate_name(&package_name);
                if candidates.contains_key(&identity) {
                    continue;
                }
                match crates_io.lookup_exact(&package_name).await {
                    Ok(Some(candidate)) if crate_belongs_to_repo(&candidate, &canonical_repo) => {
                        candidates.insert(canonical_crate_name(&candidate.name), candidate);
                        manifest_additions += 1;
                    }
                    Ok(_) => {}
                    Err(error) => diagnostics.push(format!(
                        "crates.io lookup for a package named by a bounded repository manifest failed: {error:#}"
                    )),
                }
            }
            if manifest_additions > 0 {
                diagnostics.push(format!(
                    "bounded default-branch Cargo.toml discovery added {manifest_additions} published crate mapping(s)"
                ));
            }
        }
        Err(error) => diagnostics.push(format!(
            "bounded default-branch Cargo.toml inspection could not improve repository mapping: {error:#}"
        )),
    }
    let mut ranked = rank_candidates(
        &repository.name,
        candidates.into_values().collect(),
        Some(&canonical_repo),
    );
    ranked.truncate(limit);

    let selected = (ranked.len() == 1).then(|| ranked[0].clone());
    let alternatives = if selected.is_some() {
        Vec::new()
    } else {
        ranked
    };
    let requires_selection = selected.is_none();

    Ok(ResolutionResult {
        input: input.to_owned(),
        selected,
        alternatives,
        resolution_method: if requires_selection {
            "repository_metadata_ambiguous"
        } else {
            "repository_metadata"
        }
        .to_owned(),
        requires_selection,
        globally_exhaustive: false,
        diagnostics,
    })
}

fn ensure_public_repository(repository: &GitHubRepository) -> Result<()> {
    if repository.private {
        bail!("private GitHub repositories are outside this public inventory's scope");
    }
    Ok(())
}

fn exact_named_repositories<'a>(
    query: &str,
    repositories: &'a [GitHubRepository],
) -> Vec<&'a GitHubRepository> {
    repositories
        .iter()
        .filter(|repository| !repository.private && repository.name.eq_ignore_ascii_case(query))
        .collect()
}

fn unique_unbounded_exact_repository<'a>(
    query: &str,
    matches: &'a GitHubSearchResult<GitHubRepository>,
) -> Option<&'a GitHubRepository> {
    if matches.bounded() {
        return None;
    }
    let exact = exact_named_repositories(query, &matches.items);
    (exact.len() == 1).then_some(exact[0])
}

fn crate_belongs_to_repo(candidate: &CrateSummary, expected: &GitHubRepo) -> bool {
    candidate
        .repository
        .as_deref()
        .and_then(parse_github_repo)
        .is_some_and(|actual| {
            actual
                .full_name()
                .eq_ignore_ascii_case(&expected.full_name())
        })
}

#[derive(Debug, Default)]
struct ManifestPackageDiscovery {
    package_names: BTreeSet<String>,
    diagnostics: Vec<String>,
}

async fn repository_manifest_package_names(
    github: &GitHubClient,
    repository: &GitHubRepository,
) -> Result<ManifestPackageDiscovery> {
    let head = github.default_branch_head(repository).await?;
    let tree = github
        .recursive_tree(&repository.repo(), &head.tree_sha)
        .await?;
    let mut discovery = ManifestPackageDiscovery::default();
    if tree.truncated {
        discovery.diagnostics.push(
            "GitHub truncated the recursive tree used for bounded Cargo.toml package-name discovery"
                .to_owned(),
        );
    }

    let mut manifests = tree
        .tree
        .into_iter()
        .filter(|entry| entry.is_blob() && final_component(&entry.path) == "Cargo.toml")
        .collect::<Vec<_>>();
    manifests.sort_by(|left, right| {
        left.path
            .matches('/')
            .count()
            .cmp(&right.path.matches('/').count())
            .then_with(|| left.path.cmp(&right.path))
    });
    if manifests.len() > MANIFEST_DISCOVERY_LIMIT {
        discovery.diagnostics.push(format!(
            "Cargo.toml package-name discovery inspected the first {MANIFEST_DISCOVERY_LIMIT} of {} manifests",
            manifests.len()
        ));
    }

    let repo = repository.repo();
    for entry in manifests.into_iter().take(MANIFEST_DISCOVERY_LIMIT) {
        inspect_manifest_package_name(github, &repo, &entry, &mut discovery).await;
    }
    Ok(discovery)
}

async fn inspect_manifest_package_name(
    github: &GitHubClient,
    repo: &GitHubRepo,
    entry: &GitHubTreeEntry,
    discovery: &mut ManifestPackageDiscovery,
) {
    if entry.mode == "120000" {
        discovery.diagnostics.push(format!(
            "{} is a symbolic link and was not followed",
            entry.path
        ));
        return;
    }
    if entry
        .size
        .is_some_and(|size| size > MANIFEST_DISCOVERY_FILE_LIMIT)
    {
        discovery.diagnostics.push(format!(
            "{} exceeds the bounded manifest-discovery file-size cap",
            entry.path
        ));
        return;
    }

    let bytes = match github
        .blob_by_sha(repo, &entry.sha, MANIFEST_DISCOVERY_FILE_LIMIT)
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            discovery.diagnostics.push(format!(
                "{} could not be read during bounded manifest discovery: {error:#}",
                entry.path
            ));
            return;
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            discovery.diagnostics.push(format!(
                "{} is not UTF-8 and was skipped during bounded manifest discovery",
                entry.path
            ));
            return;
        }
    };
    match package_name_from_manifest(&text) {
        Ok(Some(package_name)) => {
            discovery.package_names.insert(package_name);
        }
        Ok(None) => {}
        Err(error) => discovery.diagnostics.push(format!(
            "{} could not be parsed during bounded manifest discovery: {error}",
            entry.path
        )),
    }
}

fn package_name_from_manifest(text: &str) -> Result<Option<String>> {
    let document = toml::from_str::<toml::Table>(text)?;
    Ok(document
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned))
}

fn final_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

async fn search_candidates(
    crates_io: &CratesIoClient,
    terms: &BTreeSet<String>,
    per_term_limit: usize,
) -> Result<Vec<CrateSummary>> {
    let mut by_name = HashMap::new();
    for term in terms {
        for candidate in crates_io.search(term, per_term_limit.min(100)).await? {
            by_name
                .entry(canonical_crate_name(&candidate.name))
                .or_insert(candidate);
        }
    }
    Ok(by_name.into_values().collect())
}

fn search_terms(query: &str) -> BTreeSet<String> {
    let mut terms = BTreeSet::from([query.to_owned()]);
    let lower = query.to_ascii_lowercase();
    if let Some(stripped) = lower.strip_suffix("-rs").filter(|value| !value.is_empty()) {
        terms.insert(stripped.to_owned());
    }
    if let Some(stripped) = lower
        .strip_prefix("rust-")
        .filter(|value| !value.is_empty())
    {
        terms.insert(stripped.to_owned());
    }
    if lower.chars().count() >= 3 && lower.chars().count() <= 12 {
        let chars = lower.chars().collect::<Vec<_>>();
        let indexes = [0, chars.len() / 2, chars.len() - 1];
        for index in indexes {
            let term = chars
                .iter()
                .enumerate()
                .filter_map(|(position, ch)| (position != index).then_some(ch))
                .collect::<String>();
            if term.len() >= 2 {
                terms.insert(term);
            }
        }
    }
    terms
}

fn rank_candidates(
    query: &str,
    candidates: Vec<CrateSummary>,
    expected_repo: Option<&GitHubRepo>,
) -> Vec<RankedCrate> {
    let query_name = canonical_crate_name(query);
    let stripped_query = strip_rust_repo_affixes(&query_name);
    let mut ranked = candidates
        .into_iter()
        .map(|candidate| {
            let candidate_name = canonical_crate_name(&candidate.name);
            let name_score = jaro_winkler(&query_name, &candidate_name);
            let stripped_score = jaro_winkler(&stripped_query, &candidate_name);
            let repository_match = expected_repo.is_some_and(|expected| {
                candidate
                    .repository
                    .as_deref()
                    .and_then(parse_github_repo)
                    .is_some_and(|actual| {
                        actual
                            .full_name()
                            .eq_ignore_ascii_case(&expected.full_name())
                    })
            });
            let repository_name_score = candidate
                .repository
                .as_deref()
                .and_then(parse_github_repo)
                .map_or(0.0, |repo| {
                    let repo_name = canonical_crate_name(&repo.name);
                    jaro_winkler(&query_name, &repo_name).max(jaro_winkler(
                        &stripped_query,
                        &strip_rust_repo_affixes(&repo_name),
                    ))
                });

            let (score, reason) = if repository_match {
                (1.0, "repository_url")
            } else if candidate_name == query_name {
                (1.0, "canonical_name")
            } else if candidate_name == stripped_query {
                (0.98, "repository_affix_normalization")
            } else if repository_name_score > name_score.max(stripped_score) {
                (repository_name_score * 0.97, "repository_name_similarity")
            } else {
                (name_score.max(stripped_score), "crate_name_similarity")
            };

            RankedCrate {
                crate_info: candidate,
                score,
                match_reason: reason.to_owned(),
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| right.crate_info.downloads.cmp(&left.crate_info.downloads))
            .then_with(|| left.crate_info.name.cmp(&right.crate_info.name))
    });
    ranked
}

fn unambiguous_high_confidence(ranked: &[RankedCrate]) -> bool {
    let Some(first) = ranked.first() else {
        return false;
    };
    first.score >= 0.85
        && ranked
            .get(1)
            .is_none_or(|second| first.score - second.score >= 0.05)
}

fn ranked_resolution(
    query: &str,
    ranked: Vec<RankedCrate>,
    accept_closest: bool,
    diagnostics: Vec<String>,
) -> ResolutionResult {
    let selected = if accept_closest && unambiguous_high_confidence(&ranked) {
        ranked.first().cloned()
    } else {
        None
    };
    let alternatives = ranked
        .into_iter()
        .filter(|candidate| {
            selected.as_ref().is_none_or(|selected| {
                canonical_crate_name(&candidate.crate_info.name)
                    != canonical_crate_name(&selected.crate_info.name)
            })
        })
        .collect();
    let requires_selection = selected.is_none();

    ResolutionResult {
        input: query.to_owned(),
        resolution_method: if requires_selection {
            "ranked_suggestions"
        } else {
            "accepted_closest"
        }
        .to_owned(),
        selected,
        alternatives,
        requires_selection,
        globally_exhaustive: false,
        diagnostics,
    }
}

fn strip_rust_repo_affixes(value: &str) -> String {
    let without_prefix = value
        .strip_prefix("rust-")
        .or_else(|| value.strip_prefix("rust_"))
        .unwrap_or(value);
    without_prefix
        .strip_suffix("-rs")
        .or_else(|| without_prefix.strip_suffix("_rs"))
        .unwrap_or(without_prefix)
        .to_owned()
}

fn exact_result(input: &str, selected: CrateSummary, method: &str) -> ResolutionResult {
    ResolutionResult {
        input: input.to_owned(),
        selected: Some(RankedCrate {
            crate_info: selected,
            score: 1.0,
            match_reason: method.to_owned(),
        }),
        alternatives: Vec::new(),
        resolution_method: method.to_owned(),
        requires_selection: false,
        globally_exhaustive: false,
        diagnostics: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn candidate(name: &str, repository: Option<&str>, downloads: u64) -> CrateSummary {
        CrateSummary {
            name: name.to_owned(),
            max_version: "1.0.0".to_owned(),
            repository: repository.map(str::to_owned),
            homepage: None,
            description: None,
            downloads,
        }
    }

    fn github_repository(owner: &str, name: &str, private: bool) -> GitHubRepository {
        serde_json::from_value(json!({
            "id": 42,
            "name": name,
            "full_name": format!("{owner}/{name}"),
            "html_url": format!("https://github.com/{owner}/{name}"),
            "owner": {
                "login": owner,
                "id": 7,
                "html_url": format!("https://github.com/{owner}")
            },
            "private": private
        }))
        .unwrap()
    }

    #[test]
    fn repo_affixes_rank_fs2_for_fs2_rs() {
        let ranked = rank_candidates(
            "fs2-rs",
            vec![candidate("fs4", None, 10), candidate("fs2", None, 1)],
            None,
        );
        assert_eq!(ranked[0].crate_info.name, "fs2");
        assert_eq!(ranked[0].match_reason, "repository_affix_normalization");
    }

    #[test]
    fn exact_repository_identity_wins() {
        let repo = GitHubRepo::new("danburkert", "fs2-rs").unwrap();
        let ranked = rank_candidates(
            "unrelated",
            vec![
                candidate("popular", Some("https://github.com/example/popular"), 1_000),
                candidate("fs2", Some("https://github.com/danburkert/fs2-rs"), 1),
            ],
            Some(&repo),
        );
        assert_eq!(ranked[0].crate_info.name, "fs2");
        assert_eq!(ranked[0].score, 1.0);
    }

    #[test]
    fn search_terms_include_common_repo_affixes_and_typo_seeds() {
        let terms = search_terms("rust-fs2-rs");
        assert!(terms.contains("rust-fs2-rs"));
        assert!(terms.contains("rust-fs2"));
        assert!(terms.contains("fs2-rs"));
    }

    #[test]
    fn sensitive_github_url_is_rejected_without_echoing_its_secret() {
        let secret = "MY_FAKE_SECRET";
        let query = format!("https://user:{secret}@github.com/acme/widget?access_token={secret}");
        let error = validate_query(&query).unwrap_err().to_string();
        assert!(!error.contains(secret));
        assert!(error.contains("must not contain credentials"));
    }

    #[test]
    fn accepted_closest_is_not_marked_as_requiring_selection() {
        let ranked = rank_candidates("fs2-rs", vec![candidate("fs2", None, 1)], None);
        let resolution = ranked_resolution("fs2-rs", ranked, true, Vec::new());
        assert_eq!(
            resolution
                .selected
                .as_ref()
                .map(|item| item.crate_info.name.as_str()),
            Some("fs2")
        );
        assert!(!resolution.requires_selection);
        assert!(resolution.alternatives.is_empty());
    }

    #[test]
    fn bounded_manifest_discovery_reads_package_names_only() {
        assert_eq!(
            package_name_from_manifest(
                r#"
[package]
name = "unexpected-crate-name"
version = "1.0.0"
"#
            )
            .unwrap()
            .as_deref(),
            Some("unexpected-crate-name")
        );
        assert_eq!(
            package_name_from_manifest("[workspace]\nmembers = []\n").unwrap(),
            None
        );
    }

    #[test]
    fn private_repository_resolution_is_outside_public_scope() {
        let repository = github_repository("acme", "widget", true);
        let error = ensure_public_repository(&repository).unwrap_err();
        assert!(error.to_string().contains("outside this public inventory"));
    }

    #[test]
    fn bounded_repository_search_never_claims_a_unique_exact_name() {
        let repository = github_repository("acme", "widget", false);
        let bounded = GitHubSearchResult {
            total_count: 2,
            incomplete_results: false,
            items: vec![repository.clone()],
        };
        assert!(unique_unbounded_exact_repository("widget", &bounded).is_none());

        let complete = GitHubSearchResult {
            total_count: 1,
            incomplete_results: false,
            items: vec![repository],
        };
        assert_eq!(
            unique_unbounded_exact_repository("widget", &complete)
                .map(|item| item.full_name.as_str()),
            Some("acme/widget")
        );
    }
}
