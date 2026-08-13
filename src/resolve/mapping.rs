use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result, bail};

use crate::{
    crates_io::{CratesIoClient, canonical_crate_name},
    github::{
        GitHubClient, GitHubRepo, GitHubRepository, GitHubSearchResult, GitHubTreeEntry,
        parse_github_repo,
    },
    model::{CrateSummary, ResolutionResult},
};

use super::{
    MANIFEST_DISCOVERY_FILE_LIMIT, MANIFEST_DISCOVERY_LIMIT, rank_candidates, search_candidates,
    search_terms,
};
pub(super) async fn resolve_repository(
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

pub(super) fn ensure_public_repository(repository: &GitHubRepository) -> Result<()> {
    if repository.private {
        bail!("private GitHub repositories are outside this public inventory's scope");
    }
    Ok(())
}

pub(super) fn exact_named_repositories<'a>(
    query: &str,
    repositories: &'a [GitHubRepository],
) -> Vec<&'a GitHubRepository> {
    repositories
        .iter()
        .filter(|repository| !repository.private && repository.name.eq_ignore_ascii_case(query))
        .collect()
}

pub(super) fn unique_unbounded_exact_repository<'a>(
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

pub(super) fn package_name_from_manifest(text: &str) -> Result<Option<String>> {
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
