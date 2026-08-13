use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{Result, bail};
use futures::{StreamExt, stream};
use semver::Version;

use crate::{
    cargo_evidence::evaluate_cargo_requirement,
    cli::{DependencyKind, OptionalFilter, RequirementFilter},
    crates_io::ReverseDependencyCandidate,
    github::{GitHubClient, GitHubRepo, GitHubRepository, RepositoryScope, parse_github_repo},
};

use super::{REPOSITORY_RESOLUTION_OVERSCAN_FACTOR, ScanOptions, ScanSummary};

#[derive(Clone, Debug, Default)]
pub(super) struct CandidateGroup {
    pub(super) repository_hint: Option<GitHubRepo>,
    pub(super) original_repository_urls: BTreeSet<String>,
    pub(super) sources: BTreeSet<String>,
    pub(super) published: Vec<ReverseDependencyCandidate>,
    pub(super) unsupported_reason: Option<String>,
    pub(super) known_repository: Option<GitHubRepository>,
}

impl CandidateGroup {
    pub(super) fn merge(&mut self, other: Self) {
        self.repository_hint = self.repository_hint.take().or(other.repository_hint);
        self.original_repository_urls
            .extend(other.original_repository_urls);
        self.sources.extend(other.sources);
        self.published.extend(other.published);
        self.unsupported_reason = self.unsupported_reason.take().or(other.unsupported_reason);
        self.known_repository = self.known_repository.take().or(other.known_repository);
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResolvedGroup {
    pub(super) group: CandidateGroup,
    pub(super) repository: GitHubRepository,
}

#[derive(Debug, Default)]
pub(super) struct RepositoryResolution {
    pub(super) resolved: Vec<ResolvedGroup>,
    pub(super) failures: Vec<(CandidateGroup, anyhow::Error)>,
    pub(super) filtered_private: usize,
    pub(super) limit_reached: bool,
    pub(super) budget_exhausted: bool,
}

#[derive(Default)]
struct ResolutionAccumulator {
    by_id: HashMap<u64, ResolvedGroup>,
    failures: Vec<(CandidateGroup, anyhow::Error)>,
    private_ids: HashSet<u64>,
    skipped_due_limit: bool,
}

impl ResolutionAccumulator {
    fn record(
        &mut self,
        maximum: Option<usize>,
        scope: RepositoryScope,
        group: CandidateGroup,
        result: Result<GitHubRepository>,
    ) {
        match result {
            Ok(repository) if !scope.includes(repository.effective_visibility()) => {
                self.private_ids.insert(repository.id);
            }
            Ok(repository) => {
                if let Some(existing) = self.by_id.get_mut(&repository.id) {
                    existing.group.merge(group);
                } else if maximum.is_none_or(|maximum| self.by_id.len() < maximum) {
                    self.by_id
                        .insert(repository.id, ResolvedGroup { group, repository });
                } else {
                    self.skipped_due_limit = true;
                }
            }
            Err(error) if maximum.is_none_or(|maximum| self.by_id.len() < maximum) => {
                self.failures.push((group, error));
            }
            Err(_) => self.skipped_due_limit = true,
        }
    }
}

pub(super) fn filter_candidate(
    mut candidate: ReverseDependencyCandidate,
    options: &ScanOptions,
) -> Option<ReverseDependencyCandidate> {
    if candidate.dependent_yanked {
        return None;
    }

    let enrichment_unknown = candidate.declaration_enrichment_error.is_some();
    candidate.declarations.retain(|declaration| {
        dependency_kind_selected(&declaration.kind, &options.dependency_kinds)
            && optional_selected(declaration.optional, options.optional)
    });
    if candidate.declarations.is_empty() {
        return enrichment_unknown.then_some(candidate);
    }

    let requirement_matches = match options.requirement_filter {
        RequirementFilter::Any => true,
        RequirementFilter::Accepts => candidate.declarations.iter().any(|declaration| {
            evaluate_cargo_requirement(&declaration.req, &options.version).accepts == Some(true)
        }),
        RequirementFilter::Exact => candidate.declarations.iter().any(|declaration| {
            evaluate_cargo_requirement(&declaration.req, &options.version).explicit_exact_pin
                == Some(true)
        }),
    };
    (requirement_matches || enrichment_unknown).then_some(candidate)
}

fn dependency_kind_selected(kind: &str, selected: &[DependencyKind]) -> bool {
    selected.iter().any(|candidate| match candidate {
        DependencyKind::Normal => kind.is_empty() || kind == "normal",
        DependencyKind::Build => kind == "build",
        DependencyKind::Dev => kind == "dev",
    })
}

fn optional_selected(optional: bool, filter: OptionalFilter) -> bool {
    match filter {
        OptionalFilter::Include => true,
        OptionalFilter::Exclude => !optional,
        OptionalFilter::Only => optional,
    }
}

pub(super) fn add_published_candidate(
    groups: &mut BTreeMap<String, CandidateGroup>,
    candidate: ReverseDependencyCandidate,
) {
    let repository = candidate
        .repository
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (key, hint, reason) = match repository.and_then(parse_github_repo) {
        Some(repo) => (
            format!("github:{}", repo.full_name().to_ascii_lowercase()),
            Some(repo),
            None,
        ),
        None => match repository {
            Some(repository) => (
                format!("unsupported:{}", repository.to_ascii_lowercase()),
                None,
                Some("candidate repository is not a canonical github.com repository".to_owned()),
            ),
            None => (
                format!(
                    "missing:{}@{}",
                    candidate.dependent_name, candidate.dependent_version
                ),
                None,
                Some("dependent crate version has no repository URL".to_owned()),
            ),
        },
    };
    let group = groups.entry(key).or_default();
    group.repository_hint = group.repository_hint.take().or(hint);
    if let Some(repository) = repository {
        group.original_repository_urls.insert(repository.to_owned());
    }
    group
        .sources
        .insert("crates_io_reverse_dependencies".to_owned());
    group.published.push(candidate);
    group.unsupported_reason = group.unsupported_reason.take().or(reason);
}

pub(super) async fn add_github_code_candidates(
    github: &GitHubClient,
    target_crate: &str,
    target_version: &Version,
    limit: usize,
    groups: &mut BTreeMap<String, CandidateGroup>,
    summary: &mut ScanSummary,
    scope: RepositoryScope,
) -> Result<()> {
    if !github.is_authenticated() {
        bail!("--discovery github-code/both requires GITHUB_APP_TOKEN, GITHUB_TOKEN, or GH_TOKEN");
    }
    let queries = github_code_queries(target_crate, target_version, scope);

    for (query, exact_name, source) in queries {
        let result = match github.search_code(&query, limit).await {
            Ok(result) => result,
            Err(error) => {
                summary.github_search_incomplete = true;
                summary.partial = true;
                summary.notes.push(format!(
                    "supplemental GitHub code search `{source}` failed; retained other candidate sources: {error:#}"
                ));
                continue;
            }
        };
        summary.github_search_results_returned += result.items.len();
        summary.github_search_total_count = summary
            .github_search_total_count
            .saturating_add(result.total_count.min(usize::MAX as u64) as usize);
        summary.github_search_incomplete |= result.bounded();
        for item in result.items {
            if !scope.includes(item.repository.effective_visibility()) {
                summary.github_search_private_results_discarded += 1;
                continue;
            }
            if final_component(&item.path) != exact_name {
                continue;
            }
            let Some(repo) = parse_github_repo(&item.repository.full_name) else {
                continue;
            };
            let key = format!("github:{}", repo.full_name().to_ascii_lowercase());
            let group = groups.entry(key).or_default();
            group.repository_hint = group.repository_hint.take().or(Some(repo));
            group
                .original_repository_urls
                .insert(item.repository.html_url.to_string());
            group.sources.insert(source.to_owned());
        }
    }
    if summary.github_search_incomplete {
        summary.notes.push(
            "GitHub REST code-search candidates were capped or reported incomplete_results; they are supplemental only."
                .to_owned(),
        );
    }
    Ok(())
}

pub(super) fn github_code_queries(
    target_crate: &str,
    target_version: &Version,
    scope: RepositoryScope,
) -> [(String, &'static str, &'static str); 2] {
    let visibility = match scope {
        RepositoryScope::PublicOnly => " is:public",
        RepositoryScope::AllVisible => "",
    };
    [
        (
            format!("{target_crate} {target_version} filename:Cargo.lock{visibility}"),
            "Cargo.lock",
            "github_rest_code_search_lock_seed",
        ),
        (
            format!("{target_crate} filename:Cargo.toml{visibility}"),
            "Cargo.toml",
            "github_rest_code_search_manifest_seed",
        ),
    ]
}

pub(super) async fn add_credential_visible_candidates(
    github: &GitHubClient,
    limit: usize,
    groups: &mut BTreeMap<String, CandidateGroup>,
    summary: &mut ScanSummary,
) {
    match github.credential_visible_repositories(limit).await {
        Ok(inventory) => {
            summary.credential_visible_repositories_returned = inventory.items.len();
            summary.credential_visible_inventory_complete = Some(inventory.complete);
            if !inventory.complete {
                summary.partial = true;
                summary.notes.push(format!(
                    "credential-visible GitHub repository inventory reached its {limit}-repository bound"
                ));
            }
            for repository in inventory.items {
                let key = format!("github:{}", repository.full_name.to_ascii_lowercase());
                let repo = repository.repo();
                let url = repository.html_url.to_string();
                let group = groups.entry(key).or_default();
                group.repository_hint = group.repository_hint.take().or(Some(repo));
                group.original_repository_urls.insert(url);
                group
                    .sources
                    .insert("github_credential_visible_repository_inventory".to_owned());
                group.known_repository = group.known_repository.take().or(Some(repository));
            }
        }
        Err(error) => {
            summary.credential_visible_inventory_complete = Some(false);
            summary.partial = true;
            summary.notes.push(format!(
                "credential-visible GitHub repository inventory failed; retained other candidate sources: {error:#}"
            ));
        }
    }
}

pub(super) async fn resolve_repository_groups(
    github: &GitHubClient,
    groups: Vec<CandidateGroup>,
    jobs: usize,
    maximum: Option<usize>,
    scope: RepositoryScope,
) -> RepositoryResolution {
    let total = groups.len();
    let resolution_budget = repository_resolution_budget(total, maximum);
    let mut work =
        groups
            .into_iter()
            .take(resolution_budget)
            .enumerate()
            .map(|(position, mut group)| {
                let client = github.clone();
                async move {
                    let repository = match group.known_repository.take() {
                        Some(repository) => Ok(repository),
                        None => match group.repository_hint.as_ref() {
                            Some(repo) => client.repository(repo).await,
                            None => Err(anyhow::anyhow!(
                                "candidate group has no GitHub repository hint"
                            )),
                        },
                    };
                    (position, group, repository)
                }
            });
    let mut resolution = ResolutionAccumulator::default();
    let mut considered = 0usize;

    if maximum.is_none() {
        let mut results = stream::iter(work).buffer_unordered(jobs);
        while let Some((_, group, result)) = results.next().await {
            considered += 1;
            resolution.record(maximum, scope, group, result);
        }
    } else {
        while maximum.is_none_or(|maximum| resolution.by_id.len() < maximum) {
            let batch = work.by_ref().take(jobs).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            considered += batch.len();
            let mut results = stream::iter(batch)
                .buffer_unordered(jobs)
                .collect::<Vec<_>>()
                .await;
            results.sort_by_key(|(position, _, _)| *position);

            for (_, group, result) in results {
                resolution.record(maximum, scope, group, result);
            }
        }
    }

    let mut resolved = resolution.by_id.into_values().collect::<Vec<_>>();
    resolved.sort_by(|left, right| left.repository.full_name.cmp(&right.repository.full_name));
    let limit_reached = maximum.is_some() && (considered < total || resolution.skipped_due_limit);
    let budget_exhausted = maximum.is_some_and(|maximum| {
        maximum > 0
            && resolved.len() < maximum
            && considered >= resolution_budget
            && considered < total
    });
    RepositoryResolution {
        resolved,
        failures: resolution.failures,
        filtered_private: resolution.private_ids.len(),
        limit_reached,
        budget_exhausted,
    }
}

pub(super) fn repository_resolution_budget(total: usize, maximum: Option<usize>) -> usize {
    maximum.map_or(total, |maximum| {
        maximum
            .saturating_mul(REPOSITORY_RESOLUTION_OVERSCAN_FACTOR)
            .min(total)
    })
}

fn final_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
