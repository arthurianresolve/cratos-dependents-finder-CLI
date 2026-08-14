use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use crate::{cargo_evidence::PackageIdentityV1, evidence::DirectRequirementEvidenceV1};

use super::{
    cursor::InventorySortKeyV1,
    model::{
        InventoryMatchModeV1, InventoryQueryV1, InventorySearchFieldV1, InventorySearchResultV1,
        InventorySortV1, InventorySourceFilterV1,
    },
};

const MIN_FUZZY_SCORE: u32 = 250_000;

#[derive(Clone, Debug)]
struct SearchDocumentV1 {
    repository_terms: Vec<String>,
    package_terms: Vec<String>,
    trigrams: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TrigramIndexV1 {
    documents: BTreeMap<String, SearchDocumentV1>,
    postings: BTreeMap<String, BTreeSet<String>>,
}

impl TrigramIndexV1 {
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    pub fn upsert(
        &mut self,
        attempt_id: &str,
        repository_terms: impl IntoIterator<Item = String>,
        package_terms: impl IntoIterator<Item = String>,
    ) {
        self.remove(attempt_id);
        let repository_terms = normalize_terms(repository_terms);
        let package_terms = normalize_terms(package_terms);
        let trigrams = repository_terms
            .iter()
            .chain(&package_terms)
            .flat_map(|term| trigrams(term))
            .collect::<BTreeSet<_>>();
        for trigram in &trigrams {
            self.postings
                .entry(trigram.clone())
                .or_default()
                .insert(attempt_id.to_owned());
        }
        self.documents.insert(
            attempt_id.to_owned(),
            SearchDocumentV1 {
                repository_terms,
                package_terms,
                trigrams,
            },
        );
    }

    pub fn remove(&mut self, attempt_id: &str) {
        let Some(document) = self.documents.remove(attempt_id) else {
            return;
        };
        for trigram in document.trigrams {
            let remove_posting = self.postings.get_mut(&trigram).is_some_and(|attempts| {
                attempts.remove(attempt_id);
                attempts.is_empty()
            });
            if remove_posting {
                self.postings.remove(&trigram);
            }
        }
    }

    pub fn candidate_ids(&self, query: &InventoryQueryV1) -> BTreeSet<String> {
        let Some(search) = query.search.as_deref().map(normalize_text) else {
            return self.documents.keys().cloned().collect();
        };
        if search.chars().count() < 3 {
            return self.documents.keys().cloned().collect();
        }
        let query_trigrams = trigrams(&search);
        if query_trigrams.is_empty() {
            return self.documents.keys().cloned().collect();
        }
        match query.match_mode {
            InventoryMatchModeV1::Fuzzy => query_trigrams
                .iter()
                .filter_map(|trigram| self.postings.get(trigram))
                .flat_map(|attempts| attempts.iter().cloned())
                .collect(),
            InventoryMatchModeV1::Exact
            | InventoryMatchModeV1::Prefix
            | InventoryMatchModeV1::Substring => {
                let mut postings = query_trigrams
                    .iter()
                    .filter_map(|trigram| self.postings.get(trigram));
                let Some(first) = postings.next() else {
                    return BTreeSet::new();
                };
                postings.fold(first.clone(), |mut candidates, next| {
                    candidates.retain(|attempt| next.contains(attempt));
                    candidates
                })
            }
        }
    }

    pub fn relevance(&self, attempt_id: &str, query: &InventoryQueryV1) -> Option<u32> {
        let Some(search) = query.search.as_deref() else {
            return Some(0);
        };
        let search = normalize_text(search);
        let document = self.documents.get(attempt_id)?;
        let terms = match query.search_field {
            InventorySearchFieldV1::Any => document
                .repository_terms
                .iter()
                .chain(&document.package_terms)
                .collect::<Vec<_>>(),
            InventorySearchFieldV1::Repository => document.repository_terms.iter().collect(),
            InventorySearchFieldV1::Package => document.package_terms.iter().collect(),
        };
        terms
            .into_iter()
            .filter_map(|term| term_score_normalized(term, &search, query.match_mode))
            .max()
    }
}

pub(crate) fn matches_filters(result: &InventorySearchResultV1, query: &InventoryQueryV1) -> bool {
    let repository = &result.repository;
    if query
        .namespace
        .as_ref()
        .is_some_and(|namespace| namespace != &repository.key.namespace)
        || (!query.repository_ids.is_empty()
            && !query.repository_ids.contains(&repository.key.repository_id))
        || query
            .repository_owner
            .as_ref()
            .is_some_and(|owner| normalize_text(owner) != repository.normalized_owner)
        || (!query.repository_visibilities.is_empty()
            && !query
                .repository_visibilities
                .contains(&repository.visibility))
        || (!query.freshness.is_empty() && !query.freshness.contains(&result.freshness))
        || (!query.job_ids.is_empty() && !query.job_ids.contains(&result.attempt.job_id))
        || query
            .observed_after
            .is_some_and(|after| result.attempt.completed_at < after)
        || query
            .observed_before
            .is_some_and(|before| result.attempt.completed_at > before)
    {
        return false;
    }

    let Some(observation) = &result.observation else {
        return !has_evidence_filter(query);
    };
    if query
        .target_name
        .as_ref()
        .is_some_and(|name| normalize_text(name) != normalize_text(&observation.target.name))
        || query
            .target_version
            .as_ref()
            .is_some_and(|version| version != &observation.target.version)
        || !source_matches(&observation.target, &query.target_source)
        || (!query.recorded_relations.is_empty()
            && !query
                .recorded_relations
                .contains(&observation.recorded_relation))
        || query
            .min_msrv
            .as_ref()
            .is_some_and(|min| observation.msrv.as_ref().is_none_or(|msrv| msrv < min))
        || query
            .max_msrv
            .as_ref()
            .is_some_and(|max| observation.msrv.as_ref().is_none_or(|msrv| msrv > max))
        || (!query.strengths.is_empty() && !query.strengths.contains(&observation.strength))
        || (!query.completeness.is_empty()
            && !query.completeness.contains(&observation.completeness))
        || !query.limitation_codes.iter().all(|code| {
            observation
                .limitations
                .iter()
                .any(|limitation| limitation.code == *code)
        })
        || query
            .commit_sha
            .as_ref()
            .is_some_and(|sha| sha != &observation.snapshot.revision.commit_sha)
        || query
            .tree_sha
            .as_ref()
            .is_some_and(|sha| sha != &observation.snapshot.revision.tree_sha)
        || query
            .analyzer_profile_digest
            .as_ref()
            .is_some_and(|digest| digest != &observation.snapshot.revision.analyzer_profile_digest)
        || !requirements_match(&observation.requirements, query)
        || !packages_match(&result.packages, query)
    {
        return false;
    }
    true
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

fn requirements_match(
    requirements: &[DirectRequirementEvidenceV1],
    query: &InventoryQueryV1,
) -> bool {
    if query.requirement.is_none()
        && query.requirement_sources.is_empty()
        && query.requirement_accepts_target.is_none()
        && query.explicit_exact_pin.is_none()
    {
        return true;
    }
    requirements.iter().any(|requirement| {
        query
            .requirement
            .as_ref()
            .is_none_or(|expected| requirement.requirement.as_ref() == Some(expected))
            && (query.requirement_sources.is_empty()
                || query.requirement_sources.contains(&requirement.source))
            && query
                .requirement_accepts_target
                .is_none_or(|expected| requirement.accepts_target == Some(expected))
            && query
                .explicit_exact_pin
                .is_none_or(|expected| requirement.explicit_exact_pin == Some(expected))
    })
}

fn packages_match(packages: &[super::model::PackagePresenceV1], query: &InventoryQueryV1) -> bool {
    if query.package_name.is_none()
        && query.package_version.is_none()
        && query.package_source == InventorySourceFilterV1::Any
    {
        return true;
    }
    packages.iter().any(|presence| {
        query
            .package_name
            .as_ref()
            .is_none_or(|name| normalize_text(name) == normalize_text(&presence.package.name))
            && query
                .package_version
                .as_ref()
                .is_none_or(|version| version == &presence.package.version)
            && source_matches(&presence.package, &query.package_source)
    })
}

fn source_matches(package: &PackageIdentityV1, filter: &InventorySourceFilterV1) -> bool {
    match filter {
        InventorySourceFilterV1::Any => true,
        InventorySourceFilterV1::Local => package.source.is_none(),
        InventorySourceFilterV1::Exact(expected) => package.source.as_ref() == Some(expected),
    }
}

pub(crate) fn compare_results(
    left: &InventorySearchResultV1,
    right: &InventorySearchResultV1,
    sort: InventorySortV1,
) -> Ordering {
    match sort {
        InventorySortV1::Relevance => right
            .relevance
            .cmp(&left.relevance)
            .then_with(|| {
                left.attempt
                    .normalized_repository_name
                    .cmp(&right.attempt.normalized_repository_name)
            })
            .then_with(|| right.attempt.completed_at.cmp(&left.attempt.completed_at))
            .then_with(|| left.attempt.attempt_id.cmp(&right.attempt.attempt_id)),
        InventorySortV1::RepositoryAsc => left
            .attempt
            .normalized_repository_name
            .cmp(&right.attempt.normalized_repository_name)
            .then_with(|| right.attempt.completed_at.cmp(&left.attempt.completed_at))
            .then_with(|| left.attempt.attempt_id.cmp(&right.attempt.attempt_id)),
        InventorySortV1::ObservedAtDesc => right
            .attempt
            .completed_at
            .cmp(&left.attempt.completed_at)
            .then_with(|| {
                left.attempt
                    .normalized_repository_name
                    .cmp(&right.attempt.normalized_repository_name)
            })
            .then_with(|| left.attempt.attempt_id.cmp(&right.attempt.attempt_id)),
        InventorySortV1::MsrvAsc => compare_optional_versions(
            left.observation
                .as_ref()
                .and_then(|observation| observation.msrv.as_ref()),
            right
                .observation
                .as_ref()
                .and_then(|observation| observation.msrv.as_ref()),
        )
        .then_with(|| {
            left.attempt
                .normalized_repository_name
                .cmp(&right.attempt.normalized_repository_name)
        })
        .then_with(|| right.attempt.completed_at.cmp(&left.attempt.completed_at))
        .then_with(|| left.attempt.attempt_id.cmp(&right.attempt.attempt_id)),
    }
}

pub(crate) fn sort_key(result: &InventorySearchResultV1) -> InventorySortKeyV1 {
    InventorySortKeyV1 {
        relevance: result.relevance,
        normalized_repository: result.attempt.normalized_repository_name.clone(),
        completed_at: result.attempt.completed_at,
        msrv: result
            .observation
            .as_ref()
            .and_then(|observation| observation.msrv.clone()),
        attempt_id: result.attempt.attempt_id.clone(),
    }
}

pub(crate) fn compare_sort_keys(
    left: &InventorySortKeyV1,
    right: &InventorySortKeyV1,
    sort: InventorySortV1,
) -> Ordering {
    match sort {
        InventorySortV1::Relevance => right
            .relevance
            .cmp(&left.relevance)
            .then_with(|| left.normalized_repository.cmp(&right.normalized_repository))
            .then_with(|| right.completed_at.cmp(&left.completed_at))
            .then_with(|| left.attempt_id.cmp(&right.attempt_id)),
        InventorySortV1::RepositoryAsc => left
            .normalized_repository
            .cmp(&right.normalized_repository)
            .then_with(|| right.completed_at.cmp(&left.completed_at))
            .then_with(|| left.attempt_id.cmp(&right.attempt_id)),
        InventorySortV1::ObservedAtDesc => right
            .completed_at
            .cmp(&left.completed_at)
            .then_with(|| left.normalized_repository.cmp(&right.normalized_repository))
            .then_with(|| left.attempt_id.cmp(&right.attempt_id)),
        InventorySortV1::MsrvAsc => {
            compare_optional_versions(left.msrv.as_ref(), right.msrv.as_ref())
                .then_with(|| left.normalized_repository.cmp(&right.normalized_repository))
                .then_with(|| right.completed_at.cmp(&left.completed_at))
                .then_with(|| left.attempt_id.cmp(&right.attempt_id))
        }
    }
}

fn compare_optional_versions(
    left: Option<&semver::Version>,
    right: Option<&semver::Version>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
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

fn normalize_terms(terms: impl IntoIterator<Item = String>) -> Vec<String> {
    terms
        .into_iter()
        .map(|term| normalize_text(&term))
        .filter(|term| !term.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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

fn term_score_normalized(term: &str, query: &str, mode: InventoryMatchModeV1) -> Option<u32> {
    if query.is_empty() {
        return None;
    }
    match mode {
        InventoryMatchModeV1::Exact => (term == query).then_some(4_000_000),
        InventoryMatchModeV1::Prefix => term
            .starts_with(query)
            .then_some(3_000_000_u32.saturating_sub(term.len() as u32)),
        InventoryMatchModeV1::Substring => term
            .contains(query)
            .then_some(2_000_000_u32.saturating_sub(term.len() as u32)),
        InventoryMatchModeV1::Fuzzy => {
            if query.chars().count() < 3 {
                return term.contains(query).then_some(500_000);
            }
            let left = trigrams(term);
            let right = trigrams(query);
            let intersection = left.intersection(&right).count() as u32;
            let union = left.union(&right).count() as u32;
            let score = intersection
                .saturating_mul(1_000_000)
                .checked_div(union)
                .unwrap_or(0);
            (score >= MIN_FUZZY_SCORE).then_some(score)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigram_index_returns_typo_candidates_with_stable_score() {
        let mut index = TrigramIndexV1::default();
        index.upsert("a", ["arthurian/fs2-tools".to_owned()], ["fs2".to_owned()]);
        index.upsert("b", ["other/repository".to_owned()], ["serde".to_owned()]);
        let mut query = InventoryQueryV1::new();
        query.search = Some("arthurain/fs2-tools".to_owned());
        assert!(index.candidate_ids(&query).contains("a"));
        assert!(index.relevance("a", &query).is_some());
        assert_eq!(index.relevance("b", &query), None);
    }

    #[test]
    fn normalized_search_is_case_and_spacing_stable() {
        assert_eq!(normalize_text("  Owner / Repo  "), "owner / repo");
    }
}
