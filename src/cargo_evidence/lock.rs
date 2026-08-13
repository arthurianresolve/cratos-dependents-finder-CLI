//! Lockfile evidence extraction and dependency-tree classification.

use std::{
    collections::{BTreeSet, HashSet, VecDeque},
    str::FromStr,
};

use anyhow::{Context, Result};
use cargo_lock::{Lockfile, Package};
use semver::Version;
use serde::{Deserialize, Serialize};

/// A package entry for the requested crate in a `Cargo.lock` file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolvedOccurrence {
    pub version: Version,
    /// The exact Cargo source identifier, or `None` for a local/workspace package.
    pub source: Option<String>,
    pub is_crates_io: bool,
}

/// The relation that the recorded lockfile graph supports from its roots.
///
/// `PresentUnclassified` is intentionally used when the requested package is
/// present but graph construction, legacy-root handling, or reachability does
/// not support a direct/transitive statement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedRelation {
    Direct,
    Transitive,
    DirectAndTransitive,
    PresentUnclassified,
    NotRecorded,
}

/// Lockfile evidence for one crate name and one exact version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CargoLockEvidence {
    pub target_name: String,
    pub target_version: Version,
    pub lockfile_version: u32,
    /// Every package entry with `name == target_name`, including other versions.
    pub occurrences: Vec<ResolvedOccurrence>,
    /// Unique resolved versions for the target name.
    pub resolved_versions: Vec<Version>,
    pub exact_occurrences: usize,
    /// All target-name occurrences sourced from crates.io, regardless of version.
    pub crates_io_occurrences: usize,
    pub exact_crates_io_occurrences: usize,
    pub recorded_relation: RecordedRelation,
    /// Root is depth zero, a direct dependency is depth one.
    pub shortest_depth: Option<usize>,
    pub graph_root_count: usize,
    pub graph_analysis_complete: bool,
    pub graph_diagnostic: Option<String>,
}

/// Parse and analyze a `Cargo.lock` file without conflating package presence
/// with graph reachability.
pub fn analyze_cargo_lock(
    lock_text: &str,
    target_name: &str,
    target_version: &Version,
) -> Result<CargoLockEvidence> {
    let lockfile = Lockfile::from_str(lock_text).context("failed to parse Cargo.lock")?;

    let mut occurrences = lockfile
        .packages
        .iter()
        .chain(lockfile.root.iter())
        .filter(|package| package.name.as_str() == target_name)
        .map(resolved_occurrence)
        .collect::<Vec<_>>();
    occurrences
        .sort_by(|left, right| (&left.version, &left.source).cmp(&(&right.version, &right.source)));

    let resolved_versions = occurrences
        .iter()
        .map(|occurrence| occurrence.version.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let exact_occurrences = occurrences
        .iter()
        .filter(|occurrence| occurrence.version == *target_version)
        .count();
    let crates_io_occurrences = occurrences
        .iter()
        .filter(|occurrence| occurrence.is_crates_io)
        .count();
    let exact_crates_io_occurrences = occurrences
        .iter()
        .filter(|occurrence| occurrence.version == *target_version && occurrence.is_crates_io)
        .count();

    let relation =
        classify_recorded_relation(&lockfile, target_name, target_version, exact_occurrences);

    Ok(CargoLockEvidence {
        target_name: target_name.to_owned(),
        target_version: target_version.clone(),
        lockfile_version: u32::from(lockfile.version),
        occurrences,
        resolved_versions,
        exact_occurrences,
        crates_io_occurrences,
        exact_crates_io_occurrences,
        recorded_relation: relation.relation,
        shortest_depth: relation.shortest_depth,
        graph_root_count: relation.root_count,
        graph_analysis_complete: relation.complete,
        graph_diagnostic: relation.diagnostic,
    })
}

fn resolved_occurrence(package: &Package) -> ResolvedOccurrence {
    ResolvedOccurrence {
        version: package.version.clone(),
        source: package.source.as_ref().map(ToString::to_string),
        is_crates_io: package
            .source
            .as_ref()
            .is_some_and(cargo_lock::package::SourceId::is_default_registry),
    }
}

struct RelationAnalysis {
    relation: RecordedRelation,
    shortest_depth: Option<usize>,
    root_count: usize,
    complete: bool,
    diagnostic: Option<String>,
}

fn classify_recorded_relation(
    lockfile: &Lockfile,
    target_name: &str,
    target_version: &Version,
    exact_occurrences: usize,
) -> RelationAnalysis {
    if exact_occurrences == 0 {
        return RelationAnalysis {
            relation: RecordedRelation::NotRecorded,
            shortest_depth: None,
            root_count: 0,
            complete: true,
            diagnostic: None,
        };
    }

    // cargo-lock's dependency-tree implementation intentionally models
    // `packages` and not the separate legacy `[root]` field. Reporting a
    // relation from that incomplete graph would be stronger than the evidence.
    if lockfile.root.is_some() {
        return RelationAnalysis {
            relation: RecordedRelation::PresentUnclassified,
            shortest_depth: None,
            root_count: 1,
            complete: false,
            diagnostic: Some(
                "legacy Cargo.lock root is not represented by cargo-lock's dependency tree"
                    .to_owned(),
            ),
        };
    }

    let tree = match lockfile.dependency_tree() {
        Ok(tree) => tree,
        Err(error) => {
            return RelationAnalysis {
                relation: RecordedRelation::PresentUnclassified,
                shortest_depth: None,
                root_count: 0,
                complete: false,
                diagnostic: Some(format!("could not construct dependency tree: {error}")),
            };
        }
    };

    let roots = tree.roots();
    let graph = tree.graph();
    let mut direct = false;
    let mut transitive = false;
    let mut shortest_depth = None;

    for root in &roots {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(*root);
        queue.push_back((*root, 0_usize));

        while let Some((node, depth)) = queue.pop_front() {
            if is_exact_target(&graph[node], target_name, target_version) {
                shortest_depth = minimum_depth(shortest_depth, depth);
                // A target which is itself a graph root is not its own direct
                // dependency, and is therefore left unclassified.
                continue;
            }

            for dependency in graph
                .neighbors_directed(node, cargo_lock::dependency::graph::EdgeDirection::Outgoing)
            {
                let dependency_depth = depth + 1;
                if is_exact_target(&graph[dependency], target_name, target_version) {
                    shortest_depth = minimum_depth(shortest_depth, dependency_depth);
                    if dependency_depth == 1 {
                        direct = true;
                    } else {
                        transitive = true;
                    }
                    // Do not traverse through the requested package. This both
                    // avoids cycle-derived claims and keeps the relation about
                    // paths ending at the requested package.
                    continue;
                }

                if visited.insert(dependency) {
                    queue.push_back((dependency, dependency_depth));
                }
            }
        }
    }

    let relation = match (direct, transitive) {
        (true, true) => RecordedRelation::DirectAndTransitive,
        (true, false) => RecordedRelation::Direct,
        (false, true) => RecordedRelation::Transitive,
        (false, false) => RecordedRelation::PresentUnclassified,
    };
    let diagnostic = (relation == RecordedRelation::PresentUnclassified).then(|| {
        if shortest_depth == Some(0) {
            "the target package is itself a dependency-tree root".to_owned()
        } else if roots.is_empty() {
            "the dependency tree has no roots from which to classify the target".to_owned()
        } else {
            "the target package is not reachable from a dependency-tree root".to_owned()
        }
    });

    RelationAnalysis {
        relation,
        shortest_depth,
        root_count: roots.len(),
        complete: true,
        diagnostic,
    }
}

fn is_exact_target(package: &Package, target_name: &str, target_version: &Version) -> bool {
    package.name.as_str() == target_name && package.version == *target_version
}

fn minimum_depth(current: Option<usize>, candidate: usize) -> Option<usize> {
    Some(current.map_or(candidate, |depth| depth.min(candidate)))
}
