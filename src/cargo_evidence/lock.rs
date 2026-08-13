//! Lockfile evidence extraction and dependency-tree classification.

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
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

/// Stable identity for one package in a recorded dependency path.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PackageIdentityV1 {
    pub name: String,
    pub version: Version,
    pub source: Option<String>,
}

/// A root-to-target path retained from the recorded lockfile graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DependencyWitnessV1 {
    pub packages: Vec<PackageIdentityV1>,
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
    /// Deterministic shortest path with one dependency edge, when recorded.
    #[serde(default)]
    pub direct_witness: Option<DependencyWitnessV1>,
    /// Deterministic shortest path with at least two dependency edges, when recorded.
    #[serde(default)]
    pub transitive_witness: Option<DependencyWitnessV1>,
    pub graph_root_count: usize,
    pub graph_analysis_complete: bool,
    pub graph_diagnostic: Option<String>,
    /// Packages reachable from dependency-tree roots, when explicitly collected.
    #[serde(default)]
    pub reachable_packages: Vec<PackageIdentityV1>,
    /// True only when the reachable package inventory covers the whole lock graph.
    #[serde(default)]
    pub package_inventory_complete: bool,
    #[serde(default)]
    pub package_inventory_diagnostic: Option<String>,
}

/// Parse and analyze a `Cargo.lock` file without conflating package presence
/// with graph reachability.
pub fn analyze_cargo_lock(
    lock_text: &str,
    target_name: &str,
    target_version: &Version,
) -> Result<CargoLockEvidence> {
    analyze_cargo_lock_internal(lock_text, target_name, target_version, false)
}

/// Parse lock evidence and additionally retain the complete root-reachable
/// package inventory for offline full-graph policy evaluation.
pub fn analyze_cargo_lock_with_packages(
    lock_text: &str,
    target_name: &str,
    target_version: &Version,
) -> Result<CargoLockEvidence> {
    analyze_cargo_lock_internal(lock_text, target_name, target_version, true)
}

fn analyze_cargo_lock_internal(
    lock_text: &str,
    target_name: &str,
    target_version: &Version,
    collect_packages: bool,
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

    let relation = classify_recorded_relation(
        &lockfile,
        target_name,
        target_version,
        exact_occurrences,
        collect_packages,
    );

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
        direct_witness: relation.direct_witness,
        transitive_witness: relation.transitive_witness,
        graph_root_count: relation.root_count,
        graph_analysis_complete: relation.complete,
        graph_diagnostic: relation.diagnostic,
        reachable_packages: relation.reachable_packages,
        package_inventory_complete: relation.package_inventory_complete,
        package_inventory_diagnostic: relation.package_inventory_diagnostic,
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
    direct_witness: Option<DependencyWitnessV1>,
    transitive_witness: Option<DependencyWitnessV1>,
    root_count: usize,
    complete: bool,
    diagnostic: Option<String>,
    reachable_packages: Vec<PackageIdentityV1>,
    package_inventory_complete: bool,
    package_inventory_diagnostic: Option<String>,
}

fn classify_recorded_relation(
    lockfile: &Lockfile,
    target_name: &str,
    target_version: &Version,
    exact_occurrences: usize,
    collect_packages: bool,
) -> RelationAnalysis {
    if exact_occurrences == 0 && !collect_packages {
        return RelationAnalysis {
            relation: RecordedRelation::NotRecorded,
            shortest_depth: None,
            direct_witness: None,
            transitive_witness: None,
            root_count: 0,
            complete: true,
            diagnostic: None,
            reachable_packages: Vec::new(),
            package_inventory_complete: false,
            package_inventory_diagnostic: None,
        };
    }

    // cargo-lock's dependency-tree implementation intentionally models
    // `packages` and not the separate legacy `[root]` field. Reporting a
    // relation from that incomplete graph would be stronger than the evidence.
    if lockfile.root.is_some() {
        return RelationAnalysis {
            relation: RecordedRelation::PresentUnclassified,
            shortest_depth: None,
            direct_witness: None,
            transitive_witness: None,
            root_count: 1,
            complete: false,
            diagnostic: Some(
                "legacy Cargo.lock root is not represented by cargo-lock's dependency tree"
                    .to_owned(),
            ),
            reachable_packages: if collect_packages {
                lockfile
                    .packages
                    .iter()
                    .map(package_identity)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            },
            package_inventory_complete: false,
            package_inventory_diagnostic: collect_packages.then(|| {
                "legacy Cargo.lock roots prevent complete package reachability analysis".to_owned()
            }),
        };
    }

    let tree = match lockfile.dependency_tree() {
        Ok(tree) => tree,
        Err(error) => {
            return RelationAnalysis {
                relation: RecordedRelation::PresentUnclassified,
                shortest_depth: None,
                direct_witness: None,
                transitive_witness: None,
                root_count: 0,
                complete: false,
                diagnostic: Some(format!("could not construct dependency tree: {error}")),
                reachable_packages: Vec::new(),
                package_inventory_complete: false,
                package_inventory_diagnostic: collect_packages
                    .then(|| format!("could not construct package inventory: {error}")),
            };
        }
    };

    let mut roots = tree.roots();
    let graph = tree.graph();
    let identities = graph
        .node_indices()
        .map(|node| (node, package_identity(&graph[node])))
        .collect::<HashMap<_, _>>();
    roots.sort_by(|left, right| identities[left].cmp(&identities[right]));
    let (reachable_packages, package_inventory_complete, package_inventory_diagnostic) =
        if collect_packages {
            reachable_package_inventory(graph, &roots, &identities)
        } else {
            (Vec::new(), false, None)
        };
    if exact_occurrences == 0 {
        return RelationAnalysis {
            relation: RecordedRelation::NotRecorded,
            shortest_depth: None,
            direct_witness: None,
            transitive_witness: None,
            root_count: roots.len(),
            complete: true,
            diagnostic: None,
            reachable_packages,
            package_inventory_complete,
            package_inventory_diagnostic,
        };
    }
    let mut direct_witness = None;
    let mut transitive_witness = None;
    let mut shortest_depth = None;

    for root in &roots {
        let mut visited = HashSet::new();
        let mut predecessor = HashMap::new();
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

            let mut dependencies = graph
                .neighbors_directed(node, cargo_lock::dependency::graph::EdgeDirection::Outgoing)
                .collect::<Vec<_>>();
            dependencies.sort_by(|left, right| identities[left].cmp(&identities[right]));

            for dependency in dependencies {
                let dependency_depth = depth + 1;
                if is_exact_target(&graph[dependency], target_name, target_version) {
                    shortest_depth = minimum_depth(shortest_depth, dependency_depth);
                    let witness =
                        dependency_witness(&identities, *root, node, dependency, &predecessor);
                    if dependency_depth == 1 {
                        retain_shortest_witness(&mut direct_witness, witness);
                    } else {
                        retain_shortest_witness(&mut transitive_witness, witness);
                    }
                    // Do not traverse through the requested package. This both
                    // avoids cycle-derived claims and keeps the relation about
                    // paths ending at the requested package.
                    continue;
                }

                if visited.insert(dependency) {
                    predecessor.insert(dependency, node);
                    queue.push_back((dependency, dependency_depth));
                }
            }
        }
    }

    let relation = match (direct_witness.is_some(), transitive_witness.is_some()) {
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
        direct_witness,
        transitive_witness,
        root_count: roots.len(),
        complete: true,
        diagnostic,
        reachable_packages,
        package_inventory_complete,
        package_inventory_diagnostic,
    }
}

fn reachable_package_inventory(
    graph: &cargo_lock::dependency::graph::Graph,
    roots: &[cargo_lock::dependency::graph::NodeIndex],
    identities: &HashMap<cargo_lock::dependency::graph::NodeIndex, PackageIdentityV1>,
) -> (Vec<PackageIdentityV1>, bool, Option<String>) {
    let mut visited = HashSet::new();
    let mut queue = roots.iter().copied().collect::<VecDeque<_>>();
    while let Some(node) = queue.pop_front() {
        if !visited.insert(node) {
            continue;
        }
        queue.extend(
            graph.neighbors_directed(node, cargo_lock::dependency::graph::EdgeDirection::Outgoing),
        );
    }
    let packages = visited
        .iter()
        .map(|node| identities[node].clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let complete = visited.len() == graph.node_count();
    let diagnostic = (!complete).then(|| {
        format!(
            "{} package node(s) are not reachable from a dependency-tree root",
            graph.node_count().saturating_sub(visited.len())
        )
    });
    (packages, complete, diagnostic)
}

fn package_identity(package: &Package) -> PackageIdentityV1 {
    PackageIdentityV1 {
        name: package.name.to_string(),
        version: package.version.clone(),
        source: package.source.as_ref().map(ToString::to_string),
    }
}

fn dependency_witness(
    identities: &HashMap<cargo_lock::dependency::graph::NodeIndex, PackageIdentityV1>,
    root: cargo_lock::dependency::graph::NodeIndex,
    parent: cargo_lock::dependency::graph::NodeIndex,
    target: cargo_lock::dependency::graph::NodeIndex,
    predecessor: &HashMap<
        cargo_lock::dependency::graph::NodeIndex,
        cargo_lock::dependency::graph::NodeIndex,
    >,
) -> DependencyWitnessV1 {
    let mut nodes = vec![parent];
    let mut current = parent;
    while current != root {
        current = predecessor[&current];
        nodes.push(current);
    }
    nodes.reverse();
    nodes.push(target);

    DependencyWitnessV1 {
        packages: nodes
            .into_iter()
            .map(|node| identities[&node].clone())
            .collect(),
    }
}

fn retain_shortest_witness(
    current: &mut Option<DependencyWitnessV1>,
    candidate: DependencyWitnessV1,
) {
    let replace = current.as_ref().is_none_or(|existing| {
        (candidate.packages.len(), &candidate.packages)
            < (existing.packages.len(), &existing.packages)
    });
    if replace {
        *current = Some(candidate);
    }
}

fn is_exact_target(package: &Package, target_name: &str, target_version: &Version) -> bool {
    package.name.as_str() == target_name && package.version == *target_version
}

fn minimum_depth(current: Option<usize>, candidate: usize) -> Option<usize> {
    Some(current.map_or(candidate, |depth| depth.min(candidate)))
}

#[cfg(test)]
mod package_inventory_tests {
    use super::*;

    #[test]
    fn package_inventory_retains_only_root_reachable_packages() {
        let lock = r#"
version = 3

[[package]]
name = "app"
version = "1.0.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "orphan"
version = "9.9.9"
dependencies = ["fs2"]
"#;
        let evidence =
            analyze_cargo_lock_with_packages(lock, "fs2", &Version::new(0, 4, 3)).unwrap();
        assert!(evidence.package_inventory_complete);
        assert_eq!(
            evidence
                .reachable_packages
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            vec!["app", "fs2", "orphan"]
        );
    }

    #[test]
    fn ordinary_lock_analysis_does_not_retain_full_package_inventory() {
        let lock = r#"
version = 3

[[package]]
name = "app"
version = "1.0.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let evidence = analyze_cargo_lock(lock, "fs2", &Version::new(0, 4, 3)).unwrap();
        assert!(evidence.reachable_packages.is_empty());
        assert!(!evidence.package_inventory_complete);
    }
}
