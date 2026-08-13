//! Lockfile evidence extraction and dependency-tree classification.

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    hash::Hash,
    str::FromStr,
};

use anyhow::{Context, Result};
use cargo_lock::{Lockfile, Package};
use semver::{Version, VersionReq};
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

/// Graph evidence for one concrete package identity selected by a range.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchingResolutionEvidenceV1 {
    pub package: PackageIdentityV1,
    pub occurrences: usize,
    pub recorded_relation: RecordedRelation,
    pub shortest_depth: Option<usize>,
    #[serde(default)]
    pub direct_witness: Option<DependencyWitnessV1>,
    #[serde(default)]
    pub transitive_witness: Option<DependencyWitnessV1>,
    pub graph_analysis_complete: bool,
    pub graph_diagnostic: Option<String>,
}

/// Lockfile evidence for every concrete target version matching a requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CargoLockRangeEvidence {
    pub target_name: String,
    pub target_requirement: String,
    pub lockfile_version: u32,
    /// Every package entry with `name == target_name`, including non-matches.
    pub occurrences: Vec<ResolvedOccurrence>,
    pub resolved_versions: Vec<Version>,
    pub matching_occurrences: Vec<ResolvedOccurrence>,
    pub matching_versions: Vec<Version>,
    pub matching_occurrence_count: usize,
    pub crates_io_occurrences: usize,
    pub matching_crates_io_occurrences: usize,
    /// Per-source concrete resolution evidence collected during the same graph walk.
    pub matching_resolutions: Vec<MatchingResolutionEvidenceV1>,
    pub recorded_relation: RecordedRelation,
    pub shortest_depth: Option<usize>,
    #[serde(default)]
    pub direct_witness: Option<DependencyWitnessV1>,
    #[serde(default)]
    pub transitive_witness: Option<DependencyWitnessV1>,
    pub graph_root_count: usize,
    pub graph_analysis_complete: bool,
    pub graph_diagnostic: Option<String>,
    #[serde(default)]
    pub reachable_packages: Vec<PackageIdentityV1>,
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

/// Parse lock evidence for every concrete target version matching a Cargo
/// requirement. The dependency graph is constructed and traversed once.
pub fn analyze_cargo_lock_range(
    lock_text: &str,
    target_name: &str,
    target_requirement: &VersionReq,
) -> Result<CargoLockRangeEvidence> {
    analyze_cargo_lock_range_internal(lock_text, target_name, target_requirement, false)
}

/// Range-aware lock analysis with the complete root-reachable package inventory.
pub fn analyze_cargo_lock_range_with_packages(
    lock_text: &str,
    target_name: &str,
    target_requirement: &VersionReq,
) -> Result<CargoLockRangeEvidence> {
    analyze_cargo_lock_range_internal(lock_text, target_name, target_requirement, true)
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

    let is_target = |package: &Package| {
        package.name.as_str() == target_name && package.version == *target_version
    };
    let relation = classify_recorded_relation(
        &lockfile,
        &is_target,
        exact_occurrences,
        collect_packages,
        false,
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

fn analyze_cargo_lock_range_internal(
    lock_text: &str,
    target_name: &str,
    target_requirement: &VersionReq,
    collect_packages: bool,
) -> Result<CargoLockRangeEvidence> {
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

    let resolved_versions = unique_versions(&occurrences);
    let matching_occurrences = occurrences
        .iter()
        .filter(|occurrence| target_requirement.matches(&occurrence.version))
        .cloned()
        .collect::<Vec<_>>();
    let matching_versions = unique_versions(&matching_occurrences);
    let crates_io_occurrences = occurrences
        .iter()
        .filter(|occurrence| occurrence.is_crates_io)
        .count();
    let matching_crates_io_occurrences = matching_occurrences
        .iter()
        .filter(|occurrence| occurrence.is_crates_io)
        .count();
    let matching_occurrence_count = matching_occurrences.len();
    let is_target = |package: &Package| {
        package.name.as_str() == target_name && target_requirement.matches(&package.version)
    };
    let relation = classify_recorded_relation(
        &lockfile,
        &is_target,
        matching_occurrence_count,
        collect_packages,
        true,
    );

    Ok(CargoLockRangeEvidence {
        target_name: target_name.to_owned(),
        target_requirement: target_requirement.to_string(),
        lockfile_version: u32::from(lockfile.version),
        occurrences,
        resolved_versions,
        matching_occurrences,
        matching_versions,
        matching_occurrence_count,
        crates_io_occurrences,
        matching_crates_io_occurrences,
        matching_resolutions: relation.matching_resolutions,
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

fn unique_versions(occurrences: &[ResolvedOccurrence]) -> Vec<Version> {
    occurrences
        .iter()
        .map(|occurrence| occurrence.version.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
    matching_resolutions: Vec<MatchingResolutionEvidenceV1>,
}

#[derive(Default)]
struct ResolutionPathAnalysis {
    occurrences: usize,
    shortest_depth: Option<usize>,
    direct_witness: Option<DependencyWitnessV1>,
    transitive_witness: Option<DependencyWitnessV1>,
}

fn classify_recorded_relation<TargetMatches>(
    lockfile: &Lockfile,
    target_matches: &TargetMatches,
    matching_occurrences: usize,
    collect_packages: bool,
    collect_matching_resolutions: bool,
) -> RelationAnalysis
where
    TargetMatches: Fn(&Package) -> bool,
{
    if matching_occurrences == 0 && !collect_packages {
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
            matching_resolutions: Vec::new(),
        };
    }

    let matching_identities = if collect_matching_resolutions {
        matching_identity_counts(lockfile, target_matches)
    } else {
        std::collections::BTreeMap::new()
    };

    // cargo-lock's dependency-tree implementation intentionally models
    // `packages` and not the separate legacy `[root]` field. Reporting a
    // relation from that incomplete graph would be stronger than the evidence.
    if lockfile.root.is_some() {
        // Range absence is conclusive from the parsed package entries even
        // when the optional reachability inventory cannot be completed. Exact
        // analysis deliberately preserves the V1 behavior for this case.
        let range_absence = collect_matching_resolutions && matching_occurrences == 0;
        return RelationAnalysis {
            relation: if range_absence {
                RecordedRelation::NotRecorded
            } else {
                RecordedRelation::PresentUnclassified
            },
            shortest_depth: None,
            direct_witness: None,
            transitive_witness: None,
            root_count: 1,
            complete: range_absence,
            diagnostic: (!range_absence).then(|| {
                "legacy Cargo.lock root is not represented by cargo-lock's dependency tree"
                    .to_owned()
            }),
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
            matching_resolutions: unclassified_resolutions(
                matching_identities,
                false,
                Some(
                    "legacy Cargo.lock root is not represented by cargo-lock's dependency tree"
                        .to_owned(),
                ),
            ),
        };
    }

    let tree = match lockfile.dependency_tree() {
        Ok(tree) => tree,
        Err(error) => {
            let range_absence = collect_matching_resolutions && matching_occurrences == 0;
            return RelationAnalysis {
                relation: if range_absence {
                    RecordedRelation::NotRecorded
                } else {
                    RecordedRelation::PresentUnclassified
                },
                shortest_depth: None,
                direct_witness: None,
                transitive_witness: None,
                root_count: 0,
                complete: range_absence,
                diagnostic: (!range_absence)
                    .then(|| format!("could not construct dependency tree: {error}")),
                reachable_packages: Vec::new(),
                package_inventory_complete: false,
                package_inventory_diagnostic: collect_packages
                    .then(|| format!("could not construct package inventory: {error}")),
                matching_resolutions: unclassified_resolutions(
                    matching_identities,
                    false,
                    Some(format!("could not construct dependency tree: {error}")),
                ),
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
    if matching_occurrences == 0 {
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
            matching_resolutions: Vec::new(),
        };
    }
    let mut direct_witness = None;
    let mut transitive_witness = None;
    let mut shortest_depth = None;
    let mut resolution_paths = matching_identities
        .into_iter()
        .map(|(package, occurrences)| {
            (
                package,
                ResolutionPathAnalysis {
                    occurrences,
                    ..ResolutionPathAnalysis::default()
                },
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    for root in &roots {
        let mut visited = HashSet::new();
        let mut predecessor = HashMap::new();
        let mut queue = VecDeque::new();
        visited.insert(*root);
        queue.push_back((*root, 0_usize));

        while let Some((node, depth)) = queue.pop_front() {
            if target_matches(&graph[node]) {
                shortest_depth = minimum_depth(shortest_depth, depth);
                if collect_matching_resolutions {
                    let path = resolution_paths
                        .entry(identities[&node].clone())
                        .or_default();
                    path.shortest_depth = minimum_depth(path.shortest_depth, depth);
                }
                // For an exact selector, a target which is itself a graph root
                // is not its own dependency and remains unclassified. Range
                // analysis continues so another matching concrete version
                // below it can retain its own path.
                if !collect_matching_resolutions {
                    continue;
                }
            }

            let mut dependencies = graph
                .neighbors_directed(node, cargo_lock::dependency::graph::EdgeDirection::Outgoing)
                .collect::<Vec<_>>();
            dependencies.sort_by(|left, right| identities[left].cmp(&identities[right]));

            for dependency in dependencies {
                let dependency_depth = depth + 1;
                if target_matches(&graph[dependency]) {
                    if collect_matching_resolutions
                        && predecessor_path_contains(dependency, node, &predecessor)
                    {
                        continue;
                    }
                    shortest_depth = minimum_depth(shortest_depth, dependency_depth);
                    let witness =
                        dependency_witness(&identities, *root, node, dependency, &predecessor);
                    if dependency_depth == 1 {
                        retain_shortest_witness(&mut direct_witness, witness.clone());
                    } else {
                        retain_shortest_witness(&mut transitive_witness, witness.clone());
                    }
                    if collect_matching_resolutions {
                        let path = resolution_paths
                            .entry(identities[&dependency].clone())
                            .or_default();
                        path.shortest_depth = minimum_depth(path.shortest_depth, dependency_depth);
                        if dependency_depth == 1 {
                            retain_shortest_witness(&mut path.direct_witness, witness);
                        } else {
                            retain_shortest_witness(&mut path.transitive_witness, witness);
                        }
                    }
                    if collect_matching_resolutions && visited.insert(dependency) {
                        predecessor.insert(dependency, node);
                        queue.push_back((dependency, dependency_depth));
                    }
                    // Exact analysis does not traverse through the requested
                    // package. Range analysis may continue to another concrete
                    // matching version; the visited set still prevents cycles.
                    continue;
                }

                if visited.insert(dependency) {
                    predecessor.insert(dependency, node);
                    queue.push_back((dependency, dependency_depth));
                }
            }
        }
    }

    let relation = relation_from_witnesses(&direct_witness, &transitive_witness);
    let diagnostic = relation_diagnostic(relation, shortest_depth, roots.is_empty());
    let matching_resolutions = resolution_paths
        .into_iter()
        .map(|(package, path)| {
            let relation = relation_from_witnesses(&path.direct_witness, &path.transitive_witness);
            MatchingResolutionEvidenceV1 {
                package,
                occurrences: path.occurrences,
                recorded_relation: relation,
                shortest_depth: path.shortest_depth,
                direct_witness: path.direct_witness,
                transitive_witness: path.transitive_witness,
                graph_analysis_complete: true,
                graph_diagnostic: relation_diagnostic(
                    relation,
                    path.shortest_depth,
                    roots.is_empty(),
                ),
            }
        })
        .collect();

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
        matching_resolutions,
    }
}

fn predecessor_path_contains<Node>(
    candidate: Node,
    mut node: Node,
    predecessor: &HashMap<Node, Node>,
) -> bool
where
    Node: Copy + Eq + Hash,
{
    loop {
        if node == candidate {
            return true;
        }
        let Some(parent) = predecessor.get(&node).copied() else {
            return false;
        };
        node = parent;
    }
}

fn matching_identity_counts<TargetMatches>(
    lockfile: &Lockfile,
    target_matches: &TargetMatches,
) -> std::collections::BTreeMap<PackageIdentityV1, usize>
where
    TargetMatches: Fn(&Package) -> bool,
{
    let mut matches = std::collections::BTreeMap::new();
    for package in lockfile
        .packages
        .iter()
        .chain(lockfile.root.iter())
        .filter(|package| target_matches(package))
    {
        *matches.entry(package_identity(package)).or_insert(0) += 1;
    }
    matches
}

fn unclassified_resolutions(
    matches: std::collections::BTreeMap<PackageIdentityV1, usize>,
    graph_analysis_complete: bool,
    diagnostic: Option<String>,
) -> Vec<MatchingResolutionEvidenceV1> {
    matches
        .into_iter()
        .map(|(package, occurrences)| MatchingResolutionEvidenceV1 {
            package,
            occurrences,
            recorded_relation: RecordedRelation::PresentUnclassified,
            shortest_depth: None,
            direct_witness: None,
            transitive_witness: None,
            graph_analysis_complete,
            graph_diagnostic: diagnostic.clone(),
        })
        .collect()
}

fn relation_from_witnesses(
    direct: &Option<DependencyWitnessV1>,
    transitive: &Option<DependencyWitnessV1>,
) -> RecordedRelation {
    match (direct.is_some(), transitive.is_some()) {
        (true, true) => RecordedRelation::DirectAndTransitive,
        (true, false) => RecordedRelation::Direct,
        (false, true) => RecordedRelation::Transitive,
        (false, false) => RecordedRelation::PresentUnclassified,
    }
}

fn relation_diagnostic(
    relation: RecordedRelation,
    shortest_depth: Option<usize>,
    roots_empty: bool,
) -> Option<String> {
    (relation == RecordedRelation::PresentUnclassified).then(|| {
        if shortest_depth == Some(0) {
            "the target package is itself a dependency-tree root".to_owned()
        } else if roots_empty {
            "the dependency tree has no roots from which to classify the target".to_owned()
        } else {
            "the target package is not reachable from a dependency-tree root".to_owned()
        }
    })
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
