//! Evidence extraction from Cargo lockfiles and manifests.
//!
//! This module deliberately keeps three different statements separate:
//! a package is recorded in a lockfile, a manifest directly declares a
//! dependency, and a recorded package is reachable from a lockfile graph root.
//! None of those statements implies that the package is built for a particular
//! target or feature selection.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    str::FromStr,
};

use anyhow::{Context, Result};
use cargo_lock::{Lockfile, Package};
use semver::{Op, Version, VersionReq};
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

/// Cargo dependency-table classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Normal,
    Development,
    Build,
}

/// A direct declaration of the target package in one package manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirectDeclaration {
    /// The package manifest which uses the dependency.
    pub manifest_path: String,
    pub package_name: Option<String>,
    /// The dependency key used by the manifest. This can differ from the package.
    pub alias: String,
    pub dependency_package: String,
    pub kind: DependencyKind,
    /// Cargo target selector such as `cfg(windows)`.
    pub target: Option<String>,
    pub requirement: Option<String>,
    pub requirement_accepts: Option<bool>,
    pub explicit_exact_pin: Option<bool>,
    pub requirement_error: Option<String>,
    pub optional: bool,
    pub git: Option<String>,
    pub path: Option<String>,
    pub registry: Option<String>,
    pub workspace_inherited: bool,
    /// The manifest containing `[workspace.dependencies]`, when inherited.
    pub workspace_manifest_path: Option<String>,
}

/// A problem which makes manifest evidence incomplete or ambiguous.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManifestDiagnostic {
    pub manifest_path: String,
    pub code: String,
    pub message: String,
}

/// How the MSRV was determined for a package manifest.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MsrvSource {
    /// `[package] rust-version = "..."` present in this manifest.
    PackageField,
    /// `rust-version.workspace = true` — value lives in workspace root.
    WorkspaceInherited,
    #[default]
    NotDeclared,
}

/// Per-manifest MSRV observation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MsrvObservation {
    pub manifest_path: String,
    pub msrv: Option<String>,
    pub source: MsrvSource,
}

/// Direct-declaration evidence collected from all supplied manifests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManifestEvidence {
    pub target_name: String,
    pub target_version: Version,
    pub manifests_supplied: usize,
    pub manifests_parsed: usize,
    pub declarations: Vec<DirectDeclaration>,
    pub diagnostics: Vec<ManifestDiagnostic>,
    /// `false` means absence of a declaration must not be treated as proven.
    pub analysis_complete: bool,
    pub msrv_observations: Vec<MsrvObservation>,
    /// The lowest (most permissive) declared rust-version across all manifests, if any.
    pub effective_msrv: Option<String>,
    pub effective_msrv_source: MsrvSource,
}
/// The result of parsing and evaluating one Cargo version requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequirementEvaluation {
    pub requirement: String,
    pub accepts: Option<bool>,
    pub explicit_exact_pin: Option<bool>,
    pub error: Option<String>,
}

/// Apply Cargo-compatible semver requirement matching to an exact version.
pub fn cargo_requirement_accepts(
    requirement: &str,
    version: &Version,
) -> std::result::Result<bool, semver::Error> {
    VersionReq::parse(requirement).map(|parsed| parsed.matches(version))
}

/// Return whether a requirement is a fully specified `=x.y.z` pin for the
/// supplied version. Bare `x.y.z` is a caret requirement and returns `false`.
pub fn is_explicit_exact_pin(
    requirement: &str,
    version: &Version,
) -> std::result::Result<bool, semver::Error> {
    let parsed = VersionReq::parse(requirement)?;
    let Some(comparator) = parsed.comparators.as_slice().first() else {
        return Ok(false);
    };

    Ok(parsed.comparators.len() == 1
        && comparator.op == Op::Exact
        && comparator.major == version.major
        && comparator.minor == Some(version.minor)
        && comparator.patch == Some(version.patch)
        && comparator.pre == version.pre)
}

/// Parse and evaluate a requirement while retaining parse failures as evidence.
pub fn evaluate_cargo_requirement(requirement: &str, version: &Version) -> RequirementEvaluation {
    match VersionReq::parse(requirement) {
        Ok(parsed) => {
            let explicit_exact_pin = parsed.comparators.len() == 1
                && parsed.comparators[0].op == Op::Exact
                && parsed.comparators[0].major == version.major
                && parsed.comparators[0].minor == Some(version.minor)
                && parsed.comparators[0].patch == Some(version.patch)
                && parsed.comparators[0].pre == version.pre;
            RequirementEvaluation {
                requirement: requirement.to_owned(),
                accepts: Some(parsed.matches(version)),
                explicit_exact_pin: Some(explicit_exact_pin),
                error: None,
            }
        }
        Err(error) => RequirementEvaluation {
            requirement: requirement.to_owned(),
            accepts: None,
            explicit_exact_pin: None,
            error: Some(error.to_string()),
        },
    }
}

/// Parse supplied `(path, Cargo.toml text)` pairs and collect direct
/// declarations of `target_name`.
///
/// Malformed manifests and unresolved workspace inheritance are returned as
/// diagnostics. `[workspace.dependencies]` entries are templates and are only
/// emitted when a package dependency table uses the same key with
/// `workspace = true`.
pub fn analyze_cargo_manifests<I, P, T>(
    manifests: I,
    target_name: &str,
    target_version: &Version,
) -> ManifestEvidence
where
    I: IntoIterator<Item = (P, T)>,
    P: AsRef<str>,
    T: AsRef<str>,
{
    let supplied = manifests.into_iter().collect::<Vec<_>>();
    let manifests_supplied = supplied.len();
    let mut parsed_manifests = Vec::new();
    let mut diagnostics = Vec::new();

    for (path, text) in supplied {
        let path = path.as_ref().to_owned();
        // `toml::Value::from_str` parses a single TOML value in toml 1.x;
        // `toml::from_str::<Table>` is the document parser Cargo manifests need.
        match toml::from_str::<toml::Table>(text.as_ref()) {
            Ok(document) => parsed_manifests.push(ParsedManifest {
                normalized_path: normalize_path(&path),
                path,
                document,
            }),
            Err(error) => diagnostics.push(ManifestDiagnostic {
                manifest_path: path,
                code: "manifest_parse_error".to_owned(),
                message: error.to_string(),
            }),
        }
    }

    let workspace_roots = parsed_manifests
        .iter()
        .enumerate()
        .filter_map(|(index, manifest)| {
            manifest
                .document
                .get("workspace")
                .and_then(toml::Value::as_table)
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    let mut workspace_dependencies = BTreeMap::new();
    for root_index in &workspace_roots {
        let root = &parsed_manifests[*root_index];
        let dependencies = root
            .document
            .get("workspace")
            .and_then(toml::Value::as_table)
            .and_then(|workspace| workspace.get("dependencies"))
            .and_then(toml::Value::as_table);
        let mut specs = BTreeMap::new();
        if let Some(dependencies) = dependencies {
            for (alias, value) in dependencies {
                if let Some(spec) =
                    parse_dependency_spec(value, &root.path, alias, &mut diagnostics)
                {
                    if spec.workspace {
                        diagnostics.push(ManifestDiagnostic {
                            manifest_path: root.path.clone(),
                            code: "invalid_workspace_dependency".to_owned(),
                            message: format!(
                                "workspace dependency `{alias}` cannot itself inherit with workspace = true"
                            ),
                        });
                    } else {
                        specs.insert(alias.clone(), spec);
                    }
                }
            }
        }
        workspace_dependencies.insert(*root_index, specs);
    }

    let mut declarations = Vec::new();
    for (manifest_index, manifest) in parsed_manifests.iter().enumerate() {
        let package_name = manifest
            .document
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
// --- MSRV extraction ---
        let rust_version_value = manifest
            .document
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|pkg| pkg.get("rust-version"));

        let msrv_observation = match rust_version_value {
        Some(toml::Value::String(v)) => MsrvObservation {
             manifest_path: manifest.path.clone(),
             msrv: Some(v.clone()),
             source: MsrvSource::PackageField,
    },
    Some(toml::Value::Table(t)) if t.get("workspace").and_then(toml::Value::as_bool) == Some(true) => {
        // workspace-inherited: try to resolve from workspace root
        let resolved = find_workspace_root(manifest_index, &parsed_manifests, &workspace_roots)
            .and_then(|root_idx| {
                parsed_manifests[root_idx]
                    .document
                    .get("workspace")
                    .and_then(toml::Value::as_table)
                    .and_then(|ws| ws.get("package"))
                    .and_then(toml::Value::as_table)
                    .and_then(|pkg| pkg.get("rust-version"))
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
            });
        MsrvObservation {
            manifest_path: manifest.path.clone(),
            msrv: resolved,
            source: MsrvSource::WorkspaceInherited,
        }
    }
    _ => MsrvObservation {
        manifest_path: manifest.path.clone(),
        msrv: None,
        source: MsrvSource::NotDeclared,
    },
};
msrv_observations.push(msrv_observation);
        for table in dependency_tables(&manifest.document) {
            for (alias, value) in table.dependencies {
                let Some(member_spec) =
                    parse_dependency_spec(value, &manifest.path, alias, &mut diagnostics)
                else {
                    continue;
                };

                let (effective, workspace_manifest_path) = if member_spec.workspace {
                    if member_spec.has_disallowed_workspace_overrides() {
                        diagnostics.push(ManifestDiagnostic {
                            manifest_path: manifest.path.clone(),
                            code: "workspace_dependency_override".to_owned(),
                            message: format!(
                                "dependency `{alias}` combines workspace = true with source or version overrides; workspace source evidence is retained"
                            ),
                        });
                    }

                    let Some(root_index) =
                        find_workspace_root(manifest_index, &parsed_manifests, &workspace_roots)
                    else {
                        diagnostics.push(ManifestDiagnostic {
                            manifest_path: manifest.path.clone(),
                            code: "workspace_root_unresolved".to_owned(),
                            message: format!(
                                "could not resolve a supplied workspace root for dependency `{alias}`"
                            ),
                        });
                        continue;
                    };
                    let Some(base) = workspace_dependencies
                        .get(&root_index)
                        .and_then(|dependencies| dependencies.get(alias))
                    else {
                        diagnostics.push(ManifestDiagnostic {
                            manifest_path: manifest.path.clone(),
                            code: "workspace_dependency_unresolved".to_owned(),
                            message: format!(
                                "workspace root `{}` has no dependency template named `{alias}`",
                                parsed_manifests[root_index].path
                            ),
                        });
                        continue;
                    };

                    (
                        DependencySpec {
                            optional: member_spec.optional.or(base.optional),
                            ..base.clone()
                        },
                        Some(parsed_manifests[root_index].path.clone()),
                    )
                } else {
                    (member_spec, None)
                };

                let dependency_package = effective.package.clone().unwrap_or_else(|| alias.clone());
                if dependency_package != target_name {
                    continue;
                }

                let evaluation = effective
                    .version
                    .as_deref()
                    .map(|requirement| evaluate_cargo_requirement(requirement, target_version));
                declarations.push(DirectDeclaration {
                    manifest_path: manifest.path.clone(),
                    package_name: package_name.clone(),
                    alias: alias.clone(),
                    dependency_package,
                    kind: table.kind,
                    target: table.target.clone(),
                    requirement: effective.version,
                    requirement_accepts: evaluation.as_ref().and_then(|result| result.accepts),
                    explicit_exact_pin: evaluation
                        .as_ref()
                        .and_then(|result| result.explicit_exact_pin),
                    requirement_error: evaluation.and_then(|result| result.error),
                    optional: effective.optional.unwrap_or(false),
                    git: effective.git,
                    path: effective.path,
                    registry: effective.registry,
                    workspace_inherited: workspace_manifest_path.is_some(),
                    workspace_manifest_path,
                });
            }
        }
    }

    declarations.sort_by(|left, right| {
        (&left.manifest_path, left.kind, &left.target, &left.alias).cmp(&(
            &right.manifest_path,
            right.kind,
            &right.target,
            &right.alias,
        ))
    });
    diagnostics.sort_by(|left, right| {
        (&left.manifest_path, &left.code, &left.message).cmp(&(
            &right.manifest_path,
            &right.code,
            &right.message,
        ))
    });
// Pick the lowest semver-valid rust-version as the workspace effective MSRV.
let (effective_msrv, effective_msrv_source) = msrv_observations
    .iter()
    .filter_map(|obs| {
        obs.msrv.as_deref().and_then(|v| {
            semver::Version::parse(v).ok().map(|parsed| (parsed, v.to_owned(), obs.source))
        })
    })
    .min_by(|(a, _, _), (b, _, _)| a.cmp(b))
    .map(|(_, raw, src)| (Some(raw), src))
    .unwrap_or((None, MsrvSource::NotDeclared));

    ManifestEvidence {
        target_name: target_name.to_owned(),
        target_version: target_version.clone(),
        manifests_supplied,
        manifests_parsed: parsed_manifests.len(),
        analysis_complete: diagnostics.is_empty(),
        declarations,
        diagnostics,
    }
}

struct ParsedManifest {
    path: String,
    normalized_path: String,
    document: toml::Table,
}

#[derive(Clone, Default)]
struct DependencySpec {
    package: Option<String>,
    version: Option<String>,
    optional: Option<bool>,
    git: Option<String>,
    path: Option<String>,
    registry: Option<String>,
    workspace: bool,
}

impl DependencySpec {
    fn has_disallowed_workspace_overrides(&self) -> bool {
        self.package.is_some()
            || self.version.is_some()
            || self.git.is_some()
            || self.path.is_some()
            || self.registry.is_some()
    }
}

fn parse_dependency_spec(
    value: &toml::Value,
    manifest_path: &str,
    alias: &str,
    diagnostics: &mut Vec<ManifestDiagnostic>,
) -> Option<DependencySpec> {
    if let Some(version) = value.as_str() {
        return Some(DependencySpec {
            version: Some(version.to_owned()),
            ..DependencySpec::default()
        });
    }

    let Some(table) = value.as_table() else {
        diagnostics.push(ManifestDiagnostic {
            manifest_path: manifest_path.to_owned(),
            code: "invalid_dependency_declaration".to_owned(),
            message: format!("dependency `{alias}` must be a version string or dependency table"),
        });
        return None;
    };

    Some(DependencySpec {
        package: string_field(table, "package", manifest_path, alias, diagnostics),
        version: string_field(table, "version", manifest_path, alias, diagnostics),
        optional: bool_field(table, "optional", manifest_path, alias, diagnostics),
        git: string_field(table, "git", manifest_path, alias, diagnostics),
        path: string_field(table, "path", manifest_path, alias, diagnostics),
        registry: string_field(table, "registry", manifest_path, alias, diagnostics),
        workspace: bool_field(table, "workspace", manifest_path, alias, diagnostics)
            .unwrap_or(false),
    })
}

fn string_field(
    table: &toml::Table,
    field: &str,
    manifest_path: &str,
    alias: &str,
    diagnostics: &mut Vec<ManifestDiagnostic>,
) -> Option<String> {
    let value = table.get(field)?;
    match value.as_str() {
        Some(value) => Some(value.to_owned()),
        None => {
            diagnostics.push(ManifestDiagnostic {
                manifest_path: manifest_path.to_owned(),
                code: "invalid_dependency_field".to_owned(),
                message: format!("dependency `{alias}` field `{field}` must be a string"),
            });
            None
        }
    }
}

fn bool_field(
    table: &toml::Table,
    field: &str,
    manifest_path: &str,
    alias: &str,
    diagnostics: &mut Vec<ManifestDiagnostic>,
) -> Option<bool> {
    let value = table.get(field)?;
    match value.as_bool() {
        Some(value) => Some(value),
        None => {
            diagnostics.push(ManifestDiagnostic {
                manifest_path: manifest_path.to_owned(),
                code: "invalid_dependency_field".to_owned(),
                message: format!("dependency `{alias}` field `{field}` must be a boolean"),
            });
            None
        }
    }
}

struct DependencyTable<'a> {
    kind: DependencyKind,
    target: Option<String>,
    dependencies: &'a toml::Table,
}

fn dependency_tables(document: &toml::Table) -> Vec<DependencyTable<'_>> {
    let mut result = Vec::new();

    append_dependency_tables(document, None, &mut result);
    if let Some(targets) = document.get("target").and_then(toml::Value::as_table) {
        for (selector, target) in targets {
            if let Some(target) = target.as_table() {
                append_dependency_tables(target, Some(selector.clone()), &mut result);
            }
        }
    }
    result
}

fn append_dependency_tables<'a>(
    table: &'a toml::Table,
    target: Option<String>,
    result: &mut Vec<DependencyTable<'a>>,
) {
    for (name, kind) in [
        ("dependencies", DependencyKind::Normal),
        ("dev-dependencies", DependencyKind::Development),
        ("dev_dependencies", DependencyKind::Development),
        ("build-dependencies", DependencyKind::Build),
        ("build_dependencies", DependencyKind::Build),
    ] {
        if let Some(dependencies) = table.get(name).and_then(toml::Value::as_table) {
            result.push(DependencyTable {
                kind,
                target: target.clone(),
                dependencies,
            });
        }
    }
}

fn find_workspace_root(
    manifest_index: usize,
    manifests: &[ParsedManifest],
    workspace_roots: &[usize],
) -> Option<usize> {
    let manifest = &manifests[manifest_index];
    if let Some(explicit) = manifest
        .document
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("workspace"))
        .and_then(toml::Value::as_str)
    {
        let root_path = workspace_manifest_path(&manifest.normalized_path, explicit);
        return workspace_roots
            .iter()
            .copied()
            .find(|index| manifests[*index].normalized_path == root_path);
    }

    let member_directory = manifest_directory(&manifest.normalized_path);
    workspace_roots
        .iter()
        .copied()
        .filter(|root_index| {
            let root_directory = manifest_directory(&manifests[*root_index].normalized_path);
            directory_contains(&root_directory, &member_directory)
        })
        .max_by_key(|root_index| manifest_directory(&manifests[*root_index].normalized_path).len())
}

fn workspace_manifest_path(member_manifest: &str, workspace: &str) -> String {
    let workspace = normalize_path(workspace);
    let joined = if workspace.starts_with('/')
        || workspace
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':')
    {
        workspace
    } else {
        let member_directory = manifest_directory(member_manifest);
        normalize_path(&format!("{member_directory}/{workspace}"))
    };
    if joined.ends_with(".toml") {
        joined
    } else if joined.is_empty() {
        "Cargo.toml".to_owned()
    } else {
        format!("{joined}/Cargo.toml")
    }
}

fn manifest_directory(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(String::new, |(directory, _)| directory.to_owned())
}

fn directory_contains(parent: &str, child: &str) -> bool {
    parent.is_empty()
        || parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn normalize_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let absolute = path.starts_with('/');
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." if components.last().is_some_and(|last| *last != "..") => {
                components.pop();
            }
            ".." if !absolute => components.push(component),
            ".." => {}
            _ => components.push(component),
        }
    }
    let normalized = components.join("/");
    if absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn version(value: &str) -> Version {
        Version::parse(value).expect("valid test version")
    }

    fn lockfile(packages: &str) -> String {
        format!("version = 3\n\n{packages}")
    }

    #[test]
    fn reports_all_versions_sources_and_exact_crates_io_occurrences() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"

[[package]]
name = "fs2"
version = "0.4.3"
source = "registry+https://example.invalid/index"

[[package]]
name = "fs2"
version = "0.5.0"
source = "git+https://github.com/example/fs2?rev=abc#0123456789012345678901234567890123456789"
"#
        ));

        let evidence = analyze_cargo_lock(&text, "fs2", &version("0.4.3")).unwrap();

        assert_eq!(evidence.occurrences.len(), 3);
        assert_eq!(
            evidence.resolved_versions,
            vec![version("0.4.3"), version("0.5.0")]
        );
        assert_eq!(evidence.exact_occurrences, 2);
        assert_eq!(evidence.crates_io_occurrences, 1);
        assert_eq!(evidence.exact_crates_io_occurrences, 1);
        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::PresentUnclassified
        );
        assert_eq!(evidence.shortest_depth, Some(0));
    }

    #[test]
    fn classifies_a_direct_recorded_dependency() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"
"#
        ));

        let evidence = analyze_cargo_lock(&text, "fs2", &version("0.4.3")).unwrap();
        assert_eq!(evidence.recorded_relation, RecordedRelation::Direct);
        assert_eq!(evidence.shortest_depth, Some(1));
        assert!(evidence.graph_analysis_complete);
    }

    #[test]
    fn classifies_a_transitive_recorded_dependency() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["bridge"]

[[package]]
name = "bridge"
version = "1.0.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"
"#
        ));

        let evidence = analyze_cargo_lock(&text, "fs2", &version("0.4.3")).unwrap();
        assert_eq!(evidence.recorded_relation, RecordedRelation::Transitive);
        assert_eq!(evidence.shortest_depth, Some(2));
    }

    #[test]
    fn detects_direct_and_transitive_paths() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["bridge", "fs2"]

[[package]]
name = "bridge"
version = "1.0.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"
"#
        ));

        let evidence = analyze_cargo_lock(&text, "fs2", &version("0.4.3")).unwrap();
        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::DirectAndTransitive
        );
        assert_eq!(evidence.shortest_depth, Some(1));
    }

    #[test]
    fn distinguishes_an_absent_exact_version_from_other_versions() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.5.0"
source = "{CRATES_IO}"
"#
        ));

        let evidence = analyze_cargo_lock(&text, "fs2", &version("0.4.3")).unwrap();
        assert_eq!(evidence.recorded_relation, RecordedRelation::NotRecorded);
        assert_eq!(evidence.exact_occurrences, 0);
        assert_eq!(evidence.resolved_versions, vec![version("0.5.0")]);
    }

    #[test]
    fn retains_presence_when_the_dependency_graph_is_invalid() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["missing 1.0.0"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"
"#
        ));

        let evidence = analyze_cargo_lock(&text, "fs2", &version("0.4.3")).unwrap();
        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::PresentUnclassified
        );
        assert!(!evidence.graph_analysis_complete);
        assert!(evidence.graph_diagnostic.is_some());
    }

    #[test]
    fn requirement_matching_observes_cargo_caret_and_exact_semantics() {
        let target = version("0.4.3");
        assert!(cargo_requirement_accepts("0.4.3", &target).unwrap());
        assert!(cargo_requirement_accepts("^0.4.0", &target).unwrap());
        assert!(!cargo_requirement_accepts("^0.5", &target).unwrap());
        assert!(!is_explicit_exact_pin("0.4.3", &target).unwrap());
        assert!(is_explicit_exact_pin("=0.4.3", &target).unwrap());
        assert!(!is_explicit_exact_pin("=0.4", &target).unwrap());
    }

    #[test]
    fn requirement_evaluation_retains_parse_errors_and_prereleases() {
        let prerelease = version("1.0.0-alpha.2");
        let valid = evaluate_cargo_requirement("=1.0.0-alpha.2", &prerelease);
        assert_eq!(valid.accepts, Some(true));
        assert_eq!(valid.explicit_exact_pin, Some(true));
        assert_eq!(valid.error, None);

        let invalid = evaluate_cargo_requirement("not semver", &version("1.0.0"));
        assert_eq!(invalid.accepts, None);
        assert_eq!(invalid.explicit_exact_pin, None);
        assert!(invalid.error.is_some());
    }

    #[test]
    fn finds_normal_renamed_expanded_target_and_workspace_declarations() {
        let root = r#"
[workspace]
members = ["crates/member"]

[workspace.dependencies]
shared = { package = "fs2", version = "^0.4.0", registry = "private" }
unused = { package = "fs2", version = "=0.4.3" }
"#;
        let member = r#"
[package]
name = "member"
version = "0.1.0"

[dependencies]
fs2 = "0.4.3"
renamed = { package = "fs2", version = "=0.4.3", optional = true }
shared = { workspace = true, optional = true }

[build-dependencies.build_fs]
package = "fs2"
git = "https://github.com/example/fs2"

[target.'cfg(windows)'.dev-dependencies]
windows_fs = { package = "fs2", path = "../fs2" }
"#;

        let evidence = analyze_cargo_manifests(
            [("Cargo.toml", root), ("crates/member/Cargo.toml", member)],
            "fs2",
            &version("0.4.3"),
        );

        assert!(evidence.analysis_complete, "{:#?}", evidence.diagnostics);
        assert_eq!(evidence.declarations.len(), 5);
        assert!(
            !evidence
                .declarations
                .iter()
                .any(|item| item.alias == "unused")
        );

        let shared = evidence
            .declarations
            .iter()
            .find(|item| item.alias == "shared")
            .unwrap();
        assert!(shared.workspace_inherited);
        assert_eq!(
            shared.workspace_manifest_path.as_deref(),
            Some("Cargo.toml")
        );
        assert_eq!(shared.registry.as_deref(), Some("private"));
        assert_eq!(shared.requirement_accepts, Some(true));
        assert_eq!(shared.explicit_exact_pin, Some(false));
        assert!(shared.optional);

        let renamed = evidence
            .declarations
            .iter()
            .find(|item| item.alias == "renamed")
            .unwrap();
        assert_eq!(renamed.dependency_package, "fs2");
        assert_eq!(renamed.explicit_exact_pin, Some(true));

        let target = evidence
            .declarations
            .iter()
            .find(|item| item.alias == "windows_fs")
            .unwrap();
        assert_eq!(target.kind, DependencyKind::Development);
        assert_eq!(target.target.as_deref(), Some("cfg(windows)"));
        assert_eq!(target.path.as_deref(), Some("../fs2"));

        let build = evidence
            .declarations
            .iter()
            .find(|item| item.alias == "build_fs")
            .unwrap();
        assert_eq!(build.kind, DependencyKind::Build);
        assert_eq!(build.git.as_deref(), Some("https://github.com/example/fs2"));
    }

    #[test]
    fn does_not_count_unused_workspace_templates() {
        let root = r#"
[workspace]
members = ["member"]
[workspace.dependencies]
fs2 = "=0.4.3"
"#;
        let member = r#"
[package]
name = "member"
version = "0.1.0"
[dependencies]
serde = "1"
"#;

        let evidence = analyze_cargo_manifests(
            [("Cargo.toml", root), ("member/Cargo.toml", member)],
            "fs2",
            &version("0.4.3"),
        );
        assert!(evidence.declarations.is_empty());
        assert!(evidence.analysis_complete, "{:#?}", evidence.diagnostics);
    }

    #[test]
    fn chooses_the_nearest_workspace_root() {
        let outer = r#"
[workspace]
[workspace.dependencies]
fs2 = "=0.4.3"
"#;
        let inner = r#"
[workspace]
[workspace.dependencies]
fs2 = "=0.5.0"
"#;
        let member = r#"
[package]
name = "member"
version = "0.1.0"
[dependencies]
fs2 = { workspace = true }
"#;

        let evidence = analyze_cargo_manifests(
            [
                ("Cargo.toml", outer),
                ("nested/Cargo.toml", inner),
                ("nested/member/Cargo.toml", member),
            ],
            "fs2",
            &version("0.4.3"),
        );
        assert_eq!(
            evidence.declarations.len(),
            1,
            "{:#?}",
            evidence.diagnostics
        );
        assert_eq!(
            evidence.declarations[0].workspace_manifest_path.as_deref(),
            Some("nested/Cargo.toml")
        );
        assert_eq!(evidence.declarations[0].requirement_accepts, Some(false));
    }

    #[test]
    fn explicit_package_workspace_path_is_resolved_lexically() {
        let root = r#"
[workspace]
[workspace.dependencies]
fs2 = "=0.4.3"
"#;
        let member = r#"
[package]
name = "member"
version = "0.1.0"
workspace = "../.."
[dependencies]
fs2 = { workspace = true }
"#;

        let evidence = analyze_cargo_manifests(
            [
                ("repo/Cargo.toml", root),
                ("repo/crates/member/Cargo.toml", member),
            ],
            "fs2",
            &version("0.4.3"),
        );
        assert_eq!(
            evidence.declarations.len(),
            1,
            "{:#?}",
            evidence.diagnostics
        );
        assert_eq!(
            evidence.declarations[0].workspace_manifest_path.as_deref(),
            Some("repo/Cargo.toml")
        );
    }

    #[test]
    fn unresolved_workspace_and_malformed_manifests_are_diagnostics() {
        let valid = r#"
[package]
name = "member"
version = "0.1.0"
[dependencies]
fs2 = { workspace = true }
"#;
        let evidence = analyze_cargo_manifests(
            [
                ("member/Cargo.toml", valid),
                ("broken/Cargo.toml", "[package\nname = 3"),
            ],
            "fs2",
            &version("0.4.3"),
        );

        assert!(!evidence.analysis_complete);
        assert_eq!(evidence.manifests_supplied, 2);
        assert_eq!(evidence.manifests_parsed, 1, "{:#?}", evidence.diagnostics);
        assert!(evidence.declarations.is_empty());
        assert!(
            evidence
                .diagnostics
                .iter()
                .any(|item| item.code == "manifest_parse_error")
        );
        assert!(
            evidence
                .diagnostics
                .iter()
                .any(|item| item.code == "workspace_root_unresolved")
        );
    }

    #[test]
    fn invalid_requirement_does_not_erase_direct_declaration_evidence() {
        let manifest = r#"
[package]
name = "app"
version = "0.1.0"
[dependencies]
fs2 = { version = "not semver", optional = false }
"#;
        let evidence =
            analyze_cargo_manifests([("Cargo.toml", manifest)], "fs2", &version("0.4.3"));
        assert_eq!(
            evidence.declarations.len(),
            1,
            "{:#?}",
            evidence.diagnostics
        );
        assert_eq!(evidence.declarations[0].requirement_accepts, None);
        assert!(evidence.declarations[0].requirement_error.is_some());
    }
}
