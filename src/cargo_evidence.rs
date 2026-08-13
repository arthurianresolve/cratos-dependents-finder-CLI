//! Evidence extraction from Cargo lockfiles and manifests.
//!
//! This module deliberately keeps three different statements separate:
//! a package is recorded in a lockfile, a manifest directly declares a
//! dependency, and a recorded package is reachable from a lockfile graph root.
//! None of those statements implies that the package is built for a particular
//! target or feature selection.

use std::collections::BTreeSet;

use regex::Regex;
use semver::{Op, Version, VersionReq};
use serde::{Deserialize, Serialize};

mod lock;
mod manifest;

pub use lock::{
    CargoLockEvidence, CargoLockRangeEvidence, DependencyWitnessV1, MatchingResolutionEvidenceV1,
    PackageIdentityV1, RecordedRelation, ResolvedOccurrence, analyze_cargo_lock,
    analyze_cargo_lock_range, analyze_cargo_lock_range_with_packages,
    analyze_cargo_lock_with_packages,
};
pub use manifest::{analyze_cargo_manifests, analyze_cargo_manifests_for_range};

use crate::version_selector::PublishedVersionV1;

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

static OS_PATTERN: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"target_os\s*=\s*"([^"]+)""#).expect("OS selector pattern is valid")
});

/// OS names observed in `cfg(target_os = "...")` dependency selectors.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OsSupport {
    pub observed_targets: Vec<String>,
    pub has_unconditional_declaration: bool,
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

/// A direct declaration evaluated against a target version requirement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RangeDirectDeclaration {
    pub manifest_path: String,
    pub package_name: Option<String>,
    pub alias: String,
    pub dependency_package: String,
    pub kind: DependencyKind,
    pub target: Option<String>,
    pub requirement: Option<String>,
    pub requirement_intersects: Option<bool>,
    pub intersection_witness: Option<PublishedVersionV1>,
    pub explicit_exact_pin: Option<Version>,
    pub exact_pin_matches_selector: Option<bool>,
    pub requirement_error: Option<String>,
    pub optional: bool,
    pub git: Option<String>,
    pub path: Option<String>,
    pub registry: Option<String>,
    pub workspace_inherited: bool,
    pub workspace_manifest_path: Option<String>,
}

/// Direct-declaration evidence evaluated over a complete published-version universe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RangeManifestEvidence {
    pub target_name: String,
    pub target_requirement: String,
    pub manifests_supplied: usize,
    pub manifests_parsed: usize,
    pub declarations: Vec<RangeDirectDeclaration>,
    pub diagnostics: Vec<ManifestDiagnostic>,
    pub analysis_complete: bool,
    pub msrv_observations: Vec<MsrvObservation>,
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

/// Aggregate OS selectors from direct dependency declarations.
pub fn aggregate_os_support(declarations: &[DirectDeclaration]) -> OsSupport {
    aggregate_os_support_from_targets(
        declarations
            .iter()
            .map(|declaration| declaration.target.as_deref()),
    )
}

/// Aggregate target-OS selectors without coupling callers to a declaration projection.
pub fn aggregate_os_support_from_targets<'a>(
    targets: impl IntoIterator<Item = Option<&'a str>>,
) -> OsSupport {
    let mut observed_targets = BTreeSet::new();
    let mut has_unconditional_declaration = false;

    for target in targets {
        match target {
            None => has_unconditional_declaration = true,
            Some(target) => {
                for capture in OS_PATTERN.captures_iter(target) {
                    observed_targets.insert(capture[1].to_owned());
                }
            }
        }
    }

    OsSupport {
        observed_targets: observed_targets.into_iter().collect(),
        has_unconditional_declaration,
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

    fn witness_names(witness: &DependencyWitnessV1) -> Vec<&str> {
        witness
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect()
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
        assert_eq!(
            witness_names(evidence.direct_witness.as_ref().unwrap()),
            vec!["app", "fs2"]
        );
        assert!(evidence.transitive_witness.is_none());
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
        assert_eq!(
            witness_names(evidence.transitive_witness.as_ref().unwrap()),
            vec!["app", "bridge", "fs2"]
        );
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
        assert_eq!(
            witness_names(evidence.direct_witness.as_ref().unwrap()),
            vec!["app", "fs2"]
        );
        assert_eq!(
            witness_names(evidence.transitive_witness.as_ref().unwrap()),
            vec!["app", "bridge", "fs2"]
        );
    }

    #[test]
    fn chooses_a_deterministic_shortest_transitive_witness() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["z-bridge", "a-bridge"]

[[package]]
name = "z-bridge"
version = "1.0.0"
dependencies = ["fs2"]

[[package]]
name = "a-bridge"
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
            witness_names(evidence.transitive_witness.as_ref().unwrap()),
            vec!["app", "a-bridge", "fs2"]
        );
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
    fn range_analysis_classifies_concrete_versions_in_one_graph() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["bridge", "fs2 0.4.3"]

[[package]]
name = "bridge"
version = "1.0.0"
dependencies = ["fs2 0.4.4"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"

[[package]]
name = "fs2"
version = "0.4.4"
source = "registry+https://example.invalid/index"

[[package]]
name = "fs2"
version = "0.5.0"
source = "{CRATES_IO}"
"#
        ));
        let requirement = VersionReq::parse("^0.4").unwrap();
        let evidence = analyze_cargo_lock_range(&text, "fs2", &requirement).unwrap();

        assert_eq!(evidence.matching_occurrence_count, 2);
        assert_eq!(
            evidence.matching_versions,
            vec![version("0.4.3"), version("0.4.4")]
        );
        assert_eq!(evidence.matching_crates_io_occurrences, 1);
        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::DirectAndTransitive
        );
        assert_eq!(evidence.matching_resolutions.len(), 2);
        assert_eq!(
            evidence.matching_resolutions[0].recorded_relation,
            RecordedRelation::Direct
        );
        assert_eq!(
            evidence.matching_resolutions[1].recorded_relation,
            RecordedRelation::Transitive
        );
        assert_eq!(
            evidence.direct_witness.as_ref().unwrap().packages.last(),
            Some(&PackageIdentityV1 {
                name: "fs2".to_owned(),
                version: version("0.4.3"),
                source: Some(CRATES_IO.to_owned()),
            })
        );
        assert_eq!(
            evidence
                .transitive_witness
                .as_ref()
                .unwrap()
                .packages
                .last()
                .unwrap()
                .version,
            version("0.4.4")
        );
    }

    #[test]
    fn range_analysis_traverses_through_one_match_to_another_concrete_match() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["fs2 0.4.3"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"
dependencies = ["fs2 0.4.4"]

[[package]]
name = "fs2"
version = "0.4.4"
source = "registry+https://example.invalid/index"
"#
        ));
        let evidence =
            analyze_cargo_lock_range(&text, "fs2", &VersionReq::parse("^0.4").unwrap()).unwrap();

        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::DirectAndTransitive
        );
        assert_eq!(
            evidence.matching_resolutions[0].recorded_relation,
            RecordedRelation::Direct
        );
        assert_eq!(
            evidence.matching_resolutions[1].recorded_relation,
            RecordedRelation::Transitive
        );
    }

    #[test]
    fn range_analysis_does_not_create_a_witness_from_a_cycle() {
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
dependencies = ["bridge"]

[[package]]
name = "bridge"
version = "1.0.0"
dependencies = ["fs2"]
"#
        ));
        let evidence =
            analyze_cargo_lock_range(&text, "fs2", &VersionReq::parse("^0.4").unwrap()).unwrap();

        assert_eq!(evidence.recorded_relation, RecordedRelation::Direct);
        assert!(evidence.transitive_witness.is_none());
        assert_eq!(
            evidence.matching_resolutions[0].recorded_relation,
            RecordedRelation::Direct
        );
    }

    #[test]
    fn zero_range_matches_stay_not_recorded_when_package_inventory_is_incomplete() {
        let legacy = format!(
            r#"
[root]
name = "app"
version = "0.1.0"
dependencies = ["fs2 0.5.0 ({CRATES_IO})"]

[[package]]
name = "fs2"
version = "0.5.0"
source = "{CRATES_IO}"
"#
        );
        let requirement = VersionReq::parse("^0.4").unwrap();
        let evidence =
            analyze_cargo_lock_range_with_packages(&legacy, "fs2", &requirement).unwrap();
        assert_eq!(evidence.recorded_relation, RecordedRelation::NotRecorded);
        assert!(evidence.graph_analysis_complete);
        assert!(!evidence.package_inventory_complete);

        let invalid_graph = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["missing 1.0.0"]

[[package]]
name = "fs2"
version = "0.5.0"
source = "{CRATES_IO}"
"#
        ));
        let evidence =
            analyze_cargo_lock_range_with_packages(&invalid_graph, "fs2", &requirement).unwrap();
        assert_eq!(evidence.recorded_relation, RecordedRelation::NotRecorded);
        assert!(evidence.graph_analysis_complete);
        assert!(!evidence.package_inventory_complete);
    }

    #[test]
    fn package_inventory_preserves_exact_v1_unclassified_failures() {
        let legacy = format!(
            r#"
[root]
name = "app"
version = "0.1.0"
dependencies = ["fs2 0.5.0 ({CRATES_IO})"]

[[package]]
name = "fs2"
version = "0.5.0"
source = "{CRATES_IO}"
"#
        );
        let evidence = analyze_cargo_lock_with_packages(&legacy, "fs2", &version("0.4.3")).unwrap();
        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::PresentUnclassified
        );
        assert!(!evidence.graph_analysis_complete);

        let invalid_graph = lockfile(&format!(
            r#"
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["missing 1.0.0"]

[[package]]
name = "fs2"
version = "0.5.0"
source = "{CRATES_IO}"
"#
        ));
        let evidence =
            analyze_cargo_lock_with_packages(&invalid_graph, "fs2", &version("0.4.3")).unwrap();
        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::PresentUnclassified
        );
        assert!(!evidence.graph_analysis_complete);
    }

    #[test]
    fn range_analysis_keeps_root_only_presence_unclassified() {
        let text = lockfile(&format!(
            r#"
[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"
"#
        ));
        let evidence =
            analyze_cargo_lock_range(&text, "fs2", &VersionReq::parse("^0.4").unwrap()).unwrap();

        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::PresentUnclassified
        );
        assert_eq!(evidence.shortest_depth, Some(0));
        assert_eq!(
            evidence.matching_resolutions[0].recorded_relation,
            RecordedRelation::PresentUnclassified
        );
        assert_eq!(evidence.matching_resolutions[0].shortest_depth, Some(0));
    }

    #[test]
    fn range_analysis_does_not_overstate_legacy_root_graphs() {
        let text = format!(
            r#"
[root]
name = "app"
version = "0.1.0"
dependencies = ["fs2 0.4.3 ({CRATES_IO})"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO}"
"#
        );
        let evidence =
            analyze_cargo_lock_range(&text, "fs2", &VersionReq::parse("^0.4").unwrap()).unwrap();

        assert_eq!(
            evidence.recorded_relation,
            RecordedRelation::PresentUnclassified
        );
        assert!(!evidence.graph_analysis_complete);
        assert_eq!(evidence.matching_resolutions.len(), 1);
        assert!(!evidence.matching_resolutions[0].graph_analysis_complete);
    }

    #[test]
    fn range_refactor_preserves_exact_evidence_serialization() {
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
        let serialized = serde_json::to_value(&evidence).unwrap();

        assert_eq!(serialized["target_version"], "0.4.3");
        assert_eq!(serialized["exact_occurrences"], 1);
        assert_eq!(serialized["recorded_relation"], "direct");
        assert!(serialized.get("matching_versions").is_none());
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

    #[test]
    fn extracts_package_msrv_and_os_selectors() {
        let manifest = r#"
[package]
name = "app"
version = "0.1.0"
rust-version = "1.70.0"

[dependencies]
fs2 = "0.4"

[target.'cfg(target_os = "windows")'.dependencies]
fs2 = "0.4"

[target.'cfg(any(target_os = "linux", target_os = "macos"))'.dependencies]
fs2 = "0.4"
"#;
        let evidence =
            analyze_cargo_manifests([("Cargo.toml", manifest)], "fs2", &version("0.4.3"));

        assert_eq!(evidence.effective_msrv.as_deref(), Some("1.70.0"));
        assert_eq!(evidence.effective_msrv_source, MsrvSource::PackageField);
        let os = aggregate_os_support(&evidence.declarations);
        assert_eq!(os.observed_targets, vec!["linux", "macos", "windows"]);
        assert!(os.has_unconditional_declaration);
    }

    #[test]
    fn inherits_workspace_msrv_and_reports_not_declared() {
        let root = r#"
[workspace]
members = ["member"]
[workspace.package]
rust-version = "1.65.0"
"#;
        let member = r#"
[package]
name = "member"
version = "0.1.0"
rust-version.workspace = true
[dependencies]
fs2 = "0.4"
"#;
        let inherited = analyze_cargo_manifests(
            [("Cargo.toml", root), ("member/Cargo.toml", member)],
            "fs2",
            &version("0.4.3"),
        );
        assert_eq!(inherited.effective_msrv.as_deref(), Some("1.65.0"));
        assert_eq!(
            inherited.effective_msrv_source,
            MsrvSource::WorkspaceInherited
        );

        let no_msrv = analyze_cargo_manifests(
            [(
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            )],
            "fs2",
            &version("0.4.3"),
        );
        assert_eq!(no_msrv.effective_msrv, None);
        assert_eq!(no_msrv.effective_msrv_source, MsrvSource::NotDeclared);
    }
}
