//! Cargo.toml declaration, workspace, MSRV, and target evidence.

use std::collections::BTreeMap;

use semver::{Version, VersionReq};

use super::{
    DependencyKind, DependencySpec, DirectDeclaration, ManifestDiagnostic, ManifestEvidence,
    MsrvObservation, MsrvSource, ParsedManifest, RangeDirectDeclaration, RangeManifestEvidence,
    dependency_tables, evaluate_cargo_requirement, find_workspace_root, normalize_path,
    parse_dependency_spec,
};
use crate::version_selector::{
    PublishedVersionV1, VersionSelector, evaluate_requirement_intersection,
};

struct RawDirectDeclaration {
    manifest_path: String,
    package_name: Option<String>,
    alias: String,
    dependency_package: String,
    kind: DependencyKind,
    target: Option<String>,
    requirement: Option<String>,
    optional: bool,
    git: Option<String>,
    path: Option<String>,
    registry: Option<String>,
    workspace_inherited: bool,
    workspace_manifest_path: Option<String>,
}

struct RawManifestEvidence {
    manifests_supplied: usize,
    manifests_parsed: usize,
    declarations: Vec<RawDirectDeclaration>,
    diagnostics: Vec<ManifestDiagnostic>,
    msrv_observations: Vec<MsrvObservation>,
    effective_msrv: Option<String>,
    effective_msrv_source: MsrvSource,
}

/// Parse supplied `(path, Cargo.toml text)` pairs and collect direct
/// declarations of `target_name`.
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
    let raw = analyze_cargo_manifests_raw(manifests, target_name);
    ManifestEvidence {
        target_name: target_name.to_owned(),
        target_version: target_version.clone(),
        manifests_supplied: raw.manifests_supplied,
        manifests_parsed: raw.manifests_parsed,
        analysis_complete: raw.diagnostics.is_empty(),
        declarations: raw
            .declarations
            .into_iter()
            .map(|declaration| declaration.into_exact(target_version))
            .collect(),
        diagnostics: raw.diagnostics,
        msrv_observations: raw.msrv_observations,
        effective_msrv: raw.effective_msrv,
        effective_msrv_source: raw.effective_msrv_source,
    }
}

/// Parse manifests once and evaluate declarations against a Cargo requirement
/// over the supplied complete published-version universe.
pub fn analyze_cargo_manifests_for_range<I, P, T>(
    manifests: I,
    target_name: &str,
    target_requirement: &VersionReq,
    published_versions: &[PublishedVersionV1],
) -> RangeManifestEvidence
where
    I: IntoIterator<Item = (P, T)>,
    P: AsRef<str>,
    T: AsRef<str>,
{
    let raw = analyze_cargo_manifests_raw(manifests, target_name);
    let selector = VersionSelector::Range(target_requirement.clone());
    RangeManifestEvidence {
        target_name: target_name.to_owned(),
        target_requirement: target_requirement.to_string(),
        manifests_supplied: raw.manifests_supplied,
        manifests_parsed: raw.manifests_parsed,
        analysis_complete: raw.diagnostics.is_empty(),
        declarations: raw
            .declarations
            .into_iter()
            .map(|declaration| declaration.into_range(&selector, published_versions))
            .collect(),
        diagnostics: raw.diagnostics,
        msrv_observations: raw.msrv_observations,
        effective_msrv: raw.effective_msrv,
        effective_msrv_source: raw.effective_msrv_source,
    }
}

fn analyze_cargo_manifests_raw<I, P, T>(manifests: I, target_name: &str) -> RawManifestEvidence
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
    let mut msrv_observations = Vec::new();
    for (manifest_index, manifest) in parsed_manifests.iter().enumerate() {
        let package_name = manifest
            .document
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
        let rust_version_value = manifest
            .document
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|pkg| pkg.get("rust-version"));

        let msrv_observation = match rust_version_value {
            Some(toml::Value::String(value)) => MsrvObservation {
                manifest_path: manifest.path.clone(),
                msrv: Some(value.clone()),
                source: MsrvSource::PackageField,
            },
            Some(toml::Value::Table(table))
                if table.get("workspace").and_then(toml::Value::as_bool) == Some(true) =>
            {
                let resolved =
                    find_workspace_root(manifest_index, &parsed_manifests, &workspace_roots)
                        .and_then(|root_index| {
                            parsed_manifests[root_index]
                                .document
                                .get("workspace")
                                .and_then(toml::Value::as_table)
                                .and_then(|workspace| workspace.get("package"))
                                .and_then(toml::Value::as_table)
                                .and_then(|package| package.get("rust-version"))
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

                declarations.push(RawDirectDeclaration {
                    manifest_path: manifest.path.clone(),
                    package_name: package_name.clone(),
                    alias: alias.clone(),
                    dependency_package,
                    kind: table.kind,
                    target: table.target.clone(),
                    requirement: effective.version,
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

    let (effective_msrv, effective_msrv_source) = msrv_observations
        .iter()
        .filter_map(|observation| {
            observation.msrv.as_deref().and_then(|value| {
                semver::Version::parse(value)
                    .ok()
                    .map(|parsed| (parsed, value.to_owned(), observation.source))
            })
        })
        .min_by(|(left, _, _), (right, _, _)| left.cmp(right))
        .map(|(_, raw, source)| (Some(raw), source))
        .unwrap_or((None, MsrvSource::NotDeclared));

    RawManifestEvidence {
        manifests_supplied,
        manifests_parsed: parsed_manifests.len(),
        declarations,
        diagnostics,
        msrv_observations,
        effective_msrv,
        effective_msrv_source,
    }
}

impl RawDirectDeclaration {
    fn into_exact(self, target_version: &Version) -> DirectDeclaration {
        let evaluation = self
            .requirement
            .as_deref()
            .map(|requirement| evaluate_cargo_requirement(requirement, target_version));
        DirectDeclaration {
            manifest_path: self.manifest_path,
            package_name: self.package_name,
            alias: self.alias,
            dependency_package: self.dependency_package,
            kind: self.kind,
            target: self.target,
            requirement: self.requirement,
            requirement_accepts: evaluation.as_ref().and_then(|result| result.accepts),
            explicit_exact_pin: evaluation
                .as_ref()
                .and_then(|result| result.explicit_exact_pin),
            requirement_error: evaluation.and_then(|result| result.error),
            optional: self.optional,
            git: self.git,
            path: self.path,
            registry: self.registry,
            workspace_inherited: self.workspace_inherited,
            workspace_manifest_path: self.workspace_manifest_path,
        }
    }

    fn into_range(
        self,
        selector: &VersionSelector,
        published_versions: &[PublishedVersionV1],
    ) -> RangeDirectDeclaration {
        let evaluation = self.requirement.as_deref().map(|requirement| {
            evaluate_requirement_intersection(requirement, selector, published_versions)
        });
        let (requirement_intersects, intersection_witness, explicit_exact_pin, pin_matches, error) =
            evaluation.map_or((None, None, None, None, None), |evaluation| {
                (
                    evaluation.intersects,
                    evaluation.witness,
                    evaluation.explicit_exact_pin,
                    evaluation.pin_matches_selector,
                    evaluation.error,
                )
            });
        RangeDirectDeclaration {
            manifest_path: self.manifest_path,
            package_name: self.package_name,
            alias: self.alias,
            dependency_package: self.dependency_package,
            kind: self.kind,
            target: self.target,
            requirement: self.requirement,
            requirement_intersects,
            intersection_witness,
            explicit_exact_pin,
            exact_pin_matches_selector: pin_matches,
            requirement_error: error,
            optional: self.optional,
            git: self.git,
            path: self.path,
            registry: self.registry,
            workspace_inherited: self.workspace_inherited,
            workspace_manifest_path: self.workspace_manifest_path,
        }
    }
}

#[cfg(test)]
mod range_tests {
    use super::*;

    fn release(version: &str, yanked: bool) -> PublishedVersionV1 {
        PublishedVersionV1 {
            version: Version::parse(version).unwrap(),
            yanked,
        }
    }

    #[test]
    fn range_manifest_evidence_uses_published_intersection_witnesses() {
        let manifest = r#"
[package]
name = "consumer"
version = "1.0.0"
rust-version = "1.75.0"

[dependencies]
fs2 = ">=0.4.2, <0.5"

[build-dependencies]
pinned = { package = "fs2", version = "=0.5.0" }
"#;
        let releases = [
            release("0.4.1", false),
            release("0.4.3", true),
            release("0.5.0", false),
        ];
        let evidence = analyze_cargo_manifests_for_range(
            [("Cargo.toml", manifest)],
            "fs2",
            &VersionReq::parse("^0.4").unwrap(),
            &releases,
        );

        assert!(evidence.analysis_complete);
        assert_eq!(evidence.effective_msrv.as_deref(), Some("1.75.0"));
        assert_eq!(evidence.declarations.len(), 2);
        assert_eq!(evidence.declarations[0].requirement_intersects, Some(true));
        assert_eq!(
            evidence.declarations[0].intersection_witness,
            Some(release("0.4.3", true))
        );
        assert_eq!(evidence.declarations[1].requirement_intersects, Some(false));
        assert_eq!(
            evidence.declarations[1].explicit_exact_pin,
            Some(Version::new(0, 5, 0))
        );
        assert_eq!(
            evidence.declarations[1].exact_pin_matches_selector,
            Some(false)
        );
    }

    #[test]
    fn range_manifest_evidence_preserves_unknown_requirements() {
        let manifest = r#"
[package]
name = "consumer"
version = "1.0.0"

[dependencies]
git_fs2 = { package = "fs2", git = "https://example.invalid/fs2" }
bad_fs2 = { package = "fs2", version = "not semver" }
"#;
        let evidence = analyze_cargo_manifests_for_range(
            [("Cargo.toml", manifest)],
            "fs2",
            &VersionReq::parse("^0.4").unwrap(),
            &[release("0.4.3", false)],
        );

        assert_eq!(evidence.declarations[0].requirement_intersects, None);
        assert!(evidence.declarations[0].requirement_error.is_some());
        assert_eq!(evidence.declarations[1].requirement_intersects, None);
        assert!(evidence.declarations[1].requirement_error.is_none());
    }

    #[test]
    fn exact_manifest_projection_remains_unchanged() {
        let manifest = r#"
[package]
name = "consumer"
version = "1.0.0"

[dependencies]
fs2 = "0.4.3"
"#;
        let evidence =
            analyze_cargo_manifests([("Cargo.toml", manifest)], "fs2", &Version::new(0, 4, 3));
        let declaration = &evidence.declarations[0];

        assert_eq!(declaration.requirement_accepts, Some(true));
        assert_eq!(declaration.explicit_exact_pin, Some(false));
        let serialized = serde_json::to_value(declaration).unwrap();
        assert!(serialized.get("requirement_intersects").is_none());
    }
}
