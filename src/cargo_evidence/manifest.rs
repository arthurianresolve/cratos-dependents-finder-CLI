//! Cargo.toml declaration, workspace, MSRV, and target evidence.

use std::collections::BTreeMap;

use semver::Version;

use super::{
    DependencySpec, DirectDeclaration, ManifestDiagnostic, ManifestEvidence, MsrvObservation,
    MsrvSource, ParsedManifest, dependency_tables, evaluate_cargo_requirement, find_workspace_root,
    normalize_path, parse_dependency_spec,
};

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

    ManifestEvidence {
        target_name: target_name.to_owned(),
        target_version: target_version.clone(),
        manifests_supplied,
        manifests_parsed: parsed_manifests.len(),
        analysis_complete: diagnostics.is_empty(),
        declarations,
        diagnostics,
        msrv_observations,
        effective_msrv,
        effective_msrv_source,
    }
}
