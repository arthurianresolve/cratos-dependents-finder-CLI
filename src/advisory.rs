//! Reproducible import and application of pinned license and advisory data.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail, ensure};
use chrono::{DateTime, Utc};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256};

use crate::{
    evidence::{
        ADVISORY_SOURCE_OSV, ADVISORY_SOURCE_RUSTSEC, AdvisorySnapshotV1, EvidenceBundleV1,
        SeverityV1, VulnerabilityEvidenceV1,
    },
    output::write_json,
    secure_cache::sha256_hex,
};

const SNAPSHOT_SCHEMA_VERSION: u16 = 1;
const MAX_SOURCE_FILES: usize = 100_000;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SnapshotProvenanceV1 {
    pub source: String,
    pub revision: String,
    pub sha256: String,
    pub collected_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LicenseRecordV1 {
    pub package: String,
    pub version: Version,
    pub expression: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AdvisoryRangeV1 {
    pub introduced: Option<Version>,
    pub fixed: Option<Version>,
    pub last_affected: Option<Version>,
    pub limit: Option<Version>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AdvisoryRecordV1 {
    pub id: String,
    pub source: String,
    pub package: String,
    pub severity: Option<SeverityV1>,
    pub withdrawn: bool,
    #[serde(default)]
    pub vulnerable_versions: BTreeSet<Version>,
    #[serde(default)]
    pub ranges: Vec<AdvisoryRangeV1>,
    #[serde(default)]
    pub patched_requirements: Vec<String>,
    #[serde(default)]
    pub unaffected_requirements: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataSnapshotV1 {
    pub schema_version: u16,
    pub generated_at: DateTime<Utc>,
    pub sources: Vec<SnapshotProvenanceV1>,
    pub licenses: Vec<LicenseRecordV1>,
    pub advisories: Vec<AdvisoryRecordV1>,
}

impl DataSnapshotV1 {
    pub fn load(path: &Path) -> Result<Self> {
        let snapshot: Self = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("reading data snapshot {}", path.display()))?,
        )
        .with_context(|| format!("parsing data snapshot {}", path.display()))?;
        ensure!(
            snapshot.schema_version == SNAPSHOT_SCHEMA_VERSION,
            "unsupported data snapshot schema {}",
            snapshot.schema_version
        );
        Ok(snapshot.normalized())
    }

    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.sources.sort();
        self.sources.dedup();
        self.licenses.sort();
        self.licenses.dedup();
        self.advisories.sort();
        self.advisories.dedup();
        self
    }

    pub fn apply(&self, bundle: &mut EvidenceBundleV1) {
        let licenses = self
            .licenses
            .iter()
            .map(|license| ((license.package.as_str(), &license.version), license))
            .collect::<BTreeMap<_, _>>();
        for repository in &mut bundle.repositories {
            for package in &mut repository.packages {
                if let Some(license) =
                    licenses.get(&(package.package.name.as_str(), &package.package.version))
                {
                    package.license_expression = license.expression.clone();
                }
                repository.vulnerabilities.extend(
                    self.advisories
                        .iter()
                        .filter(|advisory| {
                            advisory.package.eq_ignore_ascii_case(&package.package.name)
                                && advisory.affects(&package.package.version)
                        })
                        .map(|advisory| VulnerabilityEvidenceV1 {
                            package: package.package.clone(),
                            advisory_id: advisory.id.clone(),
                            source: advisory.source.clone(),
                            severity: advisory.severity,
                            withdrawn: advisory.withdrawn,
                        }),
                );
            }
        }
        bundle.advisory_snapshots = self
            .sources
            .iter()
            .filter(|source| {
                matches!(
                    source.source.as_str(),
                    ADVISORY_SOURCE_RUSTSEC | ADVISORY_SOURCE_OSV
                )
            })
            .map(|source| AdvisorySnapshotV1 {
                source: source.source.clone(),
                revision: source.revision.clone(),
                sha256: source.sha256.clone(),
                collected_at: source.collected_at,
            })
            .collect();
        *bundle = bundle.clone().normalized();
    }
}

impl AdvisoryRecordV1 {
    fn affects(&self, version: &Version) -> bool {
        if self
            .unaffected_requirements
            .iter()
            .filter_map(|requirement| VersionReq::parse(requirement).ok())
            .any(|requirement| requirement.matches(version))
            || self
                .patched_requirements
                .iter()
                .filter_map(|requirement| VersionReq::parse(requirement).ok())
                .any(|requirement| requirement.matches(version))
        {
            return false;
        }

        if self.vulnerable_versions.contains(version)
            || self.ranges.iter().any(|range| range.affects(version))
        {
            return true;
        }

        self.vulnerable_versions.is_empty()
            && self.ranges.is_empty()
            && self.source == ADVISORY_SOURCE_RUSTSEC
    }
}

impl AdvisoryRangeV1 {
    fn affects(&self, version: &Version) -> bool {
        self.introduced
            .as_ref()
            .is_none_or(|introduced| version >= introduced)
            && self.fixed.as_ref().is_none_or(|fixed| version < fixed)
            && self
                .last_affected
                .as_ref()
                .is_none_or(|last| version <= last)
            && self.limit.as_ref().is_none_or(|limit| version < limit)
    }
}

#[derive(Default)]
pub struct SnapshotInputs<'a> {
    pub rustsec: Option<(&'a Path, &'a str)>,
    pub osv: Option<(&'a Path, &'a str)>,
    pub crates: Option<(&'a Path, &'a str)>,
}

pub fn create_snapshot(inputs: SnapshotInputs<'_>, output: &Path) -> Result<DataSnapshotV1> {
    let collected_at = Utc::now();
    let mut sources = Vec::new();
    let mut licenses = Vec::new();
    let mut advisories = Vec::new();

    if let Some((path, revision)) = inputs.rustsec {
        let files = source_files(path, Some("md"))?;
        sources.push(provenance(
            ADVISORY_SOURCE_RUSTSEC,
            revision,
            collected_at,
            &files,
        )?);
        advisories.extend(import_rustsec(&files)?);
    }
    if let Some((path, revision)) = inputs.osv {
        let files = source_files(path, Some("json"))?;
        sources.push(provenance(
            ADVISORY_SOURCE_OSV,
            revision,
            collected_at,
            &files,
        )?);
        advisories.extend(import_osv(&files)?);
    }
    if let Some((path, revision)) = inputs.crates {
        let files = source_files(path, Some("json"))?;
        sources.push(provenance("crates_io", revision, collected_at, &files)?);
        licenses.extend(import_crates_metadata(&files)?);
    }
    if sources.is_empty() {
        bail!("at least one pinned RustSec, OSV, or crates metadata input is required");
    }

    let snapshot = DataSnapshotV1 {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        generated_at: collected_at,
        sources,
        licenses,
        advisories,
    }
    .normalized();
    write_json(output, &snapshot)?;
    Ok(snapshot)
}

fn source_files(path: &Path, extension: Option<&str>) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut paths = Vec::new();
    if path.is_file() {
        paths.push(path.to_owned());
    } else {
        collect_paths(path, extension, &mut paths)?;
    }
    paths.sort();
    ensure!(
        paths.len() <= MAX_SOURCE_FILES,
        "snapshot input exceeds {MAX_SOURCE_FILES} files"
    );
    let mut total = 0_u64;
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = fs::read(&path)
            .with_context(|| format!("reading snapshot input {}", path.display()))?;
        total = total.saturating_add(bytes.len() as u64);
        ensure!(
            total <= MAX_SOURCE_BYTES,
            "snapshot input exceeds {MAX_SOURCE_BYTES} bytes"
        );
        files.push((path, bytes));
    }
    Ok(files)
}

fn collect_paths(path: &Path, extension: Option<&str>, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path)
        .with_context(|| format!("reading snapshot directory {}", path.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_paths(&entry.path(), extension, output)?;
        } else if file_type.is_file()
            && extension.is_none_or(|expected| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
            })
        {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn provenance(
    source: &str,
    revision: &str,
    collected_at: DateTime<Utc>,
    files: &[(PathBuf, Vec<u8>)],
) -> Result<SnapshotProvenanceV1> {
    ensure!(
        !revision.trim().is_empty(),
        "{source} revision must not be empty"
    );
    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        let path = path.to_string_lossy();
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(SnapshotProvenanceV1 {
        source: source.to_owned(),
        revision: revision.to_owned(),
        sha256: sha256_hex(&hasher.finalize()),
        collected_at,
    })
}

fn import_rustsec(files: &[(PathBuf, Vec<u8>)]) -> Result<Vec<AdvisoryRecordV1>> {
    let mut advisories = Vec::new();
    for (path, bytes) in files {
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("RustSec advisory {} is not UTF-8", path.display()))?;
        let Some(frontmatter) = toml_fence(text) else {
            continue;
        };
        let document: toml::Value = toml::from_str(frontmatter)
            .with_context(|| format!("parsing RustSec advisory {}", path.display()))?;
        let advisory = document.get("advisory").and_then(toml::Value::as_table);
        let versions = document.get("versions").and_then(toml::Value::as_table);
        let Some(id) = advisory
            .and_then(|table| table.get("id"))
            .and_then(toml::Value::as_str)
        else {
            continue;
        };
        let Some(package) = advisory
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str)
        else {
            continue;
        };
        advisories.push(AdvisoryRecordV1 {
            id: id.to_owned(),
            source: ADVISORY_SOURCE_RUSTSEC.to_owned(),
            package: package.to_owned(),
            severity: advisory
                .and_then(|table| table.get("severity"))
                .and_then(toml::Value::as_str)
                .and_then(parse_severity),
            withdrawn: advisory.and_then(|table| table.get("withdrawn")).is_some(),
            vulnerable_versions: BTreeSet::new(),
            ranges: Vec::new(),
            patched_requirements: string_array(versions.and_then(|v| v.get("patched"))),
            unaffected_requirements: string_array(versions.and_then(|v| v.get("unaffected"))),
        });
    }
    Ok(advisories)
}

fn toml_fence(text: &str) -> Option<&str> {
    let marker = "```toml";
    let start = text.find(marker)? + marker.len();
    let rest = &text[start..];
    let end = rest.find("```")?;
    Some(rest[..end].trim())
}

fn string_array(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn import_osv(files: &[(PathBuf, Vec<u8>)]) -> Result<Vec<AdvisoryRecordV1>> {
    let mut advisories = Vec::new();
    for (path, bytes) in files {
        let value: JsonValue = serde_json::from_slice(bytes)
            .with_context(|| format!("parsing OSV input {}", path.display()))?;
        let records = value
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_else(|| std::slice::from_ref(&value));
        for record in records {
            let Some(id) = record.get("id").and_then(JsonValue::as_str) else {
                continue;
            };
            let severity = record
                .pointer("/database_specific/severity")
                .and_then(JsonValue::as_str)
                .and_then(parse_severity);
            for affected in record
                .get("affected")
                .and_then(JsonValue::as_array)
                .into_iter()
                .flatten()
            {
                let ecosystem = affected
                    .pointer("/package/ecosystem")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default();
                if !matches!(
                    ecosystem.to_ascii_lowercase().as_str(),
                    "crates.io" | "cargo"
                ) {
                    continue;
                }
                let Some(package) = affected
                    .pointer("/package/name")
                    .and_then(JsonValue::as_str)
                else {
                    continue;
                };
                advisories.push(AdvisoryRecordV1 {
                    id: id.to_owned(),
                    source: ADVISORY_SOURCE_OSV.to_owned(),
                    package: package.to_owned(),
                    severity,
                    withdrawn: record.get("withdrawn").is_some(),
                    vulnerable_versions: affected
                        .get("versions")
                        .and_then(JsonValue::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(JsonValue::as_str)
                        .filter_map(|value| Version::parse(value).ok())
                        .collect(),
                    ranges: osv_ranges(affected),
                    patched_requirements: Vec::new(),
                    unaffected_requirements: Vec::new(),
                });
            }
        }
    }
    Ok(advisories)
}

fn osv_ranges(affected: &JsonValue) -> Vec<AdvisoryRangeV1> {
    let mut ranges = Vec::new();
    for range in affected
        .get("ranges")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
    {
        if !matches!(
            range.get("type").and_then(JsonValue::as_str),
            Some("SEMVER" | "ECOSYSTEM")
        ) {
            continue;
        }
        let mut current: Option<AdvisoryRangeV1> = None;
        for event in range
            .get("events")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(introduced) = event.get("introduced").and_then(JsonValue::as_str) {
                if let Some(previous) = current.take() {
                    ranges.push(previous);
                }
                current = Some(AdvisoryRangeV1 {
                    introduced: (introduced != "0")
                        .then(|| Version::parse(introduced).ok())
                        .flatten(),
                    fixed: None,
                    last_affected: None,
                    limit: None,
                });
            }
            if let Some(active) = current.as_mut() {
                if let Some(value) = event
                    .get("fixed")
                    .and_then(JsonValue::as_str)
                    .and_then(|value| Version::parse(value).ok())
                {
                    active.fixed = Some(value);
                }
                if let Some(value) = event
                    .get("last_affected")
                    .and_then(JsonValue::as_str)
                    .and_then(|value| Version::parse(value).ok())
                {
                    active.last_affected = Some(value);
                }
                if let Some(value) = event
                    .get("limit")
                    .and_then(JsonValue::as_str)
                    .and_then(|value| Version::parse(value).ok())
                {
                    active.limit = Some(value);
                }
            }
        }
        if let Some(active) = current {
            ranges.push(active);
        }
    }
    ranges
}

fn import_crates_metadata(files: &[(PathBuf, Vec<u8>)]) -> Result<Vec<LicenseRecordV1>> {
    let mut licenses = Vec::new();
    for (path, bytes) in files {
        let value: JsonValue = serde_json::from_slice(bytes)
            .with_context(|| format!("parsing crates metadata {}", path.display()))?;
        if let Some(records) = value.as_array() {
            for record in records {
                add_normalized_license(record, &mut licenses);
            }
            continue;
        }
        let crate_name = value
            .pointer("/crate/id")
            .and_then(JsonValue::as_str)
            .or_else(|| value.pointer("/crate/name").and_then(JsonValue::as_str));
        if let (Some(crate_name), Some(versions)) = (
            crate_name,
            value.get("versions").and_then(JsonValue::as_array),
        ) {
            for version in versions {
                if let Some(number) = version.get("num").and_then(JsonValue::as_str)
                    && let Ok(version_number) = Version::parse(number)
                {
                    licenses.push(LicenseRecordV1 {
                        package: crate_name.to_owned(),
                        version: version_number,
                        expression: version
                            .get("license")
                            .and_then(JsonValue::as_str)
                            .map(str::to_owned),
                    });
                }
            }
        } else {
            add_normalized_license(&value, &mut licenses);
        }
    }
    Ok(licenses)
}

fn add_normalized_license(value: &JsonValue, output: &mut Vec<LicenseRecordV1>) {
    let package = value.get("package").and_then(JsonValue::as_str);
    let version = value
        .get("version")
        .and_then(JsonValue::as_str)
        .and_then(|version| Version::parse(version).ok());
    if let (Some(package), Some(version)) = (package, version) {
        output.push(LicenseRecordV1 {
            package: package.to_owned(),
            version,
            expression: value
                .get("license_expression")
                .and_then(JsonValue::as_str)
                .map(str::to_owned),
        });
    }
}

fn parse_severity(value: &str) -> Option<SeverityV1> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Some(SeverityV1::Low),
        "moderate" | "medium" => Some(SeverityV1::Medium),
        "high" => Some(SeverityV1::High),
        "critical" => Some(SeverityV1::Critical),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_version_matching_is_conservative() {
        let rustsec = AdvisoryRecordV1 {
            id: "RUSTSEC-1".to_owned(),
            source: ADVISORY_SOURCE_RUSTSEC.to_owned(),
            package: "demo".to_owned(),
            severity: None,
            withdrawn: false,
            vulnerable_versions: BTreeSet::new(),
            ranges: Vec::new(),
            patched_requirements: vec![">=1.2.0".to_owned()],
            unaffected_requirements: vec!["<1.0.0".to_owned()],
        };
        assert!(rustsec.affects(&Version::parse("1.1.0").unwrap()));
        assert!(!rustsec.affects(&Version::parse("1.2.0").unwrap()));
    }

    #[test]
    fn osv_versions_and_ranges_are_combined_after_exclusions() {
        let osv = AdvisoryRecordV1 {
            id: "OSV-1".to_owned(),
            source: ADVISORY_SOURCE_OSV.to_owned(),
            package: "demo".to_owned(),
            severity: None,
            withdrawn: false,
            vulnerable_versions: [Version::new(1, 0, 0)].into_iter().collect(),
            ranges: vec![AdvisoryRangeV1 {
                introduced: Some(Version::new(2, 0, 0)),
                fixed: Some(Version::new(3, 0, 0)),
                last_affected: None,
                limit: None,
            }],
            patched_requirements: vec![">=2.4.0,<2.5.0".to_owned()],
            unaffected_requirements: vec![">=2.6.0,<2.7.0".to_owned()],
        };

        assert!(osv.affects(&Version::new(1, 0, 0)));
        assert!(osv.affects(&Version::new(2, 1, 0)));
        assert!(!osv.affects(&Version::new(2, 4, 1)));
        assert!(!osv.affects(&Version::new(2, 6, 1)));
        assert!(!osv.affects(&Version::new(3, 0, 0)));
    }

    #[test]
    fn imports_rustsec_toml_fence() {
        let source = b"\x60\x60\x60toml\n[advisory]\nid = \"RUSTSEC-2026-0001\"\npackage = \"demo\"\n[versions]\npatched = [\">= 1.2.0\"]\n\x60\x60\x60";
        let records = import_rustsec(&[(PathBuf::from("one.md"), source.to_vec())]).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package, "demo");
    }
}
