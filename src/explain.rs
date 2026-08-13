//! Offline rendering of canonical dependency evidence.

use std::{
    fmt::Write as _,
    fs,
    io::{self, BufRead as _, BufReader, Read as _, Write as _},
    path::{Component, Path},
};

use anyhow::{Context as _, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    cargo_evidence::PackageIdentityV1,
    coordinator::{JobId, ScanJobStateV1, TaskId},
    evidence::{EvidenceBundleV1, RepositoryExplanationV1},
};

pub const SHARDED_EXPORT_SCHEMA_VERSION_V1: u16 = 1;
pub const SHARDED_EXPORT_MANIFEST: &str = "manifest.json";
const MAX_SHARD_RECORD_BYTES: u64 = 8 * 1024 * 1024 + 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceShardRecordV1 {
    pub task_id: TaskId,
    pub evidence: EvidenceBundleV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceShardV1 {
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
    pub records: u64,
    pub repositories: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShardedEvidenceManifestV1 {
    pub schema_version: u16,
    pub created_at: DateTime<Utc>,
    pub job_id: JobId,
    pub job_state: ScanJobStateV1,
    pub target: PackageIdentityV1,
    pub tasks_total: u64,
    pub tasks_succeeded: u64,
    pub artifacts_exported: u64,
    pub artifacts_missing: u64,
    pub repositories_exported: u64,
    pub input_artifact_bytes: u64,
    pub output_shard_bytes: u64,
    pub shard_target_bytes: u64,
    pub shards: Vec<EvidenceShardV1>,
    pub missing_task_ids: Vec<TaskId>,
}

pub fn load_bundle(path: &Path) -> Result<EvidenceBundleV1> {
    let bundle: EvidenceBundleV1 = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("reading evidence {}", path.display()))?,
    )
    .with_context(|| format!("parsing evidence {}", path.display()))?;
    ensure!(
        bundle.schema_is_supported(),
        "unsupported evidence schema {}",
        bundle.schema_version
    );
    Ok(bundle.normalized())
}

pub fn render(path: &Path, repository: Option<&str>, machine_json: bool) -> Result<()> {
    if path.is_dir() {
        return render_sharded(path, repository, machine_json);
    }
    let bundle = load_bundle(path)?;
    let explanations = bundle
        .repositories
        .iter()
        .filter(|evidence| {
            repository.is_none_or(|selected| {
                evidence.repository.eq_ignore_ascii_case(selected)
                    || evidence.repository_id.as_deref() == Some(selected)
            })
        })
        .map(|evidence| &evidence.explanation)
        .collect::<Vec<_>>();
    if repository.is_some() && explanations.is_empty() {
        bail!("repository was not found in the evidence bundle");
    }
    if machine_json {
        println!("{}", serde_json::to_string_pretty(&explanations)?);
        return Ok(());
    }
    print!("{}", render_markdown_document(&bundle, &explanations));
    Ok(())
}

fn render_sharded(path: &Path, repository: Option<&str>, machine_json: bool) -> Result<()> {
    let manifest = load_sharded_manifest(path)?;
    for shard in &manifest.shards {
        verify_shard(path, shard)?;
    }

    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut matched = false;
    if machine_json {
        output.write_all(b"[")?;
    } else {
        writeln!(
            output,
            "# Dependency evidence for {} {}\n\nJob: `{}`  \nState: `{:?}`  \nArtifacts: {} exported, {} unavailable\n",
            markdown_text(&manifest.target.name),
            manifest.target.version,
            markdown_text(&manifest.job_id.0),
            manifest.job_state,
            manifest.artifacts_exported,
            manifest.artifacts_missing
        )?;
    }

    for shard in &manifest.shards {
        visit_shard_records(path, shard, |record| {
            ensure!(
                record.evidence.schema_is_supported() && record.evidence.target == manifest.target,
                "shard record has an unsupported schema or mismatched target"
            );
            for evidence in &record.evidence.repositories {
                if repository.is_none_or(|selected| {
                    evidence.repository.eq_ignore_ascii_case(selected)
                        || evidence.repository_id.as_deref() == Some(selected)
                }) {
                    if machine_json {
                        if matched {
                            output.write_all(b",")?;
                        }
                        serde_json::to_writer(&mut output, &evidence.explanation)?;
                    } else {
                        let mut rendered = String::new();
                        render_explanation_markdown(&mut rendered, &evidence.explanation);
                        output.write_all(rendered.as_bytes())?;
                    }
                    matched = true;
                }
            }
            Ok(())
        })?;
    }
    if machine_json {
        output.write_all(b"]\n")?;
    }
    output.flush()?;
    if repository.is_some() && !matched {
        bail!("repository was not found in the sharded evidence export");
    }
    Ok(())
}

pub fn load_sharded_manifest(path: &Path) -> Result<ShardedEvidenceManifestV1> {
    let manifest_path = path.join(SHARDED_EXPORT_MANIFEST);
    let manifest: ShardedEvidenceManifestV1 = serde_json::from_slice(
        &fs::read(&manifest_path)
            .with_context(|| format!("reading export manifest {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parsing export manifest {}", manifest_path.display()))?;
    ensure!(
        manifest.schema_version == SHARDED_EXPORT_SCHEMA_VERSION_V1,
        "unsupported sharded evidence schema {}",
        manifest.schema_version
    );
    ensure!(
        manifest.shards.iter().map(|shard| shard.bytes).sum::<u64>() == manifest.output_shard_bytes,
        "export manifest shard byte total is inconsistent"
    );
    ensure!(
        manifest
            .shards
            .iter()
            .map(|shard| shard.records)
            .sum::<u64>()
            == manifest.artifacts_exported
            && manifest
                .shards
                .iter()
                .map(|shard| shard.repositories)
                .sum::<u64>()
                == manifest.repositories_exported
            && manifest.missing_task_ids.len() as u64 == manifest.artifacts_missing,
        "export manifest record totals are inconsistent"
    );
    Ok(manifest)
}

fn shard_path(root: &Path, file: &str) -> Result<std::path::PathBuf> {
    let path = Path::new(file);
    ensure!(
        path.components().count() == 1
            && matches!(path.components().next(), Some(Component::Normal(_))),
        "export manifest contains an unsafe shard path"
    );
    Ok(root.join(path))
}

fn verify_shard(root: &Path, shard: &EvidenceShardV1) -> Result<()> {
    let path = shard_path(root, &shard.file)?;
    let mut input = fs::File::open(&path)
        .with_context(|| format!("opening evidence shard {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .context("evidence shard length overflowed")?;
        hasher.update(&buffer[..read]);
    }
    ensure!(
        bytes == shard.bytes,
        "evidence shard byte count differs from manifest"
    );
    ensure!(
        hex_digest(&hasher.finalize()) == shard.sha256,
        "evidence shard digest differs from manifest"
    );
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn visit_shard_records(
    root: &Path,
    shard: &EvidenceShardV1,
    mut visit: impl FnMut(EvidenceShardRecordV1) -> Result<()>,
) -> Result<()> {
    let path = shard_path(root, &shard.file)?;
    let mut input = BufReader::new(fs::File::open(&path)?);
    let mut line = Vec::new();
    let mut records = 0_u64;
    loop {
        line.clear();
        let read = input
            .by_ref()
            .take(MAX_SHARD_RECORD_BYTES + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        ensure!(
            read as u64 <= MAX_SHARD_RECORD_BYTES,
            "evidence shard record exceeds the supported bound"
        );
        let record = serde_json::from_slice::<EvidenceShardRecordV1>(&line)
            .with_context(|| format!("parsing evidence shard {}", path.display()))?;
        visit(record)?;
        records += 1;
    }
    ensure!(
        records == shard.records,
        "evidence shard record count differs from manifest"
    );
    Ok(())
}

/// Render every repository in a canonical evidence bundle as Markdown.
#[must_use]
pub fn render_bundle_markdown(bundle: &EvidenceBundleV1) -> String {
    let explanations = bundle
        .repositories
        .iter()
        .map(|evidence| &evidence.explanation)
        .collect::<Vec<_>>();
    render_markdown_document(bundle, &explanations)
}

fn render_markdown_document(
    bundle: &EvidenceBundleV1,
    explanations: &[&RepositoryExplanationV1],
) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "# Dependency evidence for {} {}\n",
        markdown_text(&bundle.target.name),
        bundle.target.version
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "Generated: {}  \nGlobally exhaustive: {}\n",
        bundle.generated_at, bundle.globally_exhaustive
    )
    .expect("writing to a String cannot fail");
    if !bundle.limitations.is_empty() {
        writeln!(output, "## Bundle limitations\n").expect("writing to a String cannot fail");
        for limitation in &bundle.limitations {
            writeln!(
                output,
                "- {}: {}",
                markdown_text(&limitation.code),
                markdown_text(&limitation.message)
            )
            .expect("writing to a String cannot fail");
        }
        writeln!(output).expect("writing to a String cannot fail");
    }
    for explanation in explanations {
        render_explanation_markdown(&mut output, explanation);
    }
    output
}

fn render_explanation_markdown(output: &mut String, explanation: &RepositoryExplanationV1) {
    writeln!(output, "## {}\n", markdown_text(&explanation.repository))
        .expect("writing to a String cannot fail");
    writeln!(
        output,
        "- Evidence strength: {:?}\n- Completeness: {:?}\n- Observed: {}\n",
        explanation.strength, explanation.completeness, explanation.observed_at
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "### Inclusion chain\n").expect("writing to a String cannot fail");
    for step in &explanation.steps {
        let reference = step
            .reference
            .as_ref()
            .map_or_else(String::new, |reference| {
                let mut coordinates = Vec::new();
                if let Some(commit) = reference.commit_sha.as_deref() {
                    coordinates.push(format!("commit {}", markdown_text(commit)));
                }
                if let Some(path) = reference.path.as_deref() {
                    coordinates.push(format!("path {}", markdown_text(path)));
                }
                if let Some(blob) = reference.blob_sha.as_deref() {
                    coordinates.push(format!("blob {}", markdown_text(blob)));
                }
                if coordinates.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", coordinates.join(", "))
                }
            });
        writeln!(
            output,
            "1. **{:?}:** {}{}",
            step.kind,
            markdown_text(&step.statement),
            reference
        )
        .expect("writing to a String cannot fail");
    }
    if let Some(witness) = explanation.direct_witness.as_ref() {
        writeln!(output, "\nDirect witness: {}", witness_path(witness))
            .expect("writing to a String cannot fail");
    }
    if let Some(witness) = explanation.transitive_witness.as_ref() {
        writeln!(output, "\nTransitive witness: {}", witness_path(witness))
            .expect("writing to a String cannot fail");
    }
    if !explanation.limitations.is_empty() {
        writeln!(output, "\n### Limitations\n").expect("writing to a String cannot fail");
        for limitation in &explanation.limitations {
            writeln!(
                output,
                "- {}: {}",
                markdown_text(&limitation.code),
                markdown_text(&limitation.message)
            )
            .expect("writing to a String cannot fail");
        }
    }
    writeln!(output).expect("writing to a String cannot fail");
}

fn witness_path(witness: &crate::cargo_evidence::DependencyWitnessV1) -> String {
    witness
        .packages
        .iter()
        .map(|package| format!("{}@{}", package.name, package.version))
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn markdown_text(value: &str) -> String {
    value.replace(['\r', '\n'], " ").replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};
    use semver::Version;

    use super::*;
    use crate::{cargo_evidence::PackageIdentityV1, evidence::LimitationV1};

    #[test]
    fn bundle_markdown_escapes_target_and_global_limitations() {
        let bundle = EvidenceBundleV1 {
            schema_version: EvidenceBundleV1::SCHEMA_VERSION,
            generated_at: Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0).unwrap(),
            target: PackageIdentityV1 {
                name: "target|crate".to_owned(),
                version: Version::new(1, 2, 3),
                source: None,
            },
            globally_exhaustive: false,
            repositories: Vec::new(),
            advisory_snapshots: Vec::new(),
            limitations: vec![LimitationV1 {
                code: "partial|scan".to_owned(),
                message: "line one\nline two".to_owned(),
            }],
        };

        let markdown = render_bundle_markdown(&bundle);
        assert!(markdown.contains("# Dependency evidence for target\\|crate 1.2.3"));
        assert!(markdown.contains("- partial\\|scan: line one line two"));
    }
}
