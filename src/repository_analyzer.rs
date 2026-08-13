//! Bounded analysis of one immutable GitHub repository snapshot.
//!
//! Distributed workers use this seam directly. It intentionally does not use
//! the inventory CSV projection, so retrying a task cannot repeat discovery or
//! alter the standalone scan fast path.

use anyhow::{Context as _, Result, bail, ensure};
use chrono::Utc;
use futures::{StreamExt as _, stream};
use semver::Version;
use serde::Serialize;

use crate::{
    cargo_evidence::{
        CargoLockEvidence, DependencyWitnessV1, DirectDeclaration, PackageIdentityV1,
        RecordedRelation, analyze_cargo_lock_with_packages, analyze_cargo_manifests,
    },
    coordinator::{ReuseFingerprintV1, Sha256Digest},
    evidence::{
        DirectRequirementEvidenceV1, EvidenceBundleV1, EvidenceCompletenessV1, EvidenceReferenceV1,
        EvidenceStrengthV1, ExplanationStepKindV1, ExplanationStepV1, LimitationV1,
        PackageEvidenceV1, RepositoryEvidenceV1, RepositoryExplanationV1, RepositoryVisibilityV1,
        RequirementEvidenceSourceV1,
    },
    github::{
        GitHubClient, GitHubHead, GitHubRepo, GitHubRepository, GitHubTreeEntry,
        RepositoryVisibility,
    },
    secure_cache::sha256_hex,
};

const DEFAULT_FILE_LIMIT: usize = 2_000;
const DEFAULT_FILE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_REPOSITORY_BYTES: u64 = 128 * 1024 * 1024;

/// Bump when repository analysis semantics or the derived evidence schema
/// changes. This value is part of every durable reuse fingerprint.
pub const REPOSITORY_ANALYZER_VERSION: &str = "cargo-repository-v1";
const EVIDENCE_PROFILE: &str = "cargo-evidence-v1-full-graph-msrv-targets";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryAnalyzerBounds {
    pub file_limit: usize,
    pub file_bytes: u64,
    pub repository_bytes: u64,
    pub concurrent_requests: usize,
}

/// The current canonical repository identity and immutable default-branch
/// revision. Resolving this snapshot is deliberately outside cache reuse so a
/// warm scan still observes repository visibility and the current HEAD.
#[derive(Clone, Debug)]
pub struct ResolvedRepositorySnapshot {
    pub repository: GitHubRepository,
    pub head: GitHubHead,
}

#[derive(Serialize)]
struct SemanticBounds {
    file_limit: usize,
    file_bytes: u64,
    repository_bytes: u64,
}

#[derive(Serialize)]
struct TargetFingerprint<'a> {
    crate_name: &'a str,
    version: &'a Version,
}

impl Default for RepositoryAnalyzerBounds {
    fn default() -> Self {
        Self {
            file_limit: DEFAULT_FILE_LIMIT,
            file_bytes: DEFAULT_FILE_BYTES,
            repository_bytes: DEFAULT_REPOSITORY_BYTES,
            concurrent_requests: 4,
        }
    }
}

impl RepositoryAnalyzerBounds {
    fn validate(self) -> Result<Self> {
        ensure!(
            self.file_limit > 0,
            "repository file limit must be positive"
        );
        ensure!(self.file_bytes > 0, "per-file byte limit must be positive");
        ensure!(
            self.repository_bytes > 0,
            "repository byte limit must be positive"
        );
        ensure!(
            self.concurrent_requests > 0,
            "repository request concurrency must be positive"
        );
        Ok(self)
    }
}

#[derive(Debug)]
struct FetchedBlob {
    path: String,
    sha: String,
    text: String,
}

#[derive(Debug)]
struct BlobSet {
    blobs: Vec<FetchedBlob>,
    limitations: Vec<LimitationV1>,
}

/// Analyze the exact default-branch revision of one repository.
pub async fn analyze_repository(
    github: &GitHubClient,
    repository_name: &str,
    target_name: &str,
    target_version: &Version,
    repository_scope: crate::github::RepositoryScope,
    bounds: RepositoryAnalyzerBounds,
) -> Result<EvidenceBundleV1> {
    let snapshot = resolve_repository_snapshot(github, repository_name, repository_scope).await?;
    analyze_repository_snapshot(github, &snapshot, target_name, target_version, bounds).await
}

/// Resolve repository metadata and the current default-branch HEAD. These two
/// provider reads are always performed, including on an incremental cache hit.
pub async fn resolve_repository_snapshot(
    github: &GitHubClient,
    repository_name: &str,
    repository_scope: crate::github::RepositoryScope,
) -> Result<ResolvedRepositorySnapshot> {
    let repo = GitHubRepo::parse(repository_name)
        .ok_or_else(|| anyhow::anyhow!("repository must be a GitHub owner/name identifier"))?;
    let repository = github.repository(&repo).await?;
    ensure!(
        repository_scope.includes(repository.effective_visibility()),
        "repository visibility is outside the requested scope"
    );
    let head = github.default_branch_head(&repository).await?;
    Ok(ResolvedRepositorySnapshot { repository, head })
}

/// Analyze Cargo evidence from an already resolved immutable snapshot.
/// Callers may skip this function only after an authenticated, complete cache
/// entry matches [`analysis_reuse_fingerprint`].
pub async fn analyze_repository_snapshot(
    github: &GitHubClient,
    snapshot: &ResolvedRepositorySnapshot,
    target_name: &str,
    target_version: &Version,
    bounds: RepositoryAnalyzerBounds,
) -> Result<EvidenceBundleV1> {
    let bounds = bounds.validate()?;
    let repository = &snapshot.repository;
    let head = &snapshot.head;
    let repo = repository.repo();
    let tree = github.recursive_tree(&repo, &head.tree_sha).await?;

    let mut entries = tree
        .tree
        .into_iter()
        .filter(|entry| entry.is_blob() && is_cargo_evidence_path(&entry.path))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let mut limitations = Vec::new();
    if tree.truncated {
        limitations.push(limitation(
            "github_tree_truncated",
            "GitHub truncated the recursive tree; missing Cargo files remain unknown",
        ));
    }
    if entries.len() > bounds.file_limit {
        limitations.push(limitation(
            "repository_file_limit",
            &format!(
                "matched {} Cargo files; analyzed the first {} in path order",
                entries.len(),
                bounds.file_limit
            ),
        ));
        entries.truncate(bounds.file_limit);
    }

    let selected = admit_known_sizes(entries, bounds, &mut limitations);
    let mut fetched = fetch_blobs(github, &repo, selected, bounds).await;
    limitations.append(&mut fetched.limitations);
    let mut manifest_blobs = Vec::new();
    let mut lock_blobs = Vec::new();
    for blob in fetched.blobs {
        if final_component(&blob.path) == "Cargo.toml" {
            manifest_blobs.push(blob);
        } else {
            lock_blobs.push(blob);
        }
    }

    let manifest_evidence = analyze_cargo_manifests(
        manifest_blobs
            .iter()
            .map(|blob| (blob.path.as_str(), blob.text.as_str())),
        target_name,
        target_version,
    );
    limitations.extend(manifest_evidence.diagnostics.iter().map(|diagnostic| {
        limitation(
            "manifest_diagnostic",
            &format!("{}: {}", diagnostic.manifest_path, diagnostic.message),
        )
    }));

    let mut lock_evidence = Vec::new();
    for blob in &lock_blobs {
        match analyze_cargo_lock_with_packages(&blob.text, target_name, target_version) {
            Ok(evidence) => lock_evidence.push((blob, evidence)),
            Err(error) => limitations.push(limitation(
                "lock_parse_failed",
                &format!("{}: {error:#}", blob.path),
            )),
        }
    }

    let repository_evidence = project_repository(
        repository,
        &head.sha,
        &head.tree_sha,
        head.committed_at,
        target_name,
        target_version,
        &manifest_blobs,
        &manifest_evidence.declarations,
        manifest_evidence.effective_msrv.as_deref(),
        &lock_evidence,
        limitations.clone(),
        !tree.truncated && limitations.is_empty(),
    );

    Ok(EvidenceBundleV1 {
        schema_version: EvidenceBundleV1::SCHEMA_VERSION,
        generated_at: Utc::now(),
        target: PackageIdentityV1 {
            name: target_name.to_owned(),
            version: target_version.clone(),
            source: None,
        },
        globally_exhaustive: false,
        repositories: vec![repository_evidence],
        advisory_snapshots: Vec::new(),
        limitations,
    }
    .normalized())
}

/// Build the stable key for complete derived-evidence reuse. Request
/// concurrency is intentionally excluded because it cannot affect evidence;
/// all semantic byte and file bounds are included.
pub fn analysis_reuse_fingerprint(
    snapshot: &ResolvedRepositorySnapshot,
    target_name: &str,
    target_version: &Version,
    bounds: RepositoryAnalyzerBounds,
) -> Result<ReuseFingerprintV1> {
    let bounds = bounds.validate()?;
    Ok(ReuseFingerprintV1 {
        repository_id: snapshot.repository.id.to_string(),
        tree_sha: snapshot.head.tree_sha.clone(),
        analyzer_version: REPOSITORY_ANALYZER_VERSION.to_owned(),
        bounds_hash: digest_json(&SemanticBounds {
            file_limit: bounds.file_limit,
            file_bytes: bounds.file_bytes,
            repository_bytes: bounds.repository_bytes,
        })?,
        target_hash: analysis_target_hash(target_name, target_version)?,
        evidence_profile_hash: analysis_evidence_profile_hash(),
    })
}

pub fn analysis_target_hash(target_name: &str, target_version: &Version) -> Result<Sha256Digest> {
    digest_json(&TargetFingerprint {
        crate_name: target_name,
        version: target_version,
    })
}

pub fn analysis_evidence_profile_hash() -> Sha256Digest {
    digest_bytes(EVIDENCE_PROFILE.as_bytes())
}

/// Validate and annotate a complete authenticated cache result for the current
/// snapshot. The cached observation stays immutable; the bundle timestamp and
/// cache-reuse explanation describe this scan's observation.
pub fn reuse_cached_evidence(
    mut evidence: EvidenceBundleV1,
    snapshot: &ResolvedRepositorySnapshot,
    target_name: &str,
    target_version: &Version,
) -> Result<EvidenceBundleV1> {
    ensure!(
        evidence.schema_is_supported(),
        "unsupported cached evidence schema"
    );
    ensure!(
        evidence.target.name == target_name && evidence.target.version == *target_version,
        "cached evidence target mismatch"
    );
    ensure!(
        evidence.repositories.len() == 1,
        "cached evidence must contain exactly one repository"
    );
    ensure!(
        evidence.limitations.is_empty(),
        "cached evidence is incomplete"
    );
    let repository = &mut evidence.repositories[0];
    let repository_id = snapshot.repository.id.to_string();
    ensure!(
        repository
            .repository
            .eq_ignore_ascii_case(&snapshot.repository.full_name)
            && repository.repository_id.as_deref() == Some(repository_id.as_str()),
        "cached evidence repository mismatch"
    );
    ensure!(
        repository.completeness == EvidenceCompletenessV1::Complete
            && repository.explanation.completeness == EvidenceCompletenessV1::Complete,
        "partial cached evidence cannot be reused"
    );
    ensure!(
        repository.visibility == map_visibility(snapshot.repository.effective_visibility()),
        "cached evidence visibility mismatch"
    );
    ensure!(
        repository.explanation.steps.iter().any(|step| {
            step.kind == ExplanationStepKindV1::ImmutableRevision
                && step.reference.as_ref().is_some_and(|reference| {
                    reference.tree_sha.as_deref() == Some(snapshot.head.tree_sha.as_str())
                })
        }),
        "cached evidence immutable revision mismatch"
    );

    let observed_at = Utc::now();
    evidence.generated_at = observed_at;
    repository.head_committed_at = Some(snapshot.head.committed_at);
    repository.explanation.observed_at = observed_at;
    repository.explanation.steps.retain(|step| {
        step.kind != ExplanationStepKindV1::CacheReuse
            && !(step.kind == ExplanationStepKindV1::ImmutableRevision
                && step
                    .statement
                    .starts_with("confirmed the current default-branch HEAD"))
    });
    repository.explanation.steps.push(ExplanationStepV1 {
        kind: ExplanationStepKindV1::ImmutableRevision,
        statement: "confirmed the current default-branch HEAD has the cached immutable tree"
            .to_owned(),
        reference: Some(EvidenceReferenceV1 {
            commit_sha: Some(snapshot.head.sha.clone()),
            tree_sha: Some(snapshot.head.tree_sha.clone()),
            path: None,
            blob_sha: None,
        }),
    });
    repository.explanation.steps.push(ExplanationStepV1 {
        kind: ExplanationStepKindV1::CacheReuse,
        statement:
            "reused authenticated complete derived evidence for the unchanged immutable tree"
                .to_owned(),
        reference: Some(EvidenceReferenceV1 {
            commit_sha: Some(snapshot.head.sha.clone()),
            tree_sha: Some(snapshot.head.tree_sha.clone()),
            path: None,
            blob_sha: None,
        }),
    });
    Ok(evidence.normalized())
}

fn digest_json(value: &impl Serialize) -> Result<Sha256Digest> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(sha256_hex(bytes)).expect("SHA-256 encoder produces a valid digest")
}

fn admit_known_sizes(
    entries: Vec<GitHubTreeEntry>,
    bounds: RepositoryAnalyzerBounds,
    limitations: &mut Vec<LimitationV1>,
) -> Vec<GitHubTreeEntry> {
    let mut admitted = Vec::new();
    let mut reserved = 0_u64;
    for entry in entries {
        if entry.size.is_some_and(|size| size > bounds.file_bytes) {
            limitations.push(limitation(
                "cargo_file_too_large",
                &format!("{} exceeds the per-file byte limit", entry.path),
            ));
            continue;
        }
        // Unknown sizes reserve the per-file maximum before requests launch.
        // A declared size also becomes the response cap below.
        let reservation = entry.size.unwrap_or(bounds.file_bytes);
        if reserved.saturating_add(reservation) > bounds.repository_bytes {
            limitations.push(limitation(
                "repository_byte_limit",
                "Cargo file sizes exceed the repository byte budget",
            ));
            continue;
        }
        reserved = reserved.saturating_add(reservation);
        admitted.push(entry);
    }
    admitted
}

async fn fetch_blobs(
    github: &GitHubClient,
    repo: &GitHubRepo,
    entries: Vec<GitHubTreeEntry>,
    bounds: RepositoryAnalyzerBounds,
) -> BlobSet {
    let results = stream::iter(entries.into_iter().enumerate().map(|(position, entry)| {
        let github = github.clone();
        let repo = repo.clone();
        async move {
            let response_limit = entry
                .size
                .unwrap_or(bounds.file_bytes)
                .min(bounds.file_bytes);
            let result = github.blob_by_sha(&repo, &entry.sha, response_limit).await;
            (position, entry, result)
        }
    }))
    .buffer_unordered(bounds.concurrent_requests)
    .collect::<Vec<_>>()
    .await;
    let mut results = results;
    results.sort_by_key(|(position, _, _)| *position);

    let mut retained_bytes = 0_u64;
    let mut blobs = Vec::new();
    let mut limitations = Vec::new();
    for (_, entry, result) in results {
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(error) => {
                limitations.push(limitation(
                    "cargo_blob_fetch_failed",
                    &format!("{}: {error:#}", entry.path),
                ));
                continue;
            }
        };
        if retained_bytes.saturating_add(bytes.len() as u64) > bounds.repository_bytes {
            limitations.push(limitation(
                "repository_byte_limit",
                &format!(
                    "{} was not retained because the byte budget was exhausted",
                    entry.path
                ),
            ));
            continue;
        }
        retained_bytes = retained_bytes.saturating_add(bytes.len() as u64);
        match String::from_utf8(bytes) {
            Ok(text) => blobs.push(FetchedBlob {
                path: entry.path,
                sha: entry.sha,
                text,
            }),
            Err(error) => limitations.push(limitation(
                "cargo_blob_not_utf8",
                &format!("{}: {error}", entry.path),
            )),
        }
    }
    BlobSet { blobs, limitations }
}

#[allow(clippy::too_many_arguments)]
fn project_repository(
    repository: &GitHubRepository,
    head_sha: &str,
    tree_sha: &str,
    committed_at: chrono::DateTime<Utc>,
    target_name: &str,
    target_version: &Version,
    manifests: &[FetchedBlob],
    declarations: &[DirectDeclaration],
    msrv: Option<&str>,
    locks: &[(&FetchedBlob, CargoLockEvidence)],
    limitations: Vec<LimitationV1>,
    complete: bool,
) -> RepositoryEvidenceV1 {
    let relation = locks
        .iter()
        .fold(RecordedRelation::NotRecorded, |current, (_, evidence)| {
            merge_relation(current, evidence.recorded_relation)
        });
    let exact_resolution_count = locks
        .iter()
        .map(|(_, evidence)| evidence.exact_occurrences)
        .sum();
    let direct_witness = best_witness(
        locks
            .iter()
            .filter_map(|(_, evidence)| evidence.direct_witness.as_ref()),
    );
    let transitive_witness = best_witness(
        locks
            .iter()
            .filter_map(|(_, evidence)| evidence.transitive_witness.as_ref()),
    );
    let strongest_lock = locks
        .iter()
        .map(|(_, evidence)| evidence)
        .max_by_key(|evidence| {
            (
                evidence.graph_analysis_complete,
                evidence.exact_occurrences,
                relation_rank(evidence.recorded_relation),
            )
        });
    let strength = EvidenceStrengthV1::classify(strongest_lock, !declarations.is_empty(), false);
    let package_inventory_complete = !locks.is_empty()
        && locks
            .iter()
            .all(|(_, evidence)| evidence.package_inventory_complete);
    let packages = locks
        .iter()
        .flat_map(|(_, evidence)| evidence.reachable_packages.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|package| PackageEvidenceV1 {
            package,
            license_expression: None,
        })
        .collect::<Vec<_>>();
    let completeness = if complete {
        EvidenceCompletenessV1::Complete
    } else {
        EvidenceCompletenessV1::Partial
    };
    let requirements = declarations
        .iter()
        .map(|declaration| DirectRequirementEvidenceV1 {
            source: RequirementEvidenceSourceV1::CurrentManifest,
            manifest_path: declaration.manifest_path.clone(),
            package_name: declaration.package_name.clone(),
            requirement: declaration.requirement.clone(),
            accepts_target: declaration.requirement_accepts,
            explicit_exact_pin: declaration.explicit_exact_pin,
        })
        .collect();
    let mut steps = vec![
        ExplanationStepV1 {
            kind: ExplanationStepKindV1::RepositoryIdentity,
            statement: format!(
                "resolved canonical GitHub repository {}",
                repository.full_name
            ),
            reference: None,
        },
        ExplanationStepV1 {
            kind: ExplanationStepKindV1::VisibilityDecision,
            statement: format!(
                "repository visibility is {}",
                repository.effective_visibility().as_str()
            ),
            reference: None,
        },
        ExplanationStepV1 {
            kind: ExplanationStepKindV1::ImmutableRevision,
            statement: "analyzed the immutable default-branch head and recursive tree".to_owned(),
            reference: Some(EvidenceReferenceV1 {
                commit_sha: Some(head_sha.to_owned()),
                tree_sha: Some(tree_sha.to_owned()),
                path: None,
                blob_sha: None,
            }),
        },
    ];
    steps.extend(
        manifests
            .iter()
            .filter(|manifest| {
                declarations
                    .iter()
                    .any(|declaration| declaration.manifest_path == manifest.path)
            })
            .map(|manifest| ExplanationStepV1 {
                kind: ExplanationStepKindV1::ManifestDeclaration,
                statement: format!("{} declares {target_name} {target_version}", manifest.path),
                reference: Some(EvidenceReferenceV1 {
                    commit_sha: Some(head_sha.to_owned()),
                    tree_sha: Some(tree_sha.to_owned()),
                    path: Some(manifest.path.clone()),
                    blob_sha: Some(manifest.sha.clone()),
                }),
            }),
    );
    steps.extend(
        locks
            .iter()
            .filter(|(_, evidence)| evidence.exact_occurrences > 0)
            .map(|(blob, evidence)| ExplanationStepV1 {
                kind: ExplanationStepKindV1::LockResolution,
                statement: format!(
                    "{} records {} exact occurrence(s) with relation {:?}",
                    blob.path, evidence.exact_occurrences, evidence.recorded_relation
                ),
                reference: Some(EvidenceReferenceV1 {
                    commit_sha: Some(head_sha.to_owned()),
                    tree_sha: Some(tree_sha.to_owned()),
                    path: Some(blob.path.clone()),
                    blob_sha: Some(blob.sha.clone()),
                }),
            }),
    );

    RepositoryEvidenceV1 {
        repository: repository.full_name.clone(),
        repository_id: Some(repository.id.to_string()),
        visibility: map_visibility(repository.effective_visibility()),
        head_committed_at: Some(committed_at),
        completeness,
        requirements,
        exact_resolution_count,
        recorded_relation: relation,
        direct_witness: direct_witness.clone(),
        transitive_witness: transitive_witness.clone(),
        msrv: msrv.and_then(|value| Version::parse(value).ok()),
        package_inventory_complete,
        packages: if packages.is_empty() {
            vec![PackageEvidenceV1 {
                package: PackageIdentityV1 {
                    name: target_name.to_owned(),
                    version: target_version.clone(),
                    source: None,
                },
                license_expression: None,
            }]
        } else {
            packages
        },
        vulnerabilities: Vec::new(),
        explanation: RepositoryExplanationV1 {
            repository: repository.full_name.clone(),
            observed_at: Utc::now(),
            strength,
            completeness,
            steps,
            limitations,
            direct_witness,
            transitive_witness,
        },
    }
}

fn best_witness<'a>(
    witnesses: impl Iterator<Item = &'a DependencyWitnessV1>,
) -> Option<DependencyWitnessV1> {
    witnesses
        .min_by(|left, right| {
            left.packages
                .len()
                .cmp(&right.packages.len())
                .then_with(|| left.packages.cmp(&right.packages))
        })
        .cloned()
}

fn merge_relation(left: RecordedRelation, right: RecordedRelation) -> RecordedRelation {
    use RecordedRelation::{
        Direct, DirectAndTransitive, NotRecorded, PresentUnclassified, Transitive,
    };
    match (left, right) {
        (DirectAndTransitive, _) | (_, DirectAndTransitive) => DirectAndTransitive,
        (Direct, Transitive) | (Transitive, Direct) => DirectAndTransitive,
        (Direct, _) | (_, Direct) => Direct,
        (Transitive, _) | (_, Transitive) => Transitive,
        (PresentUnclassified, _) | (_, PresentUnclassified) => PresentUnclassified,
        (NotRecorded, NotRecorded) => NotRecorded,
    }
}

fn relation_rank(relation: RecordedRelation) -> u8 {
    match relation {
        RecordedRelation::DirectAndTransitive => 4,
        RecordedRelation::Direct | RecordedRelation::Transitive => 3,
        RecordedRelation::PresentUnclassified => 2,
        RecordedRelation::NotRecorded => 1,
    }
}

fn map_visibility(visibility: RepositoryVisibility) -> RepositoryVisibilityV1 {
    match visibility {
        RepositoryVisibility::Public => RepositoryVisibilityV1::Public,
        RepositoryVisibility::Private => RepositoryVisibilityV1::Private,
        RepositoryVisibility::Internal => RepositoryVisibilityV1::Internal,
        RepositoryVisibility::Unknown => RepositoryVisibilityV1::Unknown,
    }
}

fn is_cargo_evidence_path(path: &str) -> bool {
    matches!(final_component(path), "Cargo.toml" | "Cargo.lock")
}

fn final_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn limitation(code: &str, message: &str) -> LimitationV1 {
    LimitationV1 {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

/// Parse an exact distributed scan target. Requirements intentionally remain a
/// submission-time error until range-aware lock evidence has a versioned model.
pub fn exact_target_version(version_spec: &str) -> Result<Version> {
    let value = version_spec.strip_prefix('=').unwrap_or(version_spec);
    if value.contains(',') || value.starts_with(['^', '~', '>', '<', '*']) {
        bail!("distributed repository analysis currently requires an exact version")
    }
    Version::parse(value).context("parsing exact scan target version")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    #[test]
    fn exact_target_accepts_bare_and_explicit_exact_versions() {
        assert_eq!(
            exact_target_version("0.4.3").unwrap(),
            Version::new(0, 4, 3)
        );
        assert_eq!(
            exact_target_version("=0.4.3").unwrap(),
            Version::new(0, 4, 3)
        );
        assert!(exact_target_version("^0.4").is_err());
    }

    #[test]
    fn byte_admission_is_deterministic() {
        let entry = |path: &str, size| GitHubTreeEntry {
            path: path.to_owned(),
            mode: "100644".to_owned(),
            kind: "blob".to_owned(),
            sha: path.to_owned(),
            size: Some(size),
            url: None,
        };
        let mut limitations = Vec::new();
        let admitted = admit_known_sizes(
            vec![entry("a/Cargo.toml", 7), entry("b/Cargo.lock", 7)],
            RepositoryAnalyzerBounds {
                repository_bytes: 10,
                file_bytes: 10,
                ..RepositoryAnalyzerBounds::default()
            },
            &mut limitations,
        );
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].path, "a/Cargo.toml");
        assert_eq!(limitations[0].code, "repository_byte_limit");
    }

    #[tokio::test]
    async fn same_head_reuse_resolves_metadata_but_skips_tree_and_blobs() {
        let server = MockServer::start().await;
        let manifest = br#"[package]
name = "app"
version = "1.0.0"

[dependencies]
fs2 = "0.4.3"
"#;
        let lock = br#"version = 3

[[package]]
name = "app"
version = "1.0.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.4.3"
"#;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 42,
                "name": "widget",
                "full_name": "acme/widget",
                "html_url": "https://github.com/acme/widget",
                "owner": {
                    "login": "acme",
                    "id": 7,
                    "html_url": "https://github.com/acme"
                },
                "default_branch": "main",
                "private": false
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/commits/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sha": "head-sha",
                "commit": {
                    "author": {"date": "2026-08-01T12:00:00Z"},
                    "committer": {"date": "2026-08-01T12:00:00Z"},
                    "tree": {"sha": "tree-sha"}
                }
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/git/trees/tree-sha"))
            .and(query_param("recursive", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sha": "tree-sha",
                "truncated": false,
                "tree": [
                    {
                        "path": "Cargo.toml",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "manifest-sha",
                        "size": manifest.len()
                    },
                    {
                        "path": "Cargo.lock",
                        "mode": "100644",
                        "type": "blob",
                        "sha": "lock-sha",
                        "size": lock.len()
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        for (sha, body) in [
            ("manifest-sha", manifest.as_slice()),
            ("lock-sha", lock.as_slice()),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widget/git/blobs/{sha}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .expect(1)
                .mount(&server)
                .await;
        }

        let github =
            GitHubClient::with_api_base(None, Url::parse(&format!("{}/", server.uri())).unwrap())
                .unwrap();
        let target_version = Version::new(0, 4, 3);
        let bounds = RepositoryAnalyzerBounds::default();
        let first_snapshot = resolve_repository_snapshot(
            &github,
            "acme/widget",
            crate::github::RepositoryScope::PublicOnly,
        )
        .await
        .unwrap();
        let cold =
            analyze_repository_snapshot(&github, &first_snapshot, "fs2", &target_version, bounds)
                .await
                .unwrap();
        let fingerprint =
            analysis_reuse_fingerprint(&first_snapshot, "fs2", &target_version, bounds).unwrap();
        assert_eq!(github.usage().requests, 5);

        let second_snapshot = resolve_repository_snapshot(
            &github,
            "acme/widget",
            crate::github::RepositoryScope::PublicOnly,
        )
        .await
        .unwrap();
        assert_eq!(
            analysis_reuse_fingerprint(&second_snapshot, "fs2", &target_version, bounds).unwrap(),
            fingerprint
        );
        let warm = reuse_cached_evidence(cold, &second_snapshot, "fs2", &target_version).unwrap();

        assert_eq!(github.usage().requests, 7);
        assert!(
            warm.repositories[0]
                .explanation
                .steps
                .iter()
                .any(|step| step.kind == ExplanationStepKindV1::CacheReuse)
        );
    }

    #[test]
    fn semantic_bound_changes_invalidate_reuse() {
        let repository: GitHubRepository = serde_json::from_value(json!({
            "id": 42,
            "name": "widget",
            "full_name": "acme/widget",
            "html_url": "https://github.com/acme/widget",
            "owner": {"login": "acme", "id": 7, "html_url": "https://github.com/acme"},
            "default_branch": "main",
            "private": false
        }))
        .unwrap();
        let snapshot = ResolvedRepositorySnapshot {
            repository,
            head: GitHubHead {
                sha: "head".to_owned(),
                tree_sha: "tree".to_owned(),
                committed_at: Utc::now(),
                authored_at: None,
                html_url: None,
            },
        };
        let target = Version::new(0, 4, 3);
        let baseline = analysis_reuse_fingerprint(
            &snapshot,
            "fs2",
            &target,
            RepositoryAnalyzerBounds::default(),
        )
        .unwrap();
        let changed = analysis_reuse_fingerprint(
            &snapshot,
            "fs2",
            &target,
            RepositoryAnalyzerBounds {
                file_bytes: DEFAULT_FILE_BYTES + 1,
                ..RepositoryAnalyzerBounds::default()
            },
        )
        .unwrap();
        assert_ne!(baseline.bounds_hash, changed.bounds_hash);
    }
}
