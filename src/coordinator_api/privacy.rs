//! Bounded, restartable removal behind the published suppression policy.

use anyhow::{Context as _, Result, ensure};
use tokio::sync::RwLockReadGuard;

use super::*;
use crate::privacy::{
    PrivacyState, REMOVAL_BATCH_SIZE, RemovalPhaseV1, RemovalRequestV1, SuppressionTargetV1,
};

pub(super) async fn read_guard(
    state: &ApiState,
) -> Result<Option<RwLockReadGuard<'_, PrivacyState>>, ApiError> {
    let Some(privacy) = &state.privacy else {
        return Ok(None);
    };
    let guard = privacy.gate.read().await;
    if !guard.ready {
        return Err(ApiError::unavailable(
            "privacy_policy_unavailable",
            "evidence access is temporarily unavailable",
        ));
    }
    Ok(Some(guard))
}

pub(super) fn ensure_allowed(
    guard: &Option<RwLockReadGuard<'_, PrivacyState>>,
    namespace: &CacheNamespaceV1,
    repository_id: &str,
    alias: &str,
) -> Result<(), ApiError> {
    if guard.as_ref().is_some_and(|policy| {
        policy
            .ledger
            .suppresses(&inventory_namespace(namespace), repository_id, alias)
    }) {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "repository_unavailable",
            message: "repository evidence is unavailable".to_owned(),
        });
    }
    Ok(())
}

pub(super) fn ensure_evidence_allowed(
    guard: &Option<RwLockReadGuard<'_, PrivacyState>>,
    namespace: &CacheNamespaceV1,
    evidence: &EvidenceBundleV1,
) -> Result<(), ApiError> {
    for repository in &evidence.repositories {
        ensure_allowed(
            guard,
            namespace,
            repository.repository_id.as_deref().unwrap_or(""),
            &repository.repository,
        )?;
    }
    Ok(())
}

fn inventory_namespace(namespace: &CacheNamespaceV1) -> InventoryNamespaceV1 {
    match namespace {
        CacheNamespaceV1::Public => InventoryNamespaceV1::Public,
        CacheNamespaceV1::Private { principal_id } => InventoryNamespaceV1::Private {
            credential_profile_id: principal_id.clone(),
        },
    }
}

pub(super) fn spawn(state: ApiState) {
    let Some(privacy) = state.privacy.clone() else {
        return;
    };
    tokio::spawn(async move {
        loop {
            if let Err(_error) = run_to_completion(&state).await {
                tracing::warn!(
                    reason = "removal_incomplete",
                    "repository removal requires attention"
                );
            }
            tokio::select! {
                _ = privacy.notify.notified() => {},
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {},
            }
        }
    });
}

pub(super) async fn run_to_completion(state: &ApiState) -> Result<()> {
    let Some(privacy) = &state.privacy else {
        return Ok(());
    };
    let mut next_request = 0;
    loop {
        let records = {
            let policy = privacy.gate.read().await;
            state.metrics.privacy_removals_incomplete.set(
                i64::try_from(
                    policy
                        .ledger
                        .records
                        .iter()
                        .filter(|record| record.phase != RemovalPhaseV1::Completed)
                        .count(),
                )
                .unwrap_or(i64::MAX),
            );
            ensure!(policy.ready, "privacy policy is unavailable");
            removal_batch(&policy.ledger.records, &mut next_request)
        };
        if records.is_empty() {
            break;
        }
        for mut record in records {
            if let Err(_error) = step(state, &mut record).await {
                state.metrics.privacy_removal_failures.inc();
                record.phase = RemovalPhaseV1::Failed;
                record.failure_code = Some("removal_batch_failed".to_owned());
            }
            privacy.update(record).await?;
            tokio::task::yield_now().await;
        }
    }
    ensure!(
        !privacy
            .gate
            .read()
            .await
            .ledger
            .records
            .iter()
            .any(|record| record.phase == RemovalPhaseV1::Failed),
        "one or more removals remain incomplete"
    );
    Ok(())
}

fn removal_batch(records: &[RemovalRequestV1], next_request: &mut usize) -> Vec<RemovalRequestV1> {
    if records.is_empty() {
        *next_request = 0;
        return Vec::new();
    }
    let start = *next_request % records.len();
    let mut selected = Vec::with_capacity(REMOVAL_BATCH_SIZE.min(records.len()));
    for offset in 0..records.len() {
        let index = (start + offset) % records.len();
        *next_request = (index + 1) % records.len();
        let record = &records[index];
        if !matches!(
            record.phase,
            RemovalPhaseV1::Completed | RemovalPhaseV1::Failed
        ) {
            selected.push(record.clone());
            if selected.len() == REMOVAL_BATCH_SIZE {
                break;
            }
        }
    }
    selected
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    #[test]
    fn removal_round_robin_bounds_clones_and_does_not_starve_later_requests() {
        let mut records = (0..(REMOVAL_BATCH_SIZE * 2 + 1))
            .map(|index| {
                serde_json::from_value::<RemovalRequestV1>(serde_json::json!({
                "schema_version": 1,
                "request_id": uuid::Uuid::from_u128(index as u128 + 1).to_string(),
                "deployment_id": uuid::Uuid::nil().to_string(), "revision": index + 1,
                "target": { "repository_id": "42", "scope": { "kind": "public" }, "aliases": [] },
                "created_at": "2026-09-01T00:00:00Z", "phase": "pending",
                "attempts_removed": 0, "artifacts_removed": 0, "failure_code": null,
            })).unwrap()
            })
            .collect::<Vec<_>>();
        records[1].phase = RemovalPhaseV1::Failed;
        records[2].phase = RemovalPhaseV1::Completed;
        let mut cursor = 0;
        let first = removal_batch(&records, &mut cursor);
        assert_eq!(first.len(), REMOVAL_BATCH_SIZE);
        let second = removal_batch(&records, &mut cursor);
        assert_eq!(second.len(), REMOVAL_BATCH_SIZE);
        assert!(
            second
                .iter()
                .any(|record| record.request_id == records.last().unwrap().request_id)
        );
        assert!(
            first
                .iter()
                .chain(&second)
                .all(|record| record.phase == RemovalPhaseV1::Pending)
        );
        assert!(removal_batch(&[], &mut cursor).is_empty());
        assert_eq!(cursor, 0);
    }
}

async fn step(state: &ApiState, record: &mut RemovalRequestV1) -> Result<()> {
    match record.phase {
        RemovalPhaseV1::Pending => cancel_tasks(state, record).await,
        RemovalPhaseV1::Catalog => {
            let _policy = read_guard(state)
                .await
                .map_err(|_| anyhow::anyhow!("privacy policy unavailable"))?;
            let removed = state
                .inventory
                .purge_repository(&record.target, REMOVAL_BATCH_SIZE)
                .await?;
            record.attempts_removed = record.attempts_removed.saturating_add(removed as u64);
            if removed == 0 {
                record.phase = RemovalPhaseV1::Artifacts;
            }
            Ok(())
        }
        RemovalPhaseV1::Artifacts => remove_artifacts(state, record).await,
        RemovalPhaseV1::Verifying => remove_failed_attempts(state, record).await,
        RemovalPhaseV1::Completed | RemovalPhaseV1::Failed => Ok(()),
    }
}

async fn cancel_tasks(state: &ApiState, record: &mut RemovalRequestV1) -> Result<()> {
    let _policy = read_guard(state)
        .await
        .map_err(|_| anyhow::anyhow!("privacy policy unavailable"))?;
    let tasks = state
        .store
        .privacy_task_page(record.task_cursor.clone().map(TaskId))
        .await?;
    if tasks.is_empty() {
        record.phase = RemovalPhaseV1::Catalog;
        return Ok(());
    }
    let mut matching = Vec::new();
    for task in &tasks {
        if !matches!(
            task.state,
            RepositoryTaskStateV1::Pending | RepositoryTaskStateV1::Leased
        ) {
            continue;
        }
        let job = state
            .store
            .job(task.job_id.clone())
            .await?
            .context("removal task job is missing")?;
        let namespace =
            cache_namespace(&job).map_err(|_| anyhow::anyhow!("invalid removal task namespace"))?;
        if record.target.matches(
            &inventory_namespace(&namespace),
            &task.repository_id,
            &task.repository_id,
        ) {
            matching.push(task.id.clone());
        }
    }
    if !matching.is_empty() {
        state
            .store
            .apply(DurableCommandV1::PrivacyCancelTasks {
                task_ids: matching,
                now: Utc::now(),
            })
            .await?;
    }
    record.task_cursor = tasks.last().map(|task| task.id.0.clone());
    Ok(())
}

async fn remove_artifacts(state: &ApiState, record: &mut RemovalRequestV1) -> Result<()> {
    if let Some(task_id) = record.pending_artifact.clone() {
        if let Some(artifact) = state.store.artifact(task_id).await? {
            delete_artifact(state, &artifact).await?;
            record.artifacts_removed = record.artifacts_removed.saturating_add(1);
        }
        record.pending_artifact = None;
    }
    let artifacts = state
        .store
        .artifact_page(record.artifact_cursor.clone().map(TaskId))
        .await?;
    if artifacts.is_empty() {
        record.phase = RemovalPhaseV1::Verifying;
        return Ok(());
    }
    for artifact in artifacts {
        if artifact_matches(state, &record.target, &artifact).await? {
            record.pending_artifact = Some(artifact.task_id.clone());
            state
                .privacy
                .as_ref()
                .context("privacy service unavailable")?
                .update(record.clone())
                .await?;
            delete_artifact(state, &artifact).await?;
            record.pending_artifact = None;
            record.artifacts_removed = record.artifacts_removed.saturating_add(1);
        }
        record.artifact_cursor = Some(artifact.task_id.0);
    }
    Ok(())
}

async fn artifact_matches(
    state: &ApiState,
    target: &SuppressionTargetV1,
    artifact: &ArtifactRecordV1,
) -> Result<bool> {
    if !target.scope.allows_cache(&artifact.metadata.key.namespace) {
        return Ok(false);
    }
    if let Some(fingerprint) = &artifact.metadata.reuse_fingerprint
        && !fingerprint.repository_id.is_empty()
        && fingerprint
            .repository_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Ok(target.repository_id == fingerprint.repository_id);
    }
    ensure!(
        artifact.metadata.content_length <= MAX_EVIDENCE_ARTIFACT_BYTES as u64,
        "artifact exceeds removal read bound"
    );
    let _policy = read_guard(state)
        .await
        .map_err(|_| anyhow::anyhow!("privacy policy unavailable"))?;
    let _retention = state.artifact_retention.read().await;
    let namespace = SecureNamespaceOwned::from_cache_namespace(&artifact.metadata.key.namespace);
    let digest = artifact.metadata.key.digest.as_str().to_owned();
    let _object = state
        .artifacts
        .lock_object(
            &namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &digest,
        )
        .await?;
    let cache = state.artifacts.clone();
    let key = state.envelope_key.clone();
    let body = tokio::task::spawn_blocking(move || {
        cache.get_bounded(
            &namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &digest,
            &key,
            MAX_EVIDENCE_ARTIFACT_BYTES as u64,
        )
    })
    .await??;
    ensure!(
        body.len() as u64 == artifact.metadata.content_length,
        "artifact length differs from metadata"
    );
    let evidence: EvidenceBundleV1 = serde_json::from_slice(&body)?;
    ensure!(
        evidence.schema_is_supported() && evidence.repositories.len() == 1,
        "invalid artifact evidence"
    );
    let repository = &evidence.repositories[0];
    Ok(target.matches(
        &inventory_namespace(&artifact.metadata.key.namespace),
        repository.repository_id.as_deref().unwrap_or(""),
        &repository.repository,
    ))
}

async fn delete_artifact(state: &ApiState, artifact: &ArtifactRecordV1) -> Result<()> {
    let _policy = read_guard(state)
        .await
        .map_err(|_| anyhow::anyhow!("privacy policy unavailable"))?;
    let _retention = state.artifact_retention.read().await;
    let namespace = SecureNamespaceOwned::from_cache_namespace(&artifact.metadata.key.namespace);
    let digest = artifact.metadata.key.digest.as_str().to_owned();
    let _object = state
        .artifacts
        .lock_object(
            &namespace.as_borrowed(),
            CACHE_CONTENT_KIND_EVIDENCE,
            &digest,
        )
        .await?;
    state
        .inventory
        .remove_artifact_projection(&artifact.task_id, &artifact.metadata.key.digest)
        .await?;
    if !state
        .store
        .artifact_referenced_except(
            artifact.metadata.key.clone(),
            Some(artifact.task_id.clone()),
        )
        .await?
    {
        let cache = state.artifacts.clone();
        tokio::task::spawn_blocking(move || {
            cache.remove(
                &namespace.as_borrowed(),
                CACHE_CONTENT_KIND_EVIDENCE,
                &digest,
            )
        })
        .await??;
    }
    state
        .store
        .apply(DurableCommandV1::PrivacyRemoveArtifacts {
            task_ids: vec![artifact.task_id.clone()],
        })
        .await?;
    Ok(())
}

async fn remove_failed_attempts(state: &ApiState, record: &mut RemovalRequestV1) -> Result<()> {
    let _policy = read_guard(state)
        .await
        .map_err(|_| anyhow::anyhow!("privacy policy unavailable"))?;
    let page = state
        .store
        .privacy_failed_page(record.failed_attempt_cursor.clone())
        .await?;
    if !page.is_empty() {
        let keys = page
            .iter()
            .filter(|attempt| {
                record.target.matches(
                    &inventory_namespace(&attempt.namespace),
                    "",
                    &attempt.repository_alias,
                )
            })
            .map(|attempt| attempt.key.clone())
            .collect::<Vec<_>>();
        if !keys.is_empty() {
            state
                .store
                .apply(DurableCommandV1::PrivacyRemoveFailedAttempts { keys })
                .await?;
        }
        record.failed_attempt_cursor = page.last().map(|attempt| attempt.key.clone());
        return Ok(());
    }
    let remaining = state
        .inventory
        .purge_repository(&record.target, REMOVAL_BATCH_SIZE)
        .await?;
    record.attempts_removed = record.attempts_removed.saturating_add(remaining as u64);
    if remaining == 0 {
        record.phase = RemovalPhaseV1::Completed;
        record.failure_code = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        inventory_evidence, reconciliation_state, seed_prior_inventory_observation,
        submit_and_fail_repository_task, test_job,
    };
    use super::*;
    use crate::{
        catalog::InMemoryInventoryStore,
        coordinator::Sha256Digest,
        privacy::{PrivacyService, RemovalScopeV1},
    };

    async fn fixture() -> (tempfile::TempDir, ApiState, Arc<PrivacyService>) {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("key");
        EnvelopeKey::generate("test-key")
            .persist_new(&key_path)
            .unwrap();
        let key = Arc::new(EnvelopeKey::load(&key_path, "test-key").unwrap());
        let store = TursoCoordinatorStore::open(
            directory.path().join("coordinator.db"),
            EnvelopeKey::load(&key_path, "test-key").unwrap(),
        )
        .await
        .unwrap();
        let inventory = Arc::new(InMemoryInventoryStore::new([91; 32]));
        seed_prior_inventory_observation(&inventory, Utc::now()).await;
        let privacy = PrivacyService::open(store.clone(), inventory.clone())
            .await
            .unwrap();
        let mut state = reconciliation_state(&directory, store, inventory, key, true);
        state.privacy = Some(privacy.clone());
        (directory, state, privacy)
    }

    async fn submit(privacy: &PrivacyService) -> RemovalRequestV1 {
        let plan = privacy
            .plan(SuppressionTargetV1 {
                repository_id: "42".to_owned(),
                scope: RemovalScopeV1::Public,
                aliases: BTreeSet::from(["example/app".to_owned()]),
            })
            .await
            .unwrap();
        privacy
            .submit(Uuid::new_v4().to_string(), plan)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn removal_cancels_only_matching_work_and_keeps_operational_history() {
        let (_directory, state, privacy) = fixture().await;
        let now = Utc::now();
        submit_and_fail_repository_task(
            &state.store,
            "failed-job",
            "failed-task",
            RepositoryScopeV1::PublicOnly,
            None,
            now,
        )
        .await;
        let job_id = JobId("mixed".to_owned());
        state
            .store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: "mixed".to_owned(),
                    spec: test_job(RepositoryScopeV1::PublicOnly, None).spec,
                    submitted_at: now,
                },
                tasks: ["example/app", "other/kept"]
                    .into_iter()
                    .enumerate()
                    .map(|(index, repository)| NewRepositoryTaskV1 {
                        task_id: TaskId(format!("mixed-{index}")),
                        job_id: job_id.clone(),
                        repository_id: repository.to_owned(),
                        created_at: now,
                        not_before: now,
                    })
                    .collect(),
                now,
            })
            .await
            .unwrap();
        let request = submit(&privacy).await;
        let guard = read_guard(&state).await.unwrap();
        assert_eq!(
            ensure_allowed(&guard, &CacheNamespaceV1::Public, "42", "renamed/app")
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
        assert!(ensure_allowed(&guard, &CacheNamespaceV1::Public, "99", "example/app").is_ok());
        drop(guard);
        run_to_completion(&state).await.unwrap();
        assert_eq!(
            privacy.status(&request.request_id).await.unwrap().phase,
            RemovalPhaseV1::Completed
        );
        assert!(
            state
                .store
                .privacy_failed_page(None)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            state
                .store
                .task(TaskId("failed-task".to_owned()))
                .await
                .unwrap()
                .unwrap()
                .state,
            RepositoryTaskStateV1::Failed
        );
        assert_eq!(
            state
                .store
                .task(TaskId("mixed-0".to_owned()))
                .await
                .unwrap()
                .unwrap()
                .state,
            RepositoryTaskStateV1::Cancelled
        );
        assert_eq!(
            state
                .store
                .task(TaskId("mixed-1".to_owned()))
                .await
                .unwrap()
                .unwrap()
                .state,
            RepositoryTaskStateV1::Pending
        );
        assert!(!state.store.events().await.unwrap().is_empty());
        run_to_completion(&state).await.unwrap();
    }

    async fn seed_artifact(
        state: &ApiState,
        id: &str,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> ArtifactRecordV1 {
        let job_id = JobId(format!("job-{id}"));
        let task_id = TaskId(id.to_owned());
        state
            .store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: id.to_owned(),
                    spec: test_job(RepositoryScopeV1::PublicOnly, None).spec,
                    submitted_at: now,
                },
                tasks: vec![NewRepositoryTaskV1 {
                    task_id: task_id.clone(),
                    job_id: job_id.clone(),
                    repository_id: "example/app".to_owned(),
                    created_at: now,
                    not_before: now,
                }],
                now,
            })
            .await
            .unwrap();
        state
            .store
            .apply(DurableCommandV1::LeaseNextTask {
                job_id: job_id.clone(),
                agent_id: "worker".to_owned(),
                lease_id: id.to_owned(),
                lease_seconds: 60,
                now,
            })
            .await
            .unwrap();
        let stored = state
            .artifacts
            .put(
                SecureCacheNamespace::Public,
                CACHE_CONTENT_KIND_EVIDENCE,
                body,
                &state.envelope_key,
            )
            .unwrap();
        let digest = Sha256Digest::parse(stored.sha256).unwrap();
        let record = ArtifactRecordV1 {
            job_id,
            task_id: task_id.clone(),
            metadata: CacheMetadataV1 {
                schema_version: 1,
                key: CacheKeyV1 {
                    namespace: CacheNamespaceV1::Public,
                    digest: digest.clone(),
                },
                content_kind: CacheContentKindV1::DerivedEvidence,
                content_length: body.len() as u64,
                github_blob_sha: None,
                protection: CacheProtectionV1::EnvelopeEncrypted {
                    algorithm: "AES-256-GCM".to_owned(),
                    wrapping_key_id: "test-key".to_owned(),
                },
                completeness: CacheCompletenessV1::Complete,
                reuse_fingerprint: None,
                created_at: now,
                last_accessed_at: now,
                retain_until: now + TimeDelta::days(1),
                reference_count: 0,
            },
            inventory_projection: InventoryProjectionStateV1::Pending,
        };
        state
            .store
            .apply(DurableCommandV1::CompleteTaskWithArtifact {
                task_id,
                agent_id: "worker".to_owned(),
                lease_id: id.to_owned(),
                result: ArtifactRefV1 {
                    digest,
                    media_type: EVIDENCE_MEDIA_TYPE_V1.to_owned(),
                    stored_bytes: body.len() as u64,
                },
                artifact: Box::new(record.clone()),
                usage: TaskUsageV1::default(),
                now,
            })
            .await
            .unwrap();
        record
    }

    #[tokio::test]
    async fn completed_http_retry_acknowledges_receipt_without_restoring_removed_content() {
        let (_directory, state, privacy) = fixture().await;
        let now = Utc::now();
        let evidence = inventory_evidence(now);
        let body = serde_json::to_vec(&evidence).unwrap();
        let artifact = seed_artifact(&state, "completed", &body, now).await;
        let certificate_sha256 = "ab".repeat(32);
        state
            .store
            .register_agent(AgentRecordV1 {
                agent_id: "worker".into(),
                certificate_sha256: certificate_sha256.clone(),
                enrolled_at: now,
                revoked_at: None,
                authorization: Default::default(),
            })
            .await
            .unwrap();
        submit(&privacy).await;
        run_to_completion(&state).await.unwrap();
        let receipt = state
            .store
            .task(artifact.task_id.clone())
            .await
            .unwrap()
            .unwrap();
        let request = CompleteTaskRequestV1 {
            lease_id: "completed".into(),
            artifact: receipt.result.unwrap(),
            evidence,
            reuse_fingerprint: None,
            usage: TaskUsageV1::default(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", HeaderValue::from_static("worker"));
        let peer = TlsPeerIdentity { certificate_sha256 };
        let events = state.store.events().await.unwrap();
        assert_eq!(
            complete_task(
                State(state.clone()),
                Path(artifact.task_id.0.clone()),
                headers.clone(),
                Extension(peer.clone()),
                Json(request.clone()),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert!(
            state
                .store
                .artifact(artifact.task_id.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .artifacts
                .get_bounded(
                    &SecureCacheNamespace::Public,
                    CACHE_CONTENT_KIND_EVIDENCE,
                    artifact.metadata.key.digest.as_str(),
                    &state.envelope_key,
                    MAX_EVIDENCE_ARTIFACT_BYTES as u64,
                )
                .is_err()
        );
        assert_eq!(state.store.events().await.unwrap(), events);
        let mut conflicting = request.clone();
        conflicting.evidence.generated_at = now + TimeDelta::seconds(1);
        let body = serde_json::to_vec(&conflicting.evidence).unwrap();
        conflicting.artifact.digest = Sha256Digest::parse(sha256_hex(&body)).unwrap();
        conflicting.artifact.stored_bytes = body.len() as u64;
        assert_eq!(
            complete_task(
                State(state.clone()),
                Path(artifact.task_id.0.clone()),
                headers.clone(),
                Extension(peer),
                Json(conflicting),
            )
            .await
            .unwrap_err()
            .code,
            "completion_conflict"
        );
        assert_eq!(
            complete_task(
                State(state.clone()),
                Path(artifact.task_id.0),
                headers,
                Extension(TlsPeerIdentity {
                    certificate_sha256: "cd".repeat(32)
                }),
                Json(request),
            )
            .await
            .unwrap_err()
            .code,
            "agent_identity_rejected"
        );
        let store = state.store.clone();
        drop(state);
        drop(privacy);
        store.shutdown_offline().await.unwrap();
    }

    #[tokio::test]
    async fn removal_preserves_shared_blobs_and_resumes_after_blob_deletion() {
        let (_directory, state, privacy) = fixture().await;
        let now = Utc::now();
        let body = serde_json::to_vec(&inventory_evidence(now)).unwrap();
        let first = seed_artifact(&state, "a", &body, now).await;
        let second = seed_artifact(&state, "b", &body, now).await;
        let mut record = submit(&privacy).await;
        assert!(
            artifact_matches(&state, &record.target, &first)
                .await
                .unwrap()
        );
        delete_artifact(&state, &first).await.unwrap();
        assert!(
            state
                .artifacts
                .get_bounded(
                    &SecureCacheNamespace::Public,
                    CACHE_CONTENT_KIND_EVIDENCE,
                    first.metadata.key.digest.as_str(),
                    &state.envelope_key,
                    MAX_EVIDENCE_ARTIFACT_BYTES as u64
                )
                .is_ok()
        );
        record.pending_artifact = Some(second.task_id.clone());
        record.phase = RemovalPhaseV1::Artifacts;
        privacy.update(record.clone()).await.unwrap();
        state
            .artifacts
            .remove(
                &SecureCacheNamespace::Public,
                CACHE_CONTENT_KIND_EVIDENCE,
                second.metadata.key.digest.as_str(),
            )
            .unwrap();
        run_to_completion(&state).await.unwrap();
        assert!(
            state
                .store
                .artifact(second.task_id.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .store
                .task(second.task_id)
                .await
                .unwrap()
                .unwrap()
                .result
                .is_some()
        );
        assert_eq!(
            privacy.status(&record.request_id).await.unwrap().phase,
            RemovalPhaseV1::Completed
        );
    }
}
