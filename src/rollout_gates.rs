//! Explicitly-invoked rollout gates for the documented coordinator scale ceiling.
//!
//! These tests are ignored because they intentionally materialize 250,000
//! coordinator tasks and 250,000 durable inventory projections. Run one test
//! at a time with `--test-threads=1`, a freshly initialized coordinator state
//! directory in `CDR_LOAD_GATE_STATE`, and a new JSONL path in
//! `CDR_LOAD_GATE_METRICS`.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, ensure};
use chrono::{DateTime, TimeDelta, TimeZone as _, Utc};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::{
    catalog::{
        CATALOG_SCHEMA_VERSION_V1, InventoryAccessV1, InventoryMatchModeV1, InventoryNamespaceV1,
        InventoryPageRequestV1, InventoryProjectionInputV1, InventoryProjectionStore as _,
        InventoryQueryV1, InventorySearchFieldV1, InventorySortV1, RepositoryAttemptInputV1,
        TursoInventoryStore,
    },
    coordinator::{
        AgentAuthorizationV1, DurableCommandV1, DurableOutcomeV1, JobId, NewRepositoryTaskV1,
        RepositoryScopeV1, RepositoryTaskStateV1, SCHEMA_VERSION_V1, ScanBoundsV1, ScanJobStateV1,
        ScanSpecV1, ScanTargetV1, SubmitJobV1, TaskId, TursoCoordinatorStore,
    },
    evidence::RepositoryVisibilityV1,
    secure_cache::EnvelopeKey,
};

const JOBS: usize = 25;
const TASKS_PER_JOB: usize = 10_000;
const TOTAL_TASKS: usize = JOBS * TASKS_PER_JOB;
const AGENTS: usize = 16;
const PAGE_SIZE: usize = 1_000;
const COORDINATOR_KEY_ID: &str = "coordinator-journal-v1";
const SENTINEL_JOB: &str = "rollout-queued-sentinel";

static GATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[tokio::test(flavor = "current_thread")]
#[ignore = "materializes the full 250,000-task and 250,000-projection rollout workload"]
async fn coordinator_and_catalog_capacity_gate() -> Result<()> {
    let _serial = GATE_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let mut metrics = MetricWriter::create("coordinator_and_catalog_capacity")?;
    let total = Instant::now();
    metrics.event("gate", "started", Duration::ZERO, json!({}))?;

    let result = run_capacity_gate(&mut metrics).await;
    match result {
        Ok(()) => {
            metrics.event(
                "gate",
                "passed",
                total.elapsed(),
                json!({
                    "jobs": JOBS,
                    "tasks_per_job": TASKS_PER_JOB,
                    "tasks": TOTAL_TASKS,
                    "catalog_projections": TOTAL_TASKS,
                    "artifact_recovery_exercised": false,
                }),
            )?;
            Ok(())
        }
        Err(error) => {
            let _ = metrics.event(
                "gate",
                "failed",
                total.elapsed(),
                json!({ "error": format!("{error:#}") }),
            );
            Err(error)
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "validates a restored full-scale rollout-gate state directory"]
async fn restored_capacity_state_gate() -> Result<()> {
    let _serial = GATE_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let mut metrics = MetricWriter::create("restored_capacity_state")?;
    let total = Instant::now();
    metrics.event("gate", "started", Duration::ZERO, json!({}))?;

    let result = run_restored_state_gate(&mut metrics).await;
    match result {
        Ok(()) => {
            metrics.event(
                "gate",
                "passed",
                total.elapsed(),
                json!({
                    "jobs": JOBS,
                    "tasks": TOTAL_TASKS,
                    "catalog_projections": TOTAL_TASKS,
                }),
            )?;
            Ok(())
        }
        Err(error) => {
            let _ = metrics.event(
                "gate",
                "failed",
                total.elapsed(),
                json!({ "error": format!("{error:#}") }),
            );
            Err(error)
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "runs an explicitly sized durable catalog rebuild diagnostic"]
async fn catalog_rebuild_diagnostic_gate() -> Result<()> {
    let _serial = GATE_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let count = catalog_diagnostic_count()?;
    let mut metrics = MetricWriter::create("catalog_rebuild_diagnostic")?;
    let total = Instant::now();
    metrics.event(
        "gate",
        "started",
        Duration::ZERO,
        json!({ "projections": count }),
    )?;

    let result = run_catalog_diagnostic(&mut metrics, count).await;
    match result {
        Ok(()) => {
            metrics.event(
                "gate",
                "passed",
                total.elapsed(),
                json!({ "projections": count }),
            )?;
            Ok(())
        }
        Err(error) => {
            let _ = metrics.event(
                "gate",
                "failed",
                total.elapsed(),
                json!({ "projections": count, "error": format!("{error:#}") }),
            );
            Err(error)
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "measures durable catalog restart, cursor paging, and exact lookup"]
async fn catalog_search_diagnostic_gate() -> Result<()> {
    let _serial = GATE_LOCK.get_or_init(|| Mutex::new(())).lock().await;
    let count = catalog_diagnostic_count()?;
    let mut metrics = MetricWriter::create("catalog_search_diagnostic")?;
    let total = Instant::now();
    metrics.event(
        "gate",
        "started",
        Duration::ZERO,
        json!({ "projections": count }),
    )?;

    let result = run_catalog_search_diagnostic(&mut metrics, count).await;
    match result {
        Ok(()) => {
            metrics.event(
                "gate",
                "passed",
                total.elapsed(),
                json!({ "projections": count }),
            )?;
            Ok(())
        }
        Err(error) => {
            let _ = metrics.event(
                "gate",
                "failed",
                total.elapsed(),
                json!({ "projections": count, "error": format!("{error:#}") }),
            );
            Err(error)
        }
    }
}

fn catalog_diagnostic_count() -> Result<usize> {
    let count = env::var("CDR_CATALOG_DIAGNOSTIC_COUNT")
        .context("CDR_CATALOG_DIAGNOSTIC_COUNT is required")?
        .parse::<usize>()
        .context("CDR_CATALOG_DIAGNOSTIC_COUNT must be an integer")?;
    ensure!(
        (1..=TOTAL_TASKS).contains(&count),
        "CDR_CATALOG_DIAGNOSTIC_COUNT must be between 1 and {TOTAL_TASKS}"
    );
    Ok(count)
}

async fn run_capacity_gate(metrics: &mut MetricWriter) -> Result<()> {
    let state = required_state_directory()?;
    let database = required_file(&state, "coordinator.db")?;
    let envelope_key = required_file(&state, "envelope.key")?;
    let cursor_key = load_cursor_key(&required_file(&state, "inventory-cursor.key")?)?;

    let phase = Instant::now();
    let store = TursoCoordinatorStore::open(
        &database,
        EnvelopeKey::load(&envelope_key, COORDINATOR_KEY_ID)?,
    )
    .await
    .context("opening fresh coordinator state")?;
    ensure!(
        store.jobs().await?.is_empty(),
        "capacity gate requires a freshly initialized coordinator with no jobs"
    );
    let inventory = TursoInventoryStore::open(&database, cursor_key).await?;
    ensure!(
        inventory.watermark().await? == 0,
        "capacity gate requires an empty inventory projection"
    );
    drop(inventory);
    metrics.event(
        "preflight",
        "passed",
        phase.elapsed(),
        json!({ "state": state }),
    )?;

    let phase = Instant::now();
    for job_index in 0..JOBS {
        let job_id = rollout_job_id(job_index);
        let tasks = (0..TASKS_PER_JOB)
            .map(|task_index| {
                let global = global_task_index(job_index, task_index);
                NewRepositoryTaskV1 {
                    task_id: rollout_task_id(global),
                    job_id: job_id.clone(),
                    repository_id: repository_name(global),
                    not_before: gate_time(),
                    created_at: gate_time(),
                }
            })
            .collect();
        let outcome = store
            .apply(DurableCommandV1::SubmitJobWithTasks {
                request: submit_request(job_id.clone(), job_index),
                tasks,
                now: gate_time(),
            })
            .await
            .with_context(|| format!("submitting rollout job {job_index}"))?;
        ensure!(
            matches!(outcome, DurableOutcomeV1::Submitted(_)),
            "rollout batch returned an unexpected outcome"
        );
    }
    verify_job_summaries(&store).await?;
    metrics.event(
        "submit_peak_state",
        "passed",
        phase.elapsed(),
        json!({ "running_jobs": JOBS, "tasks": TOTAL_TASKS }),
    )?;

    let phase = Instant::now();
    exercise_queued_sentinel(&store).await?;
    exercise_fair_global_leases(&store).await?;
    verify_coordinator_state(&store).await?;
    metrics.event(
        "queue_and_fair_dispatch",
        "passed",
        phase.elapsed(),
        json!({ "global_leases": AGENTS, "distinct_jobs": AGENTS }),
    )?;

    let phase = Instant::now();
    store.compact().await.context("compacting peak state")?;
    metrics.event("compaction", "passed", phase.elapsed(), json!({}))?;
    drop(store);

    let phase = Instant::now();
    let store = reopen_coordinator(&database, &envelope_key).await?;
    verify_coordinator_state(&store).await?;
    metrics.event(
        "coordinator_restart",
        "passed",
        phase.elapsed(),
        json!({ "tasks_verified_by_page": TOTAL_TASKS }),
    )?;

    let phase = Instant::now();
    let projections = projection_inputs();
    metrics.event(
        "catalog_input_generation",
        "passed",
        phase.elapsed(),
        json!({ "projections": projections.len() }),
    )?;

    let phase = Instant::now();
    let inventory = TursoInventoryStore::open(&database, cursor_key).await?;
    inventory
        .rebuild(projections)
        .await
        .context("rebuilding the 250,000-record inventory projection")?;
    ensure!(
        inventory.watermark().await? == TOTAL_TASKS as u64,
        "catalog watermark does not equal the exact projection count"
    );
    metrics.event(
        "catalog_rebuild",
        "passed",
        phase.elapsed(),
        json!({ "projections": TOTAL_TASKS }),
    )?;
    drop(inventory);

    let phase = Instant::now();
    let inventory = TursoInventoryStore::open(&database, cursor_key).await?;
    verify_catalog_state(&inventory).await?;
    metrics.event(
        "catalog_restart_search_and_cursor",
        "passed",
        phase.elapsed(),
        json!({ "pages": TOTAL_TASKS / PAGE_SIZE, "items": TOTAL_TASKS }),
    )?;
    drop(inventory);
    drop(store);
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}

async fn run_catalog_diagnostic(metrics: &mut MetricWriter, count: usize) -> Result<()> {
    let state = required_state_directory()?;
    let database = required_file(&state, "coordinator.db")?;
    let cursor_key = load_cursor_key(&required_file(&state, "inventory-cursor.key")?)?;

    let inventory = TursoInventoryStore::open(&database, cursor_key).await?;
    ensure!(
        inventory.watermark().await? == 0,
        "catalog diagnostic requires an empty inventory projection"
    );
    let phase = Instant::now();
    inventory.rebuild(projection_inputs_for(count)).await?;
    ensure!(
        inventory.watermark().await? == count as u64,
        "catalog diagnostic watermark does not equal the requested projection count"
    );
    metrics.event(
        "catalog_rebuild",
        "passed",
        phase.elapsed(),
        json!({ "projections": count }),
    )?;
    drop(inventory);

    run_catalog_search_diagnostic(metrics, count).await
}

async fn run_catalog_search_diagnostic(metrics: &mut MetricWriter, count: usize) -> Result<()> {
    let state = required_state_directory()?;
    let database = required_file(&state, "coordinator.db")?;
    let cursor_key = load_cursor_key(&required_file(&state, "inventory-cursor.key")?)?;

    let phase = Instant::now();
    let inventory = TursoInventoryStore::open(&database, cursor_key).await?;
    ensure!(
        inventory.watermark().await? == count as u64,
        "catalog diagnostic watermark does not equal the requested projection count"
    );
    metrics.event(
        "catalog_restart",
        "passed",
        phase.elapsed(),
        json!({ "projections": count }),
    )?;

    let phase = Instant::now();
    let page_timings = verify_catalog_pages(&inventory, count).await?;
    metrics.event(
        "catalog_cursor_pages",
        "passed",
        phase.elapsed(),
        json!({
            "projections": count,
            "pages": page_timings.pages,
            "candidate_milliseconds": page_timings.candidates.as_millis(),
            "hydration_and_projection_milliseconds": page_timings.hydration_and_projection.as_millis(),
        }),
    )?;

    let phase = Instant::now();
    verify_catalog_exact_search(&inventory, count).await?;
    metrics.event(
        "catalog_exact_search",
        "passed",
        phase.elapsed(),
        json!({ "projections": count }),
    )?;
    Ok(())
}

async fn run_restored_state_gate(metrics: &mut MetricWriter) -> Result<()> {
    let state = required_state_directory()?;
    let database = required_file(&state, "coordinator.db")?;
    let envelope_key = required_file(&state, "envelope.key")?;
    let cursor_key = load_cursor_key(&required_file(&state, "inventory-cursor.key")?)?;

    let phase = Instant::now();
    let store = TursoCoordinatorStore::open(
        &database,
        EnvelopeKey::load(&envelope_key, COORDINATOR_KEY_ID)?,
    )
    .await
    .context("opening restored coordinator state")?;
    verify_coordinator_state(&store).await?;
    metrics.event(
        "restored_coordinator",
        "passed",
        phase.elapsed(),
        json!({ "tasks_verified_by_page": TOTAL_TASKS }),
    )?;

    let phase = Instant::now();
    let inventory = TursoInventoryStore::open(&database, cursor_key).await?;
    verify_catalog_state(&inventory).await?;
    metrics.event(
        "restored_catalog",
        "passed",
        phase.elapsed(),
        json!({ "pages": TOTAL_TASKS / PAGE_SIZE, "items": TOTAL_TASKS }),
    )?;
    drop(inventory);
    drop(store);
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}

async fn exercise_queued_sentinel(store: &TursoCoordinatorStore) -> Result<()> {
    let sentinel = JobId(SENTINEL_JOB.to_owned());
    store
        .apply(DurableCommandV1::SubmitJob {
            request: submit_request(sentinel.clone(), JOBS),
        })
        .await?;
    ensure!(
        store.job(sentinel.clone()).await?.unwrap().state == ScanJobStateV1::Queued,
        "the twenty-sixth job was not queued"
    );

    let displaced = rollout_job_id(JOBS - 1);
    store
        .apply(DurableCommandV1::PauseJob {
            job_id: displaced.clone(),
            now: gate_time() + TimeDelta::minutes(1),
        })
        .await?;
    ensure!(
        store.job(sentinel.clone()).await?.unwrap().state == ScanJobStateV1::Running,
        "the queued sentinel was not promoted when capacity opened"
    );
    store
        .apply(DurableCommandV1::CancelJob {
            job_id: sentinel,
            now: gate_time() + TimeDelta::minutes(2),
        })
        .await?;
    store
        .apply(DurableCommandV1::ResumeJob {
            job_id: displaced,
            now: gate_time() + TimeDelta::minutes(3),
        })
        .await?;
    Ok(())
}

async fn exercise_fair_global_leases(store: &TursoCoordinatorStore) -> Result<()> {
    let now = gate_time() + TimeDelta::minutes(4);
    let mut leased = Vec::with_capacity(AGENTS);
    for index in 0..AGENTS {
        let outcome = store
            .apply(DurableCommandV1::LeaseNextAuthorizedTask {
                authorization: AgentAuthorizationV1::default(),
                agent_id: format!("rollout-agent-{index:02}"),
                lease_id: format!("rollout-lease-{index:02}"),
                lease_seconds: 300,
                now,
            })
            .await?;
        let DurableOutcomeV1::Task(Some(task)) = outcome else {
            return Err(anyhow!("global lease {index} returned no task"));
        };
        leased.push(task);
    }
    let leased_jobs = leased
        .iter()
        .map(|task| task.job_id.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        leased_jobs.len() == AGENTS,
        "sixteen global leases did not span sixteen distinct jobs"
    );
    for (index, task) in leased.into_iter().enumerate() {
        ensure!(
            task.job_id == rollout_job_id(index),
            "global lease order was not round-robin across the running jobs"
        );
        store
            .apply(DurableCommandV1::DeferTask {
                task_id: task.id,
                agent_id: format!("rollout-agent-{index:02}"),
                lease_id: format!("rollout-lease-{index:02}"),
                not_before: now,
                reason_code: "rollout_gate_fairness_probe".to_owned(),
                now,
            })
            .await?;
    }
    Ok(())
}

async fn verify_job_summaries(store: &TursoCoordinatorStore) -> Result<()> {
    let jobs = store.jobs().await?;
    let main = jobs
        .iter()
        .filter(|job| job.id.0.starts_with("rollout-job-"))
        .collect::<Vec<_>>();
    ensure!(
        main.len() == JOBS,
        "expected exactly twenty-five rollout jobs"
    );
    ensure!(
        main.iter().all(|job| {
            job.state == ScanJobStateV1::Running
                && job.progress.tasks_total == TASKS_PER_JOB as u64
                && job.progress.tasks_pending == TASKS_PER_JOB as u64
                && job.progress.tasks_leased == 0
                && job.progress.tasks_succeeded == 0
                && job.progress.tasks_failed == 0
        }),
        "rollout jobs did not reach the exact peak state"
    );
    Ok(())
}

async fn verify_coordinator_state(store: &TursoCoordinatorStore) -> Result<()> {
    let jobs = store.jobs().await?;
    ensure!(jobs.len() == JOBS + 1, "unexpected coordinator job count");
    ensure!(
        jobs.iter()
            .find(|job| job.id.0 == SENTINEL_JOB)
            .is_some_and(|job| job.state == ScanJobStateV1::Cancelled),
        "queued sentinel did not retain its terminal promotion-probe state"
    );

    for job_index in 0..JOBS {
        let job_id = rollout_job_id(job_index);
        let job = store
            .job(job_id.clone())
            .await?
            .with_context(|| format!("missing rollout job {job_index}"))?;
        ensure!(
            job.state == ScanJobStateV1::Running,
            "rollout job is not running"
        );
        ensure!(
            job.progress.tasks_total == TASKS_PER_JOB as u64
                && job.progress.tasks_pending == TASKS_PER_JOB as u64
                && job.progress.tasks_leased == 0
                && job.progress.tasks_succeeded == 0
                && job.progress.tasks_failed == 0,
            "rollout job progress changed across compaction or restart"
        );

        let mut after = None;
        let mut observed = 0_usize;
        let mut pages = 0_usize;
        loop {
            let page = store
                .tasks_for_job(job_id.clone(), after.clone(), PAGE_SIZE)
                .await?;
            if page.is_empty() {
                break;
            }
            ensure!(page.len() == PAGE_SIZE, "coordinator task page was short");
            for task in &page {
                let expected = global_task_index(job_index, observed);
                ensure!(
                    task.id == rollout_task_id(expected)
                        && task.repository_id == repository_name(expected)
                        && task.state == RepositoryTaskStateV1::Pending
                        && task.attempt == 0
                        && task.lease.is_none(),
                    "coordinator task page contained unexpected state at index {expected}"
                );
                observed += 1;
            }
            after = page.last().map(|task| task.repository_id.clone());
            pages += 1;
        }
        ensure!(
            observed == TASKS_PER_JOB && pages == TASKS_PER_JOB / PAGE_SIZE,
            "coordinator pagination did not cover one complete job"
        );
    }
    Ok(())
}

async fn verify_catalog_state(inventory: &TursoInventoryStore) -> Result<()> {
    ensure!(
        inventory.watermark().await? == TOTAL_TASKS as u64,
        "restored catalog watermark does not equal 250,000"
    );
    let access = InventoryAccessV1 {
        principal_id: "rollout-gate".to_owned(),
        private_credential_profiles: BTreeSet::new(),
    };
    let mut query = InventoryQueryV1::new();
    query.namespace = Some(InventoryNamespaceV1::Public);
    query.sort = InventorySortV1::RepositoryAsc;
    let mut cursor = None;
    for page_index in 0..TOTAL_TASKS / PAGE_SIZE {
        let page = inventory
            .search(
                &access,
                &query,
                &InventoryPageRequestV1 {
                    limit: Some(PAGE_SIZE),
                    cursor,
                },
            )
            .await?;
        ensure!(
            page.items.len() == PAGE_SIZE,
            "catalog cursor page was short"
        );
        for (item_index, item) in page.items.iter().enumerate() {
            let expected = page_index * PAGE_SIZE + item_index;
            ensure!(
                item.repository.full_name == repository_name(expected)
                    && item.repository.key.namespace == InventoryNamespaceV1::Public
                    && item.attempt.status == crate::catalog::InventoryAttemptStatusV1::Failed,
                "catalog page contained an unexpected result at index {expected}"
            );
        }
        cursor = page.next_cursor;
        ensure!(
            cursor.is_some() == (page_index + 1 < TOTAL_TASKS / PAGE_SIZE),
            "catalog cursor termination did not occur on page 250"
        );
    }

    verify_search(
        inventory,
        &access,
        InventoryMatchModeV1::Exact,
        &repository_name(123_456),
        1,
        1,
    )
    .await?;
    verify_search(
        inventory,
        &access,
        InventoryMatchModeV1::Prefix,
        "arthurian/fs2-tools-123",
        PAGE_SIZE,
        PAGE_SIZE,
    )
    .await?;
    verify_search(
        inventory,
        &access,
        InventoryMatchModeV1::Substring,
        "tools-123456",
        10,
        1,
    )
    .await?;

    let mut fuzzy = InventoryQueryV1::new();
    fuzzy.namespace = Some(InventoryNamespaceV1::Public);
    fuzzy.search = Some("arthurain/fs2-tools-123456".to_owned());
    fuzzy.search_field = InventorySearchFieldV1::Repository;
    fuzzy.match_mode = InventoryMatchModeV1::Fuzzy;
    let started = Instant::now();
    eprintln!("catalog Fuzzy search started: arthurain/fs2-tools-123456");
    let page = inventory
        .search(
            &access,
            &fuzzy,
            &InventoryPageRequestV1 {
                limit: Some(100),
                cursor: None,
            },
        )
        .await?;
    eprintln!(
        "catalog Fuzzy search completed in {:?}: {} results",
        started.elapsed(),
        page.items.len()
    );
    ensure!(
        page.items
            .iter()
            .any(|item| item.repository.full_name == repository_name(123_456)),
        "fuzzy search did not recover the typo target"
    );
    Ok(())
}

struct CatalogPageTimings {
    pages: usize,
    candidates: Duration,
    hydration_and_projection: Duration,
}

async fn verify_catalog_pages(
    inventory: &TursoInventoryStore,
    count: usize,
) -> Result<CatalogPageTimings> {
    let access = InventoryAccessV1 {
        principal_id: "rollout-gate".to_owned(),
        private_credential_profiles: BTreeSet::new(),
    };
    let mut query = InventoryQueryV1::new();
    query.namespace = Some(InventoryNamespaceV1::Public);
    query.sort = InventorySortV1::RepositoryAsc;
    let mut cursor = None;
    let mut observed = 0_usize;
    let mut pages = 0_usize;
    let mut candidate_time = Duration::ZERO;
    let mut hydration_and_projection_time = Duration::ZERO;
    while observed < count {
        let page_started = Instant::now();
        let (page, candidates_elapsed) = inventory
            .search_with_candidate_timing(
                &access,
                &query,
                &InventoryPageRequestV1 {
                    limit: Some(PAGE_SIZE),
                    cursor,
                },
            )
            .await?;
        let page_elapsed = page_started.elapsed();
        pages += 1;
        candidate_time += candidates_elapsed;
        hydration_and_projection_time += page_elapsed.saturating_sub(candidates_elapsed);
        eprintln!(
            "catalog page {pages}: candidates={candidates_elapsed:?}, hydration+projection={:?}",
            page_elapsed.saturating_sub(candidates_elapsed)
        );
        ensure!(!page.items.is_empty(), "catalog diagnostic page was empty");
        for item in &page.items {
            ensure!(
                item.repository.full_name == repository_name(observed)
                    && item.attempt.status == crate::catalog::InventoryAttemptStatusV1::Failed,
                "catalog diagnostic returned an unexpected item at index {observed}"
            );
            observed += 1;
        }
        cursor = page.next_cursor;
        ensure!(
            cursor.is_some() == (observed < count),
            "catalog diagnostic cursor termination changed"
        );
    }
    ensure!(observed == count, "catalog diagnostic result count changed");

    Ok(CatalogPageTimings {
        pages,
        candidates: candidate_time,
        hydration_and_projection: hydration_and_projection_time,
    })
}

async fn verify_catalog_exact_search(inventory: &TursoInventoryStore, count: usize) -> Result<()> {
    let access = InventoryAccessV1 {
        principal_id: "rollout-gate".to_owned(),
        private_credential_profiles: BTreeSet::new(),
    };
    let exact_index = count / 2;
    verify_search(
        inventory,
        &access,
        InventoryMatchModeV1::Exact,
        &repository_name(exact_index),
        1,
        1,
    )
    .await
}

async fn verify_search(
    inventory: &TursoInventoryStore,
    access: &InventoryAccessV1,
    mode: InventoryMatchModeV1,
    search: &str,
    limit: usize,
    expected: usize,
) -> Result<()> {
    let mut query = InventoryQueryV1::new();
    query.namespace = Some(InventoryNamespaceV1::Public);
    query.search = Some(search.to_owned());
    query.search_field = InventorySearchFieldV1::Repository;
    query.match_mode = mode;
    let started = Instant::now();
    eprintln!("catalog {mode:?} search started: {search}");
    let page = inventory
        .search(
            access,
            &query,
            &InventoryPageRequestV1 {
                limit: Some(limit),
                cursor: None,
            },
        )
        .await?;
    eprintln!(
        "catalog {mode:?} search completed in {:?}: {} results",
        started.elapsed(),
        page.items.len()
    );
    ensure!(page.items.len() == expected, "search result count changed");
    Ok(())
}

fn projection_inputs() -> Vec<InventoryProjectionInputV1> {
    projection_inputs_for(TOTAL_TASKS)
}

fn projection_inputs_for(count: usize) -> Vec<InventoryProjectionInputV1> {
    (0..count)
        .map(|global| {
            InventoryProjectionInputV1::FailedAttempt(RepositoryAttemptInputV1 {
                schema_version: CATALOG_SCHEMA_VERSION_V1,
                namespace: InventoryNamespaceV1::Public,
                job_id: rollout_job_id(global / TASKS_PER_JOB),
                task_id: rollout_task_id(global),
                task_attempt: 1,
                repository_id: (1_000_000_u64 + global as u64).to_string(),
                repository_full_name: repository_name(global),
                visibility: RepositoryVisibilityV1::Public,
                revision: None,
                completed_at: gate_time(),
                failure_code: "rollout_gate_synthetic_failure".to_owned(),
                failure_message: "synthetic failed attempt for rollout capacity validation"
                    .to_owned(),
            })
        })
        .collect()
}

fn submit_request(job_id: JobId, order: usize) -> SubmitJobV1 {
    SubmitJobV1 {
        idempotency_key: format!("rollout-submission-{order:02}"),
        job_id,
        spec: ScanSpecV1 {
            schema_version: SCHEMA_VERSION_V1,
            target: ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: RepositoryScopeV1::PublicOnly,
            credential_profile_id: None,
            bounds: ScanBoundsV1::default(),
            analyzer_versions: BTreeMap::from([(
                "rollout-gate".to_owned(),
                "capacity-v1".to_owned(),
            )]),
        },
        submitted_at: gate_time() + TimeDelta::seconds(order as i64),
    }
}

fn rollout_job_id(index: usize) -> JobId {
    JobId(format!("rollout-job-{index:02}"))
}

fn rollout_task_id(global: usize) -> TaskId {
    TaskId(format!("rollout-task-{global:06}"))
}

fn repository_name(global: usize) -> String {
    format!("arthurian/fs2-tools-{global:06}")
}

fn global_task_index(job: usize, task: usize) -> usize {
    job * TASKS_PER_JOB + task
}

fn gate_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0).unwrap()
}

async fn reopen_coordinator(database: &Path, key_path: &Path) -> Result<TursoCoordinatorStore> {
    let mut last_error = None;
    for _ in 0..50 {
        match TursoCoordinatorStore::open(
            database,
            EnvelopeKey::load(key_path, COORDINATOR_KEY_ID)?,
        )
        .await
        {
            Ok(store) => return Ok(store),
            Err(error) if error.to_string().contains("already owned") => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error).context("reopening compacted coordinator state"),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("coordinator owner lock did not clear")))
        .context("reopening compacted coordinator state")
}

fn required_state_directory() -> Result<PathBuf> {
    let path = env::var_os("CDR_LOAD_GATE_STATE")
        .map(PathBuf::from)
        .context("CDR_LOAD_GATE_STATE is required")?;
    ensure!(path.is_dir(), "CDR_LOAD_GATE_STATE is not a directory");
    fs::canonicalize(&path)
        .with_context(|| format!("resolving rollout state directory {}", path.display()))
}

fn required_file(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    ensure!(
        path.is_file(),
        "required rollout state file is missing: {}",
        path.display()
    );
    Ok(path)
}

fn load_cursor_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading inventory cursor key {}", path.display()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "inventory cursor key {} contains {} bytes instead of 32",
            path.display(),
            bytes.len()
        )
    })
}

struct MetricWriter {
    file: File,
    gate: &'static str,
}

impl MetricWriter {
    fn create(gate: &'static str) -> Result<Self> {
        let path = env::var_os("CDR_LOAD_GATE_METRICS")
            .map(PathBuf::from)
            .context("CDR_LOAD_GATE_METRICS is required")?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating metrics directory {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("creating new rollout metrics file {}", path.display()))?;
        Ok(Self { file, gate })
    }

    fn event(
        &mut self,
        phase: &str,
        status: &str,
        elapsed: Duration,
        details: Value,
    ) -> Result<()> {
        let event = json!({
            "schema_version": 1,
            "gate": self.gate,
            "phase": phase,
            "status": status,
            "elapsed_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            "recorded_at": Utc::now(),
            "details": details,
        });
        serde_json::to_writer(&mut self.file, &event)?;
        writeln!(self.file)?;
        self.file.flush()?;
        self.file.sync_data()?;
        println!("{event}");
        Ok(())
    }
}
