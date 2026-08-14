use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;

use crate::{
    catalog::{
        CatalogError, InventoryNamespaceV1, InventoryPageRequestV1, InventoryQueryV1,
        InventorySortV1,
    },
    coordinator::{
        ControlActionV1, ControlCommandV1, ControlResultV1, JobId, MaterializationDecisionV1,
        OccurrenceMaterializationV1, OccurrenceStateV1, RepositorySetContentV1,
        RepositorySetProvenanceV1, RepositorySetSnapshotV1, RepositorySourceRefV1,
        SCHEMA_VERSION_V1, SavedInventoryQueryRefV1, SavedQueryRefreshV1, ScanJobStateV1,
        ScheduleOccurrenceV1, ScheduleRevisionV1, ScheduleStateV1, ScheduledOccurrenceRefV1,
        SubmitJobV1,
    },
    secure_cache::sha256_hex,
    telemetry::CoordinatorMetrics,
};

use super::{ControlApiState, ControlApiStateError};

const MATERIALIZATION_PAGE_SIZE: usize = 100;
const SCHEDULER_INTERVAL_SECONDS: u64 = 30;
const SCHEDULER_COMMAND_DOMAIN: &[u8] = b"crate-dependent-repos/scheduler-command/v1\0";
const SCHEDULED_JOB_DOMAIN: &[u8] = b"crate-dependent-repos/scheduled-job/v1\0";

#[derive(Clone)]
pub struct DurableSchedulerRunner<StateT> {
    state: StateT,
    interval: Duration,
    metrics: Option<CoordinatorMetrics>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SchedulerRunReportV1 {
    pub occurrences_planned: usize,
    pub occurrences_claimed: usize,
    pub jobs_submitted: usize,
    pub occurrences_finished: usize,
    pub occurrences_deferred: usize,
}

impl<StateT: ControlApiState> DurableSchedulerRunner<StateT> {
    pub fn new(state: StateT) -> Self {
        Self {
            state,
            interval: Duration::from_secs(SCHEDULER_INTERVAL_SECONDS),
            metrics: None,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval.max(Duration::from_secs(1));
        self
    }

    pub fn with_metrics(mut self, metrics: CoordinatorMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = self.run_once(Utc::now()).await {
                        tracing::warn!(error = %error, "durable scheduler iteration failed");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    pub async fn run_once(
        &self,
        now: DateTime<Utc>,
    ) -> Result<SchedulerRunReportV1, ControlApiStateError> {
        let tick_bucket = now.timestamp().div_euclid(60).to_string();
        let tick = self
            .apply(
                runner_command_id("tick", [&tick_bucket]),
                ControlActionV1::TickSchedules,
                now,
            )
            .await?;
        let mut report = SchedulerRunReportV1::default();
        if let ControlResultV1::OccurrencesPlanned { plans } = tick.result {
            report.occurrences_planned = plans.len();
            if let Some(metrics) = &self.metrics {
                metrics
                    .schedule_occurrences_created
                    .inc_by(plans.len() as u64);
                metrics.schedule_occurrences_coalesced.inc_by(
                    plans
                        .iter()
                        .filter(|plan| plan.superseded_occurrence.is_some())
                        .count() as u64,
                );
            }
        }

        let snapshot = self.state.scheduler_snapshot().await?;
        let materializations = self.state.occurrence_materializations().await?;
        for schedule in snapshot.schedules {
            if let Some(active_id) = schedule.active_occurrence.as_ref()
                && let Some(active) = schedule
                    .occurrences
                    .iter()
                    .find(|occurrence| &occurrence.id == active_id)
            {
                self.process_active(&schedule, active, &materializations, now, &mut report)
                    .await;
                continue;
            }
            let Some(pending_id) = schedule.pending_occurrence.as_ref() else {
                continue;
            };
            let claim = self
                .apply(
                    runner_command_id("claim", [&schedule.schedule.id.0, &pending_id.0]),
                    ControlActionV1::ClaimOccurrence {
                        schedule_id: schedule.schedule.id.clone(),
                    },
                    now,
                )
                .await;
            let Ok(claim) = claim else {
                report.occurrences_deferred += 1;
                continue;
            };
            let ControlResultV1::OccurrenceClaimed {
                occurrence: Some(occurrence),
            } = claim.result
            else {
                continue;
            };
            report.occurrences_claimed += 1;
            self.process_active(&schedule, &occurrence, &materializations, now, &mut report)
                .await;
        }
        if let Some(metrics) = &self.metrics
            && let Ok(jobs) = self.state.jobs().await
        {
            metrics.queue_depth.set(
                jobs.iter()
                    .filter(|job| job.state == ScanJobStateV1::Queued)
                    .count() as i64,
            );
            metrics.running_jobs.set(
                jobs.iter()
                    .filter(|job| job.state == ScanJobStateV1::Running)
                    .count() as i64,
            );
        }
        Ok(report)
    }

    async fn process_active(
        &self,
        schedule: &ScheduleStateV1,
        occurrence: &ScheduleOccurrenceV1,
        materializations: &[OccurrenceMaterializationV1],
        now: DateTime<Utc>,
        report: &mut SchedulerRunReportV1,
    ) {
        let Some(revision) = schedule
            .revisions
            .iter()
            .find(|revision| revision.revision == occurrence.schedule_revision)
        else {
            report.occurrences_deferred += 1;
            return;
        };
        let age_limit =
            TimeDelta::seconds(i64::try_from(revision.max_run_age_seconds).unwrap_or(i64::MAX));
        if occurrence.job_id.is_none() && run_age_exceeded(occurrence.created_at, age_limit, now) {
            let finished = self
                .apply(
                    runner_command_id("expire", [&occurrence.id.0]),
                    ControlActionV1::FinishOccurrence {
                        occurrence: ScheduledOccurrenceRefV1 {
                            schedule_id: occurrence.schedule_id.clone(),
                            occurrence_id: occurrence.id.clone(),
                        },
                        terminal_state: OccurrenceStateV1::Failed,
                    },
                    now,
                )
                .await
                .is_ok();
            if finished {
                report.occurrences_finished += 1;
            } else {
                report.occurrences_deferred += 1;
            }
            return;
        }
        if let Some(job_id) = &occurrence.job_id {
            self.reconcile_job(occurrence, revision, job_id, now, report)
                .await;
            return;
        }

        let occurrence_ref = ScheduledOccurrenceRefV1 {
            schedule_id: occurrence.schedule_id.clone(),
            occurrence_id: occurrence.id.clone(),
        };
        let existing = materializations
            .iter()
            .find(|materialization| materialization.occurrence == occurrence_ref);
        let (decision, fresh_content) = match existing {
            Some(materialization) => (materialization.decision.clone(), None),
            None => match self
                .materialize(schedule, occurrence, revision, materializations, now)
                .await
            {
                Ok(parts) => parts,
                Err(_) => {
                    if let Some(metrics) = &self.metrics {
                        metrics.schedule_materialization_failures.inc();
                    }
                    report.occurrences_deferred += 1;
                    return;
                }
            },
        };
        let selection = match decision {
            MaterializationDecisionV1::Ready { selection } => selection,
            MaterializationDecisionV1::SkippedEmpty { .. } => {
                // MaterializeOccurrence atomically terminalizes these states
                // before returning the recorded decision.
                report.occurrences_finished += 1;
                return;
            }
            MaterializationDecisionV1::Blocked { .. } => {
                if let Some(metrics) = &self.metrics {
                    metrics.schedule_materialization_failures.inc();
                }
                report.occurrences_finished += 1;
                return;
            }
        };
        let content = match fresh_content {
            Some(content) => content,
            None => match self
                .state
                .repository_set(&selection.repository_set.digest)
                .await
            {
                Ok(Some(content)) => content,
                _ => {
                    report.occurrences_deferred += 1;
                    return;
                }
            },
        };
        if content.repository_set != selection.repository_set || content.repository_ids.is_empty() {
            report.occurrences_deferred += 1;
            return;
        }
        let job_id = scheduled_job_id(&occurrence.id.0);
        let outcome = self
            .state
            .submit_job_with_repositories(
                SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: format!("scheduled:{}", occurrence.id.0),
                    spec: revision.scan_spec.clone(),
                    submitted_at: now,
                },
                content.repository_ids,
                now,
            )
            .await;
        let Ok(outcome) = outcome else {
            report.occurrences_deferred += 1;
            return;
        };
        let job_id = match outcome {
            crate::coordinator::SubmitOutcome::Created(job_id)
            | crate::coordinator::SubmitOutcome::Existing(job_id) => job_id,
        };
        if self
            .apply(
                runner_command_id("attach", [&occurrence.id.0, &job_id.0]),
                ControlActionV1::AttachOccurrenceJob {
                    occurrence: occurrence_ref,
                    job_id,
                },
                now,
            )
            .await
            .is_ok()
        {
            report.jobs_submitted += 1;
        } else {
            report.occurrences_deferred += 1;
        }
    }

    async fn materialize(
        &self,
        schedule: &ScheduleStateV1,
        occurrence: &ScheduleOccurrenceV1,
        revision: &ScheduleRevisionV1,
        materializations: &[OccurrenceMaterializationV1],
        now: DateTime<Utc>,
    ) -> Result<(MaterializationDecisionV1, Option<RepositorySetContentV1>), ControlApiStateError>
    {
        let occurrence_ref = ScheduledOccurrenceRefV1 {
            schedule_id: occurrence.schedule_id.clone(),
            occurrence_id: occurrence.id.clone(),
        };
        let (refresh, last_complete, content) = match &revision.repository_source {
            RepositorySourceRefV1::Explicit { .. } => (None, None, None),
            RepositorySourceRefV1::SavedQuery { query } => {
                let last_complete = last_complete_snapshot(schedule, query, materializations);
                match self.refresh_saved_query(query, revision, now).await {
                    Ok((refresh, content)) => (Some(refresh), last_complete, content),
                    Err(error) => (
                        Some(SavedQueryRefreshV1::Failed {
                            reason_code: materialization_reason(error),
                        }),
                        last_complete,
                        None,
                    ),
                }
            }
        };
        let outcome = self
            .apply(
                runner_command_id("materialize", [&occurrence.id.0]),
                ControlActionV1::MaterializeOccurrence {
                    occurrence: occurrence_ref,
                    refresh,
                    last_complete,
                    repository_set_content: content.clone(),
                },
                now,
            )
            .await?;
        match outcome.result {
            ControlResultV1::OccurrenceMaterialized { decision } => Ok((decision, content)),
            _ => Err(ControlApiStateError::Unavailable),
        }
    }

    async fn refresh_saved_query(
        &self,
        query_ref: &SavedInventoryQueryRefV1,
        revision: &ScheduleRevisionV1,
        now: DateTime<Utc>,
    ) -> Result<(SavedQueryRefreshV1, Option<RepositorySetContentV1>), ControlApiStateError> {
        let access = self
            .state
            .scheduler_inventory_access(&revision.scan_spec)
            .await?;
        let saved = self
            .state
            .inventory()
            .saved_query(&access, &query_ref.query_id, Some(query_ref.revision))
            .await
            .map_err(catalog_error)?
            .ok_or(ControlApiStateError::NotFound)?;
        match &saved.namespace {
            InventoryNamespaceV1::Public
                if revision.scan_spec.repository_scope
                    == crate::coordinator::RepositoryScopeV1::PublicOnly => {}
            InventoryNamespaceV1::Private {
                credential_profile_id,
            } if revision.scan_spec.repository_scope
                == crate::coordinator::RepositoryScopeV1::AllVisible
                && revision.scan_spec.credential_profile_id.as_deref()
                    == Some(credential_profile_id.as_str()) => {}
            _ => return Err(ControlApiStateError::ValidationFailed),
        }

        let query = saved_query_materialization_query(saved.query, saved.namespace);
        let mut repositories = BTreeSet::new();
        let mut cursor = None;
        let mut watermark = None;
        loop {
            let page = self
                .state
                .inventory()
                .search(
                    &access,
                    &query,
                    &InventoryPageRequestV1 {
                        limit: Some(MATERIALIZATION_PAGE_SIZE),
                        cursor,
                    },
                )
                .await
                .map_err(catalog_error)?;
            if watermark.is_some_and(|expected| expected != page.index_watermark) {
                return Err(ControlApiStateError::Conflict);
            }
            watermark = Some(page.index_watermark);
            repositories.extend(
                page.items
                    .into_iter()
                    .map(|item| item.repository.full_name.to_ascii_lowercase()),
            );
            if repositories.len() as u64 > revision.scan_spec.bounds.repository_limit {
                return Ok((
                    SavedQueryRefreshV1::Incomplete {
                        reason_code: "saved_query_repository_limit_exceeded".to_owned(),
                    },
                    None,
                ));
            }
            let Some(next) = page.next_cursor else {
                break;
            };
            cursor = Some(next);
        }
        let content = RepositorySetContentV1::from_repositories(repositories.into_iter().collect())
            .map_err(|_| ControlApiStateError::ValidationFailed)?;
        let snapshot = RepositorySetSnapshotV1 {
            schema_version: SCHEMA_VERSION_V1,
            repository_set: content.repository_set.clone(),
            inventory_watermark: format!(
                "catalog-{}",
                watermark.ok_or(ControlApiStateError::Unavailable)?
            ),
            materialized_at: now,
        };
        Ok((SavedQueryRefreshV1::Complete { snapshot }, Some(content)))
    }

    async fn reconcile_job(
        &self,
        occurrence: &ScheduleOccurrenceV1,
        revision: &ScheduleRevisionV1,
        job_id: &JobId,
        now: DateTime<Utc>,
        report: &mut SchedulerRunReportV1,
    ) {
        let age_limit =
            TimeDelta::seconds(i64::try_from(revision.max_run_age_seconds).unwrap_or(i64::MAX));
        let job = match self.state.job(job_id.clone()).await {
            Ok(Some(job)) => job,
            _ => {
                report.occurrences_deferred += 1;
                return;
            }
        };
        let (terminal, expired) =
            occurrence_terminal_state(job.state, occurrence.created_at, age_limit, now);
        if expired {
            let _ = self.state.cancel_job(job_id.clone(), now).await;
        }
        let Some(terminal_state) = terminal else {
            return;
        };
        if self
            .apply(
                runner_command_id("finish", [&occurrence.id.0, &job_id.0]),
                ControlActionV1::FinishOccurrence {
                    occurrence: ScheduledOccurrenceRefV1 {
                        schedule_id: occurrence.schedule_id.clone(),
                        occurrence_id: occurrence.id.clone(),
                    },
                    terminal_state,
                },
                now,
            )
            .await
            .is_ok()
        {
            report.occurrences_finished += 1;
        } else {
            report.occurrences_deferred += 1;
        }
    }

    async fn apply(
        &self,
        command_id: String,
        action: ControlActionV1,
        issued_at: DateTime<Utc>,
    ) -> Result<crate::coordinator::ControlOutcomeV1, ControlApiStateError> {
        self.state
            .apply_control(ControlCommandV1 {
                schema_version: SCHEMA_VERSION_V1,
                command_id,
                expected_generation: None,
                issued_at,
                action,
            })
            .await
    }
}

fn saved_query_materialization_query(
    mut query: InventoryQueryV1,
    namespace: InventoryNamespaceV1,
) -> InventoryQueryV1 {
    query.namespace = Some(namespace);
    query.sort = InventorySortV1::RepositoryAsc;
    query
}

fn last_complete_snapshot(
    schedule: &ScheduleStateV1,
    query: &SavedInventoryQueryRefV1,
    materializations: &[OccurrenceMaterializationV1],
) -> Option<RepositorySetSnapshotV1> {
    materializations
        .iter()
        .filter(|materialization| materialization.occurrence.schedule_id == schedule.schedule.id)
        .filter_map(|materialization| {
            let occurrence = schedule
                .occurrences
                .iter()
                .find(|occurrence| occurrence.id == materialization.occurrence.occurrence_id)?;
            let revision = schedule
                .revisions
                .iter()
                .find(|revision| revision.revision == occurrence.schedule_revision)?;
            if !matches!(
                &revision.repository_source,
                RepositorySourceRefV1::SavedQuery { query: candidate } if candidate == query
            ) {
                return None;
            }
            let MaterializationDecisionV1::Ready { selection } = &materialization.decision else {
                return None;
            };
            if selection.provenance != RepositorySetProvenanceV1::FreshQuery {
                return None;
            }
            Some((
                materialization.observed_at,
                RepositorySetSnapshotV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    repository_set: selection.repository_set.clone(),
                    inventory_watermark: selection.inventory_watermark.clone()?,
                    materialized_at: materialization.observed_at,
                },
            ))
        })
        .max_by_key(|(observed_at, _)| *observed_at)
        .map(|(_, snapshot)| snapshot)
}

fn runner_command_id<S>(kind: &str, parts: impl IntoIterator<Item = S>) -> String
where
    S: AsRef<str>,
{
    let mut hasher = Sha256::new();
    hasher.update(SCHEDULER_COMMAND_DOMAIN);
    hash_part(&mut hasher, kind.as_bytes());
    for part in parts {
        hash_part(&mut hasher, part.as_ref().as_bytes());
    }
    format!("scheduler-{}", sha256_hex(&hasher.finalize()))
}

fn scheduled_job_id(occurrence_id: &str) -> JobId {
    let mut hasher = Sha256::new();
    hasher.update(SCHEDULED_JOB_DOMAIN);
    hash_part(&mut hasher, occurrence_id.as_bytes());
    JobId(format!("job-{}", sha256_hex(&hasher.finalize())))
}

fn hash_part(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part);
}

fn catalog_error(error: CatalogError) -> ControlApiStateError {
    match error {
        CatalogError::Unauthorized => ControlApiStateError::NotFound,
        CatalogError::UnsupportedSchemaVersion(_)
        | CatalogError::InvalidInput(_)
        | CatalogError::InvalidEvidence(_)
        | CatalogError::CursorInvalid => ControlApiStateError::ValidationFailed,
        CatalogError::CursorStale | CatalogError::RevisionConflict { .. } => {
            ControlApiStateError::Conflict
        }
        CatalogError::StoreUnavailable => ControlApiStateError::Unavailable,
    }
}

fn materialization_reason(error: ControlApiStateError) -> String {
    match error {
        ControlApiStateError::AuthenticationRejected | ControlApiStateError::NotFound => {
            "saved_query_access_unavailable"
        }
        ControlApiStateError::Conflict => "saved_query_cursor_conflict",
        ControlApiStateError::ValidationFailed => "saved_query_invalid",
        ControlApiStateError::RateLimited => "saved_query_rate_limited",
        ControlApiStateError::Unavailable => "saved_query_refresh_unavailable",
    }
    .to_owned()
}

fn occurrence_terminal_state(
    job_state: ScanJobStateV1,
    occurrence_created_at: DateTime<Utc>,
    age_limit: TimeDelta,
    now: DateTime<Utc>,
) -> (Option<OccurrenceStateV1>, bool) {
    match job_state {
        ScanJobStateV1::Completed | ScanJobStateV1::CompletedPartial => {
            (Some(OccurrenceStateV1::Completed), false)
        }
        ScanJobStateV1::Failed | ScanJobStateV1::Cancelled => {
            (Some(OccurrenceStateV1::Failed), false)
        }
        ScanJobStateV1::Queued | ScanJobStateV1::Running | ScanJobStateV1::Paused
            if run_age_exceeded(occurrence_created_at, age_limit, now) =>
        {
            (Some(OccurrenceStateV1::Failed), true)
        }
        ScanJobStateV1::Queued | ScanJobStateV1::Running | ScanJobStateV1::Paused => (None, false),
    }
}

fn run_age_exceeded(
    occurrence_created_at: DateTime<Utc>,
    age_limit: TimeDelta,
    now: DateTime<Utc>,
) -> bool {
    now.signed_duration_since(occurrence_created_at) > age_limit
}

#[cfg(test)]
mod tests {
    use crate::catalog::InventoryHistoryModeV1;

    use super::*;

    #[test]
    fn saved_query_materialization_preserves_history_semantics() {
        for history in [
            InventoryHistoryModeV1::LatestAttempt,
            InventoryHistoryModeV1::LatestEvidence,
            InventoryHistoryModeV1::LastComplete,
            InventoryHistoryModeV1::Observations,
        ] {
            let mut query = InventoryQueryV1::new();
            query.history = history;
            query.sort = InventorySortV1::ObservedAtDesc;

            let query = saved_query_materialization_query(query, InventoryNamespaceV1::Public);

            assert_eq!(query.history, history);
            assert_eq!(query.namespace, Some(InventoryNamespaceV1::Public));
            assert_eq!(query.sort, InventorySortV1::RepositoryAsc);
        }
    }

    #[test]
    fn runner_ids_are_stable_and_domain_separated() {
        assert_eq!(
            runner_command_id("claim", ["schedule", "occurrence"]),
            runner_command_id("claim", ["schedule", "occurrence"])
        );
        assert_ne!(
            runner_command_id("claim", ["schedule", "occurrence"]),
            runner_command_id("finish", ["schedule", "occurrence"])
        );
        assert_ne!(scheduled_job_id("occ-a"), scheduled_job_id("occ-b"));
    }

    #[test]
    fn run_age_is_enforced_for_nonterminal_jobs() {
        let created = DateTime::<Utc>::UNIX_EPOCH;
        assert_eq!(
            occurrence_terminal_state(
                ScanJobStateV1::Running,
                created,
                TimeDelta::hours(1),
                created + TimeDelta::minutes(59),
            ),
            (None, false)
        );
        assert_eq!(
            occurrence_terminal_state(
                ScanJobStateV1::Running,
                created,
                TimeDelta::hours(1),
                created + TimeDelta::hours(2),
            ),
            (Some(OccurrenceStateV1::Failed), true)
        );
        assert!(run_age_exceeded(
            created,
            TimeDelta::hours(1),
            created + TimeDelta::hours(2)
        ));
    }
}
