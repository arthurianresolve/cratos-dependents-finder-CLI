use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::{
    dispatch::{MAX_QUEUED_JOBS, MAX_RUNNING_JOBS},
    domain::{
        AgentAuthorizationV1, ArtifactRefV1, DomainError, JobEventKindV1, JobEventV1, JobId,
        JobProgressV1, LeaseV1, PermitId, QuotaUsageV1, RepositoryTaskStateV1, RepositoryTaskV1,
        ReservationId, SCHEMA_VERSION_V1, ScanJobStateV1, ScanJobV1, ScanSpecV1, TaskId,
    },
    provider::{
        PermitDecision, ProviderError, ProviderGate, ProviderGateSnapshotV1, ProviderKeyV1,
        ProviderOutcomeClassV1, ProviderPolicyV1, RateLimitObservationV1,
    },
};

/// Backwards-compatible name for the running-job admission limit.
pub const MAX_ACTIVE_JOBS: usize = MAX_RUNNING_JOBS;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitJobV1 {
    pub job_id: JobId,
    pub idempotency_key: String,
    pub spec: ScanSpecV1,
    pub submitted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmitOutcome {
    Created(JobId),
    Existing(JobId),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewRepositoryTaskV1 {
    pub task_id: TaskId,
    pub job_id: JobId,
    pub repository_id: String,
    pub not_before: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskFailureV1 {
    pub task_id: TaskId,
    pub agent_id: String,
    pub lease_id: String,
    pub failure: String,
    pub retry_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaResourceV1 {
    Repositories,
    ProviderRequests,
    DownloadedBytes,
    ArtifactBytes,
}

impl QuotaResourceV1 {
    fn reason_code(self) -> &'static str {
        match self {
            Self::Repositories => "quota_exhausted:repositories",
            Self::ProviderRequests => "quota_exhausted:provider_requests",
            Self::DownloadedBytes => "quota_exhausted:downloaded_bytes",
            Self::ArtifactBytes => "quota_exhausted:artifact_bytes",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotaLedgerV1 {
    pub limit: u64,
    pub reserved: u64,
    pub used: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaReservationStateV1 {
    Reserved,
    Reconciled,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotaReservationV1 {
    pub id: ReservationId,
    pub job_id: JobId,
    pub resource: QuotaResourceV1,
    pub reserved_amount: u64,
    pub actual_amount: Option<u64>,
    pub state: QuotaReservationStateV1,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Canonical coordinator state persisted by encrypted journal compaction.
/// Derived lookup indexes are deliberately rebuilt and validated on restore.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct StateSnapshotV1 {
    jobs: Vec<ScanJobV1>,
    tasks: Vec<RepositoryTaskV1>,
    quotas: Vec<(JobId, QuotaResourceV1, QuotaLedgerV1)>,
    reservations: Vec<QuotaReservationV1>,
    provider_gate: ProviderGateSnapshotV1,
    events: Vec<JobEventV1>,
    next_event_sequence: u64,
    #[serde(default)]
    global_lease_cursor: Option<JobId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationOutcome {
    Reserved,
    AlreadyReserved,
}

/// Records removed by one whole-run operational retention command.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationalRetentionSummaryV1 {
    pub jobs: usize,
    pub tasks: usize,
    pub quotas: usize,
    pub reservations: usize,
    pub events: usize,
    pub idempotency_keys: usize,
}

impl OperationalRetentionSummaryV1 {
    pub fn is_empty(self) -> bool {
        self.jobs == 0
    }
}

/// Durable state seam. Every mutation requires exclusive ownership of the adapter.
pub trait StateStore {
    fn submit_job(&mut self, request: SubmitJobV1) -> Result<SubmitOutcome, StoreError>;
    fn start_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError>;
    fn start_next_queued_job(&mut self, now: DateTime<Utc>) -> Result<Option<JobId>, StoreError>;
    fn pause_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError>;
    fn resume_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError>;
    fn cancel_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError>;
    fn finalize_job(
        &mut self,
        job_id: &JobId,
        partial_reasons: BTreeSet<String>,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    fn enqueue_task(&mut self, task: NewRepositoryTaskV1) -> Result<(), StoreError>;
    fn lease_next_task(
        &mut self,
        job_id: &JobId,
        agent_id: &str,
        lease_id: &str,
        lease_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<RepositoryTaskV1>, StoreError>;
    fn lease_next_authorized_task(
        &mut self,
        authorization: &AgentAuthorizationV1,
        agent_id: &str,
        lease_id: &str,
        lease_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<RepositoryTaskV1>, StoreError>;
    fn heartbeat_task(
        &mut self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        lease_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    fn defer_task(
        &mut self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        not_before: DateTime<Utc>,
        reason_code: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    fn complete_task(
        &mut self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        result: ArtifactRefV1,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    fn fail_task(&mut self, failure: TaskFailureV1) -> Result<(), StoreError>;
    fn reclaim_expired_leases(&mut self, now: DateTime<Utc>) -> Result<Vec<TaskId>, StoreError>;
    fn prune_events_before(&mut self, cutoff: DateTime<Utc>) -> Result<usize, StoreError>;

    fn reserve_quota(
        &mut self,
        reservation_id: ReservationId,
        job_id: &JobId,
        resource: QuotaResourceV1,
        amount: u64,
        now: DateTime<Utc>,
    ) -> Result<ReservationOutcome, StoreError>;
    fn reconcile_quota(
        &mut self,
        reservation_id: &ReservationId,
        actual_amount: u64,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    fn release_quota(
        &mut self,
        reservation_id: &ReservationId,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    fn configure_provider(
        &mut self,
        key: ProviderKeyV1,
        policy: ProviderPolicyV1,
    ) -> Result<(), StoreError>;
    fn acquire_provider_permit(
        &mut self,
        key: &ProviderKeyV1,
        permit_id: PermitId,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PermitDecision, StoreError>;
    fn finish_provider_request(
        &mut self,
        permit_id: &PermitId,
        agent_id: &str,
        outcome: ProviderOutcomeClassV1,
        observation: &RateLimitObservationV1,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    fn job(&self, job_id: &JobId) -> Option<&ScanJobV1>;
    fn jobs(&self) -> Vec<&ScanJobV1>;
    fn task(&self, task_id: &TaskId) -> Option<&RepositoryTaskV1>;
    fn quota(&self, job_id: &JobId, resource: QuotaResourceV1) -> Option<&QuotaLedgerV1>;
    fn events(&self) -> Vec<JobEventV1>;
}

/// Deterministic adapter used for state-machine tests and single-process execution.
#[derive(Clone, Debug, Default)]
pub struct InMemoryStateStore {
    jobs: BTreeMap<JobId, ScanJobV1>,
    idempotency_keys: BTreeMap<String, JobId>,
    queued_jobs: BTreeSet<(DateTime<Utc>, JobId)>,
    running_jobs: BTreeSet<JobId>,
    tasks: BTreeMap<TaskId, RepositoryTaskV1>,
    task_ids_by_job: BTreeMap<JobId, BTreeSet<TaskId>>,
    pending_tasks_by_job: BTreeMap<JobId, BTreeSet<(DateTime<Utc>, TaskId)>>,
    repository_tasks: BTreeMap<(JobId, String), TaskId>,
    active_leases: BTreeMap<String, TaskId>,
    quotas: BTreeMap<(JobId, QuotaResourceV1), QuotaLedgerV1>,
    reservations: BTreeMap<ReservationId, QuotaReservationV1>,
    provider_gate: ProviderGate,
    events_by_job: BTreeMap<(JobId, u64), JobEventV1>,
    next_event_sequence: u64,
    global_lease_cursor: Option<JobId>,
}

impl StateStore for InMemoryStateStore {
    fn submit_job(&mut self, request: SubmitJobV1) -> Result<SubmitOutcome, StoreError> {
        request.spec.validate()?;
        if request.job_id.0.is_empty() || request.idempotency_key.is_empty() {
            return Err(StoreError::InvalidIdentifier);
        }
        if let Some(existing_id) = self.idempotency_keys.get(&request.idempotency_key) {
            let existing = self
                .jobs
                .get(existing_id)
                .expect("idempotency index references a job");
            return if existing.spec == request.spec {
                Ok(SubmitOutcome::Existing(existing_id.clone()))
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        if self.jobs.contains_key(&request.job_id) {
            return Err(StoreError::JobAlreadyExists);
        }
        if self.queued_jobs.len() >= MAX_QUEUED_JOBS {
            return Err(StoreError::QueuedJobLimitExceeded);
        }
        self.ensure_event_capacity(1)?;

        let job_id = request.job_id.clone();
        let bounds = &request.spec.bounds;
        for (resource, limit) in [
            (QuotaResourceV1::Repositories, bounds.repository_limit),
            (
                QuotaResourceV1::ProviderRequests,
                bounds.provider_request_limit,
            ),
            (QuotaResourceV1::DownloadedBytes, bounds.download_byte_limit),
            (QuotaResourceV1::ArtifactBytes, bounds.artifact_byte_limit),
        ] {
            self.quotas.insert(
                (job_id.clone(), resource),
                QuotaLedgerV1 {
                    limit,
                    reserved: 0,
                    used: 0,
                },
            );
        }
        self.idempotency_keys
            .insert(request.idempotency_key.clone(), job_id.clone());
        self.jobs.insert(
            job_id.clone(),
            ScanJobV1 {
                schema_version: SCHEMA_VERSION_V1,
                id: job_id.clone(),
                idempotency_key: request.idempotency_key,
                spec: request.spec,
                state: ScanJobStateV1::Queued,
                created_at: request.submitted_at,
                updated_at: request.submitted_at,
                progress: JobProgressV1::default(),
                quota_usage: QuotaUsageV1::default(),
                partial_reasons: BTreeSet::new(),
                failure: None,
            },
        );
        self.queued_jobs
            .insert((request.submitted_at, job_id.clone()));
        self.record_event(
            &job_id,
            None,
            request.submitted_at,
            JobEventKindV1::Submitted,
            BTreeMap::new(),
        )?;
        Ok(SubmitOutcome::Created(job_id))
    }

    fn start_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError> {
        let job = self.jobs.get(job_id).ok_or(StoreError::JobNotFound)?;
        let state = job.state;
        let created_at = job.created_at;
        if state != ScanJobStateV1::Queued {
            return Err(StoreError::InvalidJobTransition);
        }
        self.ensure_running_capacity()?;
        self.ensure_event_capacity(1)?;
        let job = self.jobs.get_mut(job_id).expect("job was checked");
        job.state = ScanJobStateV1::Running;
        job.updated_at = now;
        self.queued_jobs.remove(&(created_at, job_id.clone()));
        self.running_jobs.insert(job_id.clone());
        self.record_event(job_id, None, now, JobEventKindV1::Started, BTreeMap::new())
    }

    fn start_next_queued_job(&mut self, now: DateTime<Utc>) -> Result<Option<JobId>, StoreError> {
        if self.running_jobs.len() >= MAX_RUNNING_JOBS {
            return Ok(None);
        }
        let Some((_, job_id)) = self.queued_jobs.first().cloned() else {
            return Ok(None);
        };
        self.start_job(&job_id, now)?;
        Ok(Some(job_id))
    }

    fn pause_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError> {
        let state = self.jobs.get(job_id).ok_or(StoreError::JobNotFound)?.state;
        if state != ScanJobStateV1::Running {
            return Err(StoreError::InvalidJobTransition);
        }
        self.ensure_event_capacity(1)?;
        let job = self.jobs.get_mut(job_id).expect("job was checked");
        job.state = ScanJobStateV1::Paused;
        job.updated_at = now;
        self.running_jobs.remove(job_id);
        self.record_event(job_id, None, now, JobEventKindV1::Paused, BTreeMap::new())
    }

    fn resume_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError> {
        let state = self.jobs.get(job_id).ok_or(StoreError::JobNotFound)?.state;
        if !matches!(
            state,
            ScanJobStateV1::Paused | ScanJobStateV1::Failed | ScanJobStateV1::CompletedPartial
        ) {
            return Err(StoreError::InvalidJobTransition);
        }
        self.ensure_running_capacity()?;
        self.reclaim_expired_job_leases(job_id, now)?;
        let failed_tasks = self
            .task_ids_by_job
            .get(job_id)
            .into_iter()
            .flatten()
            .filter(|task_id| self.tasks[*task_id].state == RepositoryTaskStateV1::Failed)
            .cloned()
            .collect::<Vec<_>>();
        for task_id in failed_tasks {
            self.transition_task(&task_id, RepositoryTaskStateV1::Pending, now)?;
            self.tasks
                .get_mut(&task_id)
                .expect("task was transitioned")
                .failure = None;
            self.set_pending_not_before(&task_id, now)?;
        }
        let has_nonterminal_tasks = self
            .task_ids_by_job
            .get(job_id)
            .into_iter()
            .flatten()
            .any(|task_id| !self.tasks[task_id].state.is_terminal());
        let job = self.jobs.get_mut(job_id).ok_or(StoreError::JobNotFound)?;
        if !has_nonterminal_tasks {
            return Err(StoreError::InvalidJobTransition);
        }
        job.state = ScanJobStateV1::Running;
        job.failure = None;
        job.partial_reasons
            .retain(|reason| !reason.starts_with("quota_exhausted"));
        job.updated_at = now;
        self.running_jobs.insert(job_id.clone());
        self.record_event(job_id, None, now, JobEventKindV1::Resumed, BTreeMap::new())
    }

    fn cancel_job(&mut self, job_id: &JobId, now: DateTime<Utc>) -> Result<(), StoreError> {
        let job = self.jobs.get(job_id).ok_or(StoreError::JobNotFound)?;
        if job.state.is_terminal() {
            return Err(StoreError::InvalidJobTransition);
        }
        self.ensure_event_capacity(1)?;
        let previous_state = job.state;
        let created_at = job.created_at;
        let task_ids = self
            .task_ids_by_job
            .get(job_id)
            .cloned()
            .unwrap_or_default();
        for task_id in task_ids {
            if !self.tasks[&task_id].state.is_terminal() {
                self.clear_task_lease(&task_id);
                self.transition_task(&task_id, RepositoryTaskStateV1::Cancelled, now)?;
            }
        }
        let job = self.jobs.get_mut(job_id).expect("job was just checked");
        job.state = ScanJobStateV1::Cancelled;
        job.updated_at = now;
        if previous_state == ScanJobStateV1::Queued {
            self.queued_jobs.remove(&(created_at, job_id.clone()));
        }
        self.running_jobs.remove(job_id);
        self.record_event(
            job_id,
            None,
            now,
            JobEventKindV1::Cancelled,
            BTreeMap::new(),
        )
    }

    fn finalize_job(
        &mut self,
        job_id: &JobId,
        partial_reasons: BTreeSet<String>,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let job = self.jobs.get_mut(job_id).ok_or(StoreError::JobNotFound)?;
        if !matches!(job.state, ScanJobStateV1::Running | ScanJobStateV1::Paused) {
            return Err(StoreError::InvalidJobTransition);
        }
        if job.progress.tasks_leased != 0 {
            return Err(StoreError::ActiveLeasesRemain);
        }
        job.partial_reasons.extend(partial_reasons);
        let complete = job.progress.tasks_pending == 0
            && job.progress.tasks_failed == 0
            && job.partial_reasons.is_empty();
        let (state, event) = if complete {
            (ScanJobStateV1::Completed, JobEventKindV1::Completed)
        } else {
            (
                ScanJobStateV1::CompletedPartial,
                JobEventKindV1::CompletedPartial,
            )
        };
        job.state = state;
        job.updated_at = now;
        self.running_jobs.remove(job_id);
        self.record_event(job_id, None, now, event, BTreeMap::new())
    }

    fn enqueue_task(&mut self, task: NewRepositoryTaskV1) -> Result<(), StoreError> {
        if task.task_id.0.is_empty() || task.repository_id.is_empty() {
            return Err(StoreError::InvalidIdentifier);
        }
        let job = self.jobs.get(&task.job_id).ok_or(StoreError::JobNotFound)?;
        if job.state.is_terminal() {
            return Err(StoreError::InvalidJobTransition);
        }
        if let Some(existing) = self.tasks.get(&task.task_id) {
            return if existing.job_id == task.job_id && existing.repository_id == task.repository_id
            {
                Ok(())
            } else {
                Err(StoreError::TaskIdConflict)
            };
        }
        let repository_key = (task.job_id.clone(), task.repository_id.clone());
        if self.repository_tasks.contains_key(&repository_key) {
            return Err(StoreError::RepositoryAlreadyQueued);
        }
        self.ensure_event_capacity(1)?;
        let progress = &job.progress;
        progress
            .tasks_total
            .checked_add(1)
            .and_then(|_| progress.tasks_pending.checked_add(1))
            .ok_or(StoreError::ProgressInvariantViolation)?;
        self.tasks.insert(
            task.task_id.clone(),
            RepositoryTaskV1 {
                schema_version: SCHEMA_VERSION_V1,
                id: task.task_id.clone(),
                job_id: task.job_id.clone(),
                repository_id: task.repository_id.clone(),
                state: RepositoryTaskStateV1::Pending,
                attempt: 0,
                not_before: task.not_before,
                lease: None,
                result: None,
                failure: None,
                created_at: task.created_at,
                updated_at: task.created_at,
            },
        );
        self.task_ids_by_job
            .entry(task.job_id.clone())
            .or_default()
            .insert(task.task_id.clone());
        self.pending_tasks_by_job
            .entry(task.job_id.clone())
            .or_default()
            .insert((task.not_before, task.task_id.clone()));
        self.repository_tasks
            .insert(repository_key, task.task_id.clone());
        let job = self.jobs.get_mut(&task.job_id).expect("job was checked");
        job.progress.tasks_total += 1;
        job.progress.tasks_pending += 1;
        job.updated_at = task.created_at;
        self.record_event(
            &task.job_id,
            Some(task.task_id),
            task.created_at,
            JobEventKindV1::TaskQueued,
            BTreeMap::new(),
        )
    }

    fn lease_next_task(
        &mut self,
        job_id: &JobId,
        agent_id: &str,
        lease_id: &str,
        lease_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<RepositoryTaskV1>, StoreError> {
        if agent_id.is_empty() || lease_id.is_empty() || lease_seconds == 0 {
            return Err(StoreError::InvalidLease);
        }
        let job = self.jobs.get(job_id).ok_or(StoreError::JobNotFound)?;
        if job.state != ScanJobStateV1::Running {
            return Err(StoreError::InvalidJobTransition);
        }
        if let Some(existing_task_id) = self.active_leases.get(lease_id) {
            let existing = &self.tasks[existing_task_id];
            if existing.job_id == *job_id
                && existing
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.agent_id == agent_id)
            {
                return Ok(Some(existing.clone()));
            }
            return Err(StoreError::LeaseIdConflict);
        }
        let task_id = self.ready_task_for_job(job_id, now);
        let Some(task_id) = task_id else {
            return Ok(None);
        };

        self.transition_task(&task_id, RepositoryTaskStateV1::Leased, now)?;
        let task = self.tasks.get_mut(&task_id).expect("task was selected");
        task.attempt = task
            .attempt
            .checked_add(1)
            .ok_or(StoreError::AttemptOverflow)?;
        task.lease = Some(LeaseV1 {
            lease_id: lease_id.to_owned(),
            agent_id: agent_id.to_owned(),
            acquired_at: now,
            expires_at: checked_add_seconds(now, lease_seconds),
        });
        task.failure = None;
        self.active_leases
            .insert(lease_id.to_owned(), task_id.clone());
        let leased = task.clone();
        self.record_event(
            job_id,
            Some(task_id),
            now,
            JobEventKindV1::TaskLeased,
            BTreeMap::from([("agent_id".to_owned(), agent_id.to_owned())]),
        )?;
        Ok(Some(leased))
    }

    fn lease_next_authorized_task(
        &mut self,
        authorization: &AgentAuthorizationV1,
        agent_id: &str,
        lease_id: &str,
        lease_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<RepositoryTaskV1>, StoreError> {
        if agent_id.is_empty() || lease_id.is_empty() || lease_seconds == 0 {
            return Err(StoreError::InvalidLease);
        }
        authorization.validate()?;

        if let Some(existing_task_id) = self.active_leases.get(lease_id) {
            let existing = &self.tasks[existing_task_id];
            let job = self
                .jobs
                .get(&existing.job_id)
                .expect("leased task references a job");
            if existing
                .lease
                .as_ref()
                .is_some_and(|lease| lease.agent_id == agent_id)
            {
                return Ok(authorization.allows(&job.spec).then(|| existing.clone()));
            }
            return Err(StoreError::LeaseIdConflict);
        }

        let eligible_jobs = self
            .running_jobs
            .iter()
            .filter(|job_id| {
                let job = &self.jobs[*job_id];
                authorization.allows(&job.spec) && self.ready_task_for_job(job_id, now).is_some()
            })
            .cloned()
            .collect::<Vec<_>>();
        let Some(job_id) = next_after_cursor(&eligible_jobs, self.global_lease_cursor.as_ref())
        else {
            return Ok(None);
        };

        let leased = self.lease_next_task(&job_id, agent_id, lease_id, lease_seconds, now)?;
        if leased.is_some() {
            self.global_lease_cursor = Some(job_id);
        }
        Ok(leased)
    }

    fn heartbeat_task(
        &mut self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        lease_seconds: u64,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if lease_seconds == 0 {
            return Err(StoreError::InvalidLease);
        }
        self.validate_active_lease(task_id, agent_id, lease_id, now)?;
        let task = self.tasks.get_mut(task_id).expect("lease was validated");
        task.lease.as_mut().expect("lease was validated").expires_at =
            checked_add_seconds(now, lease_seconds);
        task.updated_at = now;
        let job_id = task.job_id.clone();
        self.record_event(
            &job_id,
            Some(task_id.clone()),
            now,
            JobEventKindV1::TaskHeartbeat,
            BTreeMap::new(),
        )
    }

    fn defer_task(
        &mut self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        not_before: DateTime<Utc>,
        reason_code: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if !valid_reason_code(reason_code) {
            return Err(StoreError::InvalidReasonCode);
        }
        self.validate_active_lease(task_id, agent_id, lease_id, now)?;
        self.ensure_event_capacity(1)?;
        let task = self.tasks.get(task_id).expect("lease was validated");
        if task.attempt == 0 {
            return Err(StoreError::ProgressInvariantViolation);
        }
        let job_id = task.job_id.clone();
        self.clear_task_lease(task_id);
        self.transition_task(task_id, RepositoryTaskStateV1::Pending, now)?;
        let task = self.tasks.get_mut(task_id).expect("task was transitioned");
        task.attempt -= 1;
        task.failure = None;
        self.set_pending_not_before(task_id, not_before.max(now))?;
        self.record_event(
            &job_id,
            Some(task_id.clone()),
            now,
            JobEventKindV1::TaskDeferred,
            BTreeMap::from([("reason_code".to_owned(), reason_code.to_owned())]),
        )
    }

    fn complete_task(
        &mut self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        result: ArtifactRefV1,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if let Some(task) = self.tasks.get(task_id)
            && task.state == RepositoryTaskStateV1::Succeeded
        {
            return if task.result.as_ref() == Some(&result) {
                Ok(())
            } else {
                Err(StoreError::CompletionConflict)
            };
        }
        self.validate_active_lease(task_id, agent_id, lease_id, now)?;
        let job_id = self.tasks[task_id].job_id.clone();
        self.clear_task_lease(task_id);
        self.transition_task(task_id, RepositoryTaskStateV1::Succeeded, now)?;
        self.tasks
            .get_mut(task_id)
            .expect("task was transitioned")
            .result = Some(result);
        self.record_event(
            &job_id,
            Some(task_id.clone()),
            now,
            JobEventKindV1::TaskSucceeded,
            BTreeMap::new(),
        )
    }

    fn fail_task(&mut self, failure: TaskFailureV1) -> Result<(), StoreError> {
        let target = if failure.retry_at.is_some() {
            RepositoryTaskStateV1::Pending
        } else {
            RepositoryTaskStateV1::Failed
        };
        if self.validate_failure(&failure)? {
            return Ok(());
        }
        let job_id = self.tasks[&failure.task_id].job_id.clone();
        self.clear_task_lease(&failure.task_id);
        self.transition_task(&failure.task_id, target, failure.observed_at)?;
        self.tasks
            .get_mut(&failure.task_id)
            .expect("task was transitioned")
            .failure = Some(failure.failure);
        if let Some(retry_at) = failure.retry_at {
            let not_before = retry_at.max(failure.observed_at);
            self.set_pending_not_before(&failure.task_id, not_before)?;
        }
        self.record_event(
            &job_id,
            Some(failure.task_id),
            failure.observed_at,
            JobEventKindV1::TaskFailed,
            BTreeMap::from([(
                "retryable".to_owned(),
                (target == RepositoryTaskStateV1::Pending).to_string(),
            )]),
        )
    }

    fn reclaim_expired_leases(&mut self, now: DateTime<Utc>) -> Result<Vec<TaskId>, StoreError> {
        let job_ids = self.jobs.keys().cloned().collect::<Vec<_>>();
        let mut reclaimed = Vec::new();
        for job_id in job_ids {
            reclaimed.extend(self.reclaim_expired_job_leases(&job_id, now)?);
        }
        Ok(reclaimed)
    }

    fn prune_events_before(&mut self, cutoff: DateTime<Utc>) -> Result<usize, StoreError> {
        let before = self.events_by_job.len();
        self.events_by_job.retain(|(job_id, _), event| {
            event.occurred_at >= cutoff
                || self
                    .jobs
                    .get(job_id)
                    .is_none_or(|job| !job.state.is_terminal())
        });
        Ok(before - self.events_by_job.len())
    }

    fn reserve_quota(
        &mut self,
        reservation_id: ReservationId,
        job_id: &JobId,
        resource: QuotaResourceV1,
        amount: u64,
        now: DateTime<Utc>,
    ) -> Result<ReservationOutcome, StoreError> {
        if amount == 0 || reservation_id.0.is_empty() {
            return Err(StoreError::InvalidReservation);
        }
        if let Some(existing) = self.reservations.get(&reservation_id) {
            return if existing.job_id == *job_id
                && existing.resource == resource
                && existing.reserved_amount == amount
                && (existing.state == QuotaReservationStateV1::Reserved
                    || (existing.state == QuotaReservationStateV1::Reconciled
                        && existing.actual_amount == Some(amount)))
            {
                Ok(ReservationOutcome::AlreadyReserved)
            } else {
                Err(StoreError::ReservationConflict)
            };
        }
        let ledger = self
            .quotas
            .get(&(job_id.clone(), resource))
            .ok_or(StoreError::JobNotFound)?;
        let committed = ledger
            .used
            .checked_add(ledger.reserved)
            .and_then(|value| value.checked_add(amount))
            .ok_or(StoreError::QuotaExceeded(resource))?;
        if committed > ledger.limit {
            {
                let job = self.jobs.get_mut(job_id).ok_or(StoreError::JobNotFound)?;
                job.partial_reasons
                    .insert(resource.reason_code().to_owned());
                if job.state == ScanJobStateV1::Running {
                    job.state = ScanJobStateV1::Paused;
                }
                job.updated_at = now;
            }
            self.running_jobs.remove(job_id);
            self.record_event(
                job_id,
                None,
                now,
                JobEventKindV1::Paused,
                BTreeMap::from([("reason".to_owned(), resource.reason_code().to_owned())]),
            )?;
            return Err(StoreError::QuotaExceeded(resource));
        }
        self.quotas
            .get_mut(&(job_id.clone(), resource))
            .expect("quota ledger was checked")
            .reserved += amount;
        self.reservations.insert(
            reservation_id.clone(),
            QuotaReservationV1 {
                id: reservation_id,
                job_id: job_id.clone(),
                resource,
                reserved_amount: amount,
                actual_amount: None,
                state: QuotaReservationStateV1::Reserved,
                created_at: now,
                updated_at: now,
            },
        );
        self.record_event(
            job_id,
            None,
            now,
            JobEventKindV1::QuotaReserved,
            quota_attributes(resource, amount),
        )?;
        Ok(ReservationOutcome::Reserved)
    }

    fn reconcile_quota(
        &mut self,
        reservation_id: &ReservationId,
        actual_amount: u64,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let reservation = self
            .reservations
            .get(reservation_id)
            .ok_or(StoreError::ReservationNotFound)?;
        if reservation.state == QuotaReservationStateV1::Reconciled {
            return if reservation.actual_amount == Some(actual_amount) {
                Ok(())
            } else {
                Err(StoreError::ReservationConflict)
            };
        }
        if reservation.state != QuotaReservationStateV1::Reserved
            || actual_amount > reservation.reserved_amount
        {
            return Err(StoreError::InvalidReconciliation);
        }
        let job_id = reservation.job_id.clone();
        let resource = reservation.resource;
        let reserved_amount = reservation.reserved_amount;
        let ledger = self
            .quotas
            .get_mut(&(job_id.clone(), resource))
            .expect("reservation references a quota ledger");
        ledger.reserved -= reserved_amount;
        ledger.used = ledger
            .used
            .checked_add(actual_amount)
            .ok_or(StoreError::QuotaExceeded(resource))?;
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .expect("reservation was checked");
        reservation.actual_amount = Some(actual_amount);
        reservation.state = QuotaReservationStateV1::Reconciled;
        reservation.updated_at = now;
        apply_quota_usage(
            &mut self.jobs.get_mut(&job_id).expect("job exists").quota_usage,
            resource,
            actual_amount,
        )?;
        self.record_event(
            &job_id,
            None,
            now,
            JobEventKindV1::QuotaReconciled,
            quota_attributes(resource, actual_amount),
        )
    }

    fn release_quota(
        &mut self,
        reservation_id: &ReservationId,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let reservation = self
            .reservations
            .get(reservation_id)
            .ok_or(StoreError::ReservationNotFound)?;
        if reservation.state == QuotaReservationStateV1::Released {
            return Ok(());
        }
        if reservation.state != QuotaReservationStateV1::Reserved {
            return Err(StoreError::InvalidReconciliation);
        }
        let job_id = reservation.job_id.clone();
        let resource = reservation.resource;
        let amount = reservation.reserved_amount;
        self.quotas
            .get_mut(&(job_id.clone(), resource))
            .expect("reservation references a quota ledger")
            .reserved -= amount;
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .expect("reservation was checked");
        reservation.state = QuotaReservationStateV1::Released;
        reservation.updated_at = now;
        self.record_event(
            &job_id,
            None,
            now,
            JobEventKindV1::QuotaReleased,
            quota_attributes(resource, amount),
        )
    }

    fn configure_provider(
        &mut self,
        key: ProviderKeyV1,
        policy: ProviderPolicyV1,
    ) -> Result<(), StoreError> {
        self.provider_gate.configure(key, policy)?;
        Ok(())
    }

    fn acquire_provider_permit(
        &mut self,
        key: &ProviderKeyV1,
        permit_id: PermitId,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PermitDecision, StoreError> {
        Ok(self.provider_gate.acquire(key, permit_id, agent_id, now)?)
    }

    fn finish_provider_request(
        &mut self,
        permit_id: &PermitId,
        agent_id: &str,
        outcome: ProviderOutcomeClassV1,
        observation: &RateLimitObservationV1,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.provider_gate
            .finish(permit_id, agent_id, outcome, observation, now)?;
        Ok(())
    }

    fn job(&self, job_id: &JobId) -> Option<&ScanJobV1> {
        self.jobs.get(job_id)
    }

    fn jobs(&self) -> Vec<&ScanJobV1> {
        self.jobs.values().collect()
    }

    fn task(&self, task_id: &TaskId) -> Option<&RepositoryTaskV1> {
        self.tasks.get(task_id)
    }

    fn quota(&self, job_id: &JobId, resource: QuotaResourceV1) -> Option<&QuotaLedgerV1> {
        self.quotas.get(&(job_id.clone(), resource))
    }

    fn events(&self) -> Vec<JobEventV1> {
        let mut events = self.events_by_job.values().cloned().collect::<Vec<_>>();
        events.sort_unstable_by_key(|event| event.sequence);
        events
    }
}

impl InMemoryStateStore {
    /// Submit one complete repository batch as a single state transition.
    ///
    /// Every fallible condition is checked before the first canonical write.
    /// The job starts immediately when admission capacity is available and
    /// otherwise remains queued for the durable dispatcher.
    pub(super) fn submit_job_with_tasks_atomic(
        &mut self,
        request: &SubmitJobV1,
        tasks: &[NewRepositoryTaskV1],
        now: DateTime<Utc>,
    ) -> Result<SubmitOutcome, StoreError> {
        request.spec.validate()?;
        if request.job_id.0.is_empty() || request.idempotency_key.is_empty() || tasks.is_empty() {
            return Err(StoreError::InvalidBatch);
        }
        let task_count = u64::try_from(tasks.len()).map_err(|_| StoreError::InvalidBatch)?;
        if task_count > request.spec.bounds.repository_limit {
            return Err(StoreError::InvalidBatch);
        }

        let mut task_ids = BTreeSet::new();
        let mut repositories = BTreeSet::new();
        for task in tasks {
            if task.job_id != request.job_id
                || task.task_id.0.trim().is_empty()
                || task.repository_id.trim().is_empty()
                || !task_ids.insert(task.task_id.clone())
                || !repositories.insert(task.repository_id.clone())
            {
                return Err(StoreError::InvalidBatch);
            }
        }

        if let Some(existing_id) = self.idempotency_keys.get(&request.idempotency_key) {
            let existing = self
                .jobs
                .get(existing_id)
                .ok_or(StoreError::ProgressInvariantViolation)?;
            if existing.spec != request.spec
                || self.repository_ids_for_job(existing_id) != repositories
            {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(SubmitOutcome::Existing(existing_id.clone()));
        }
        if self.jobs.contains_key(&request.job_id) {
            return Err(StoreError::JobAlreadyExists);
        }
        if self.queued_jobs.len() >= MAX_QUEUED_JOBS {
            return Err(StoreError::QueuedJobLimitExceeded);
        }
        if task_ids
            .iter()
            .any(|task_id| self.tasks.contains_key(task_id))
        {
            return Err(StoreError::TaskIdConflict);
        }
        if repositories.iter().any(|repository| {
            self.repository_tasks
                .contains_key(&(request.job_id.clone(), repository.clone()))
        }) {
            return Err(StoreError::RepositoryAlreadyQueued);
        }
        let reservation_id = ReservationId(format!("repositories:{}", request.job_id.0));
        if self.reservations.contains_key(&reservation_id) {
            return Err(StoreError::ReservationConflict);
        }
        // A newly submitted job may consume a free execution slot only when
        // there is no older queued work. Slot-release paths promote from the
        // ordered queue, so bypassing it here would violate FIFO admission.
        let will_start = self.running_jobs.len() < MAX_RUNNING_JOBS && self.queued_jobs.is_empty();
        let additional_events = task_count
            .checked_add(3)
            .and_then(|events| events.checked_add(if will_start { 1 } else { 0 }))
            .ok_or(StoreError::EventSequenceOverflow)?;
        self.ensure_event_capacity(additional_events)?;

        let SubmitOutcome::Created(job_id) = self.submit_job(request.clone())? else {
            unreachable!("idempotency was prevalidated")
        };
        self.reserve_quota(
            reservation_id.clone(),
            &job_id,
            QuotaResourceV1::Repositories,
            task_count,
            now,
        )?;
        self.reconcile_quota(&reservation_id, task_count, now)?;
        for task in tasks {
            self.enqueue_task(task.clone())?;
        }
        if will_start {
            self.start_job(&job_id, now)?;
        }
        Ok(SubmitOutcome::Created(job_id))
    }

    pub(crate) fn snapshot(&self) -> StateSnapshotV1 {
        StateSnapshotV1 {
            jobs: self.jobs.values().cloned().collect(),
            tasks: self.tasks.values().cloned().collect(),
            quotas: self
                .quotas
                .iter()
                .map(|((job_id, resource), ledger)| (job_id.clone(), *resource, ledger.clone()))
                .collect(),
            reservations: self.reservations.values().cloned().collect(),
            provider_gate: self.provider_gate.snapshot(),
            events: self.events(),
            next_event_sequence: self.next_event_sequence,
            global_lease_cursor: self.global_lease_cursor.clone(),
        }
    }

    pub(crate) fn from_snapshot(snapshot: StateSnapshotV1) -> Result<Self, StoreError> {
        let mut store = Self {
            provider_gate: ProviderGate::from_snapshot(snapshot.provider_gate)?,
            next_event_sequence: snapshot.next_event_sequence,
            global_lease_cursor: snapshot.global_lease_cursor,
            ..Self::default()
        };

        for job in snapshot.jobs {
            job.spec.validate()?;
            if job.id.0.is_empty()
                || job.idempotency_key.is_empty()
                || store.jobs.contains_key(&job.id)
                || store
                    .idempotency_keys
                    .insert(job.idempotency_key.clone(), job.id.clone())
                    .is_some()
            {
                return Err(StoreError::InvalidSnapshot);
            }
            match job.state {
                ScanJobStateV1::Queued => {
                    store.queued_jobs.insert((job.created_at, job.id.clone()));
                }
                ScanJobStateV1::Running => {
                    store.running_jobs.insert(job.id.clone());
                }
                _ => {}
            }
            store.jobs.insert(job.id.clone(), job);
        }

        for task in snapshot.tasks {
            if task.id.0.is_empty()
                || task.repository_id.is_empty()
                || !store.jobs.contains_key(&task.job_id)
                || store.tasks.contains_key(&task.id)
                || store
                    .repository_tasks
                    .insert(
                        (task.job_id.clone(), task.repository_id.clone()),
                        task.id.clone(),
                    )
                    .is_some()
            {
                return Err(StoreError::InvalidSnapshot);
            }
            match (&task.state, &task.lease) {
                (RepositoryTaskStateV1::Leased, Some(lease)) => {
                    if store
                        .active_leases
                        .insert(lease.lease_id.clone(), task.id.clone())
                        .is_some()
                    {
                        return Err(StoreError::InvalidSnapshot);
                    }
                }
                (RepositoryTaskStateV1::Leased, None) | (_, Some(_)) => {
                    return Err(StoreError::InvalidSnapshot);
                }
                _ => {}
            }
            store
                .task_ids_by_job
                .entry(task.job_id.clone())
                .or_default()
                .insert(task.id.clone());
            if task.state == RepositoryTaskStateV1::Pending {
                store
                    .pending_tasks_by_job
                    .entry(task.job_id.clone())
                    .or_default()
                    .insert((task.not_before, task.id.clone()));
            }
            store.tasks.insert(task.id.clone(), task);
        }

        for (job_id, resource, ledger) in snapshot.quotas {
            if !store.jobs.contains_key(&job_id)
                || ledger.reserved.saturating_add(ledger.used) > ledger.limit
                || store.quotas.insert((job_id, resource), ledger).is_some()
            {
                return Err(StoreError::InvalidSnapshot);
            }
        }
        for reservation in snapshot.reservations {
            if !store.jobs.contains_key(&reservation.job_id)
                || !store
                    .quotas
                    .contains_key(&(reservation.job_id.clone(), reservation.resource))
                || store
                    .reservations
                    .insert(reservation.id.clone(), reservation)
                    .is_some()
            {
                return Err(StoreError::InvalidSnapshot);
            }
        }

        let mut previous_sequence = None;
        for event in snapshot.events {
            if event.schema_version != SCHEMA_VERSION_V1
                || !store.jobs.contains_key(&event.job_id)
                || previous_sequence.is_some_and(|previous| previous >= event.sequence)
                || event.sequence >= store.next_event_sequence
                || store
                    .events_by_job
                    .insert((event.job_id.clone(), event.sequence), event.clone())
                    .is_some()
            {
                return Err(StoreError::InvalidSnapshot);
            }
            previous_sequence = Some(event.sequence);
        }
        if store
            .global_lease_cursor
            .as_ref()
            .is_some_and(|job_id| !store.jobs.contains_key(job_id))
        {
            return Err(StoreError::InvalidSnapshot);
        }
        if store.queued_jobs.len() > MAX_QUEUED_JOBS || store.running_jobs.len() > MAX_RUNNING_JOBS
        {
            return Err(StoreError::InvalidSnapshot);
        }
        Ok(store)
    }

    pub(super) fn tasks_for_job_page(
        &self,
        job_id: &JobId,
        after_repository: Option<&str>,
        limit: usize,
    ) -> Vec<RepositoryTaskV1> {
        let after = after_repository.unwrap_or_default().to_owned();
        self.repository_tasks
            .range((
                std::ops::Bound::Excluded((job_id.clone(), after)),
                std::ops::Bound::Unbounded,
            ))
            .take_while(|((candidate_job, _), _)| candidate_job == job_id)
            .filter_map(|(_, task_id)| self.tasks.get(task_id).cloned())
            .take(limit)
            .collect()
    }

    pub(super) fn events_for_job_page(
        &self,
        job_id: &JobId,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> Vec<JobEventV1> {
        let lower = after_sequence
            .map_or(std::ops::Bound::Included((job_id.clone(), 0)), |sequence| {
                std::ops::Bound::Excluded((job_id.clone(), sequence))
            });
        self.events_by_job
            .range((lower, std::ops::Bound::Unbounded))
            .take_while(|((candidate_job, _), _)| candidate_job == job_id)
            .take(limit)
            .map(|(_, event)| event.clone())
            .collect()
    }

    pub(super) fn repository_ids_for_job(&self, job_id: &JobId) -> BTreeSet<String> {
        self.task_ids_by_job
            .get(job_id)
            .into_iter()
            .flatten()
            .filter_map(|task_id| self.tasks.get(task_id))
            .map(|task| task.repository_id.clone())
            .collect()
    }

    /// Remove complete terminal runs older than `cutoff`. Jobs with retained
    /// artifact metadata are protected so evidence never outlives the state
    /// needed to authorize and interpret it.
    pub(crate) fn prune_terminal_runs_before(
        &mut self,
        cutoff: DateTime<Utc>,
        protected_jobs: &BTreeSet<JobId>,
    ) -> OperationalRetentionSummaryV1 {
        let job_ids = self
            .jobs
            .values()
            .filter(|job| {
                job.state.is_terminal()
                    && job.updated_at < cutoff
                    && !protected_jobs.contains(&job.id)
            })
            .map(|job| job.id.clone())
            .collect::<BTreeSet<_>>();
        if job_ids.is_empty() {
            return OperationalRetentionSummaryV1::default();
        }

        let before_tasks = self.tasks.len();
        let before_quotas = self.quotas.len();
        let before_reservations = self.reservations.len();
        let before_events = self.events_by_job.len();
        let before_idempotency = self.idempotency_keys.len();

        for job_id in &job_ids {
            if let Some(task_ids) = self.task_ids_by_job.remove(job_id) {
                for task_id in task_ids {
                    if let Some(task) = self.tasks.remove(&task_id) {
                        self.repository_tasks
                            .remove(&(job_id.clone(), task.repository_id));
                        if let Some(lease) = task.lease {
                            self.active_leases.remove(&lease.lease_id);
                        }
                    }
                }
            }
            self.pending_tasks_by_job.remove(job_id);
            self.queued_jobs.retain(|(_, queued)| queued != job_id);
            self.running_jobs.remove(job_id);
            self.jobs.remove(job_id);
        }
        self.idempotency_keys
            .retain(|_, job_id| !job_ids.contains(job_id));
        self.quotas
            .retain(|(job_id, _), _| !job_ids.contains(job_id));
        self.reservations
            .retain(|_, reservation| !job_ids.contains(&reservation.job_id));
        self.events_by_job
            .retain(|(job_id, _), _| !job_ids.contains(job_id));
        if self
            .global_lease_cursor
            .as_ref()
            .is_some_and(|job_id| job_ids.contains(job_id))
        {
            self.global_lease_cursor = None;
        }

        OperationalRetentionSummaryV1 {
            jobs: job_ids.len(),
            tasks: before_tasks - self.tasks.len(),
            quotas: before_quotas - self.quotas.len(),
            reservations: before_reservations - self.reservations.len(),
            events: before_events - self.events_by_job.len(),
            idempotency_keys: before_idempotency - self.idempotency_keys.len(),
        }
    }

    pub(super) fn validate_completion(
        &self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        result: &ArtifactRefV1,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if let Some(task) = self.tasks.get(task_id)
            && task.state == RepositoryTaskStateV1::Succeeded
        {
            return if task.result.as_ref() == Some(result) {
                Ok(())
            } else {
                Err(StoreError::CompletionConflict)
            };
        }
        self.validate_active_lease(task_id, agent_id, lease_id, now)
    }

    /// Returns `true` when this exact failure transition was already applied.
    pub(super) fn validate_failure(&self, failure: &TaskFailureV1) -> Result<bool, StoreError> {
        let target = if failure.retry_at.is_some() {
            RepositoryTaskStateV1::Pending
        } else {
            RepositoryTaskStateV1::Failed
        };
        if let Some(task) = self.tasks.get(&failure.task_id)
            && task.state == target
            && task.lease.is_none()
            && task.failure.as_deref() == Some(failure.failure.as_str())
            && failure
                .retry_at
                .is_none_or(|retry_at| task.not_before == retry_at.max(failure.observed_at))
        {
            return Ok(true);
        }
        self.validate_active_lease(
            &failure.task_id,
            &failure.agent_id,
            &failure.lease_id,
            failure.observed_at,
        )?;
        Ok(false)
    }
}

impl InMemoryStateStore {
    fn ensure_running_capacity(&self) -> Result<(), StoreError> {
        if self.running_jobs.len() >= MAX_RUNNING_JOBS {
            return Err(StoreError::ActiveJobLimitExceeded);
        }
        Ok(())
    }

    fn ready_task_for_job(&self, job_id: &JobId, now: DateTime<Utc>) -> Option<TaskId> {
        self.pending_tasks_by_job
            .get(job_id)
            .and_then(BTreeSet::first)
            .filter(|(not_before, _)| *not_before <= now)
            .map(|(_, task_id)| task_id.clone())
    }

    fn ensure_event_capacity(&self, additional: u64) -> Result<(), StoreError> {
        self.next_event_sequence
            .checked_add(additional)
            .ok_or(StoreError::EventSequenceOverflow)
            .map(drop)
    }

    fn set_pending_not_before(
        &mut self,
        task_id: &TaskId,
        not_before: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let task = self.tasks.get(task_id).ok_or(StoreError::TaskNotFound)?;
        if task.state != RepositoryTaskStateV1::Pending {
            return Err(StoreError::InvalidJobTransition);
        }
        let job_id = task.job_id.clone();
        let previous = task.not_before;
        if previous == not_before {
            return Ok(());
        }
        let pending = self
            .pending_tasks_by_job
            .get_mut(&job_id)
            .ok_or(StoreError::ProgressInvariantViolation)?;
        if !pending.remove(&(previous, task_id.clone())) {
            return Err(StoreError::ProgressInvariantViolation);
        }
        pending.insert((not_before, task_id.clone()));
        self.tasks
            .get_mut(task_id)
            .expect("task was checked")
            .not_before = not_before;
        Ok(())
    }

    fn validate_active_lease(
        &self,
        task_id: &TaskId,
        agent_id: &str,
        lease_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let task = self.tasks.get(task_id).ok_or(StoreError::TaskNotFound)?;
        let lease = task.lease.as_ref().ok_or(StoreError::LeaseNotFound)?;
        if task.state != RepositoryTaskStateV1::Leased
            || lease.lease_id != lease_id
            || lease.agent_id != agent_id
        {
            return Err(StoreError::LeaseMismatch);
        }
        if lease.expires_at <= now {
            return Err(StoreError::LeaseExpired);
        }
        Ok(())
    }

    fn clear_task_lease(&mut self, task_id: &TaskId) {
        if let Some(lease) = self
            .tasks
            .get_mut(task_id)
            .and_then(|task| task.lease.take())
        {
            self.active_leases.remove(&lease.lease_id);
        }
    }

    fn transition_task(
        &mut self,
        task_id: &TaskId,
        target: RepositoryTaskStateV1,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let task = self.tasks.get(task_id).ok_or(StoreError::TaskNotFound)?;
        let source = task.state;
        if source == target {
            return Ok(());
        }
        let job_id = task.job_id.clone();
        let not_before = task.not_before;
        if source == RepositoryTaskStateV1::Pending {
            let pending = self
                .pending_tasks_by_job
                .get_mut(&job_id)
                .ok_or(StoreError::ProgressInvariantViolation)?;
            if !pending.remove(&(not_before, task_id.clone())) {
                return Err(StoreError::ProgressInvariantViolation);
            }
            if pending.is_empty() {
                self.pending_tasks_by_job.remove(&job_id);
            }
        }
        let task = self.tasks.get_mut(task_id).expect("task was checked");
        task.state = target;
        task.updated_at = now;
        if target == RepositoryTaskStateV1::Pending {
            self.pending_tasks_by_job
                .entry(job_id.clone())
                .or_default()
                .insert((not_before, task_id.clone()));
        }
        let job = self.jobs.get_mut(&job_id).expect("task references a job");
        decrement_progress(&mut job.progress, source)?;
        increment_progress(&mut job.progress, target)?;
        job.updated_at = now;
        Ok(())
    }

    fn reclaim_expired_job_leases(
        &mut self,
        job_id: &JobId,
        now: DateTime<Utc>,
    ) -> Result<Vec<TaskId>, StoreError> {
        if !self.jobs.contains_key(job_id) {
            return Err(StoreError::JobNotFound);
        }
        let expired = self
            .task_ids_by_job
            .get(job_id)
            .into_iter()
            .flatten()
            .filter(|task_id| {
                self.tasks[*task_id]
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.expires_at <= now)
            })
            .cloned()
            .collect::<Vec<_>>();
        for task_id in &expired {
            self.clear_task_lease(task_id);
            self.transition_task(task_id, RepositoryTaskStateV1::Pending, now)?;
            self.record_event(
                job_id,
                Some(task_id.clone()),
                now,
                JobEventKindV1::TaskReclaimed,
                BTreeMap::new(),
            )?;
        }
        Ok(expired)
    }

    fn record_event(
        &mut self,
        job_id: &JobId,
        task_id: Option<TaskId>,
        occurred_at: DateTime<Utc>,
        kind: JobEventKindV1,
        attributes: BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        let sequence = self.next_event_sequence;
        self.next_event_sequence = sequence
            .checked_add(1)
            .ok_or(StoreError::EventSequenceOverflow)?;
        let event = JobEventV1 {
            schema_version: SCHEMA_VERSION_V1,
            sequence,
            job_id: job_id.clone(),
            task_id,
            occurred_at,
            kind,
            attributes,
        };
        if self
            .events_by_job
            .insert((job_id.clone(), sequence), event)
            .is_some()
        {
            return Err(StoreError::EventSequenceOverflow);
        }
        Ok(())
    }
}

fn decrement_progress(
    progress: &mut JobProgressV1,
    state: RepositoryTaskStateV1,
) -> Result<(), StoreError> {
    let counter = progress_counter_mut(progress, state);
    *counter = counter
        .checked_sub(1)
        .ok_or(StoreError::ProgressInvariantViolation)?;
    Ok(())
}

fn increment_progress(
    progress: &mut JobProgressV1,
    state: RepositoryTaskStateV1,
) -> Result<(), StoreError> {
    let counter = progress_counter_mut(progress, state);
    *counter = counter
        .checked_add(1)
        .ok_or(StoreError::ProgressInvariantViolation)?;
    Ok(())
}

fn progress_counter_mut(progress: &mut JobProgressV1, state: RepositoryTaskStateV1) -> &mut u64 {
    match state {
        RepositoryTaskStateV1::Pending => &mut progress.tasks_pending,
        RepositoryTaskStateV1::Leased => &mut progress.tasks_leased,
        RepositoryTaskStateV1::Succeeded => &mut progress.tasks_succeeded,
        RepositoryTaskStateV1::Failed | RepositoryTaskStateV1::Cancelled => {
            &mut progress.tasks_failed
        }
    }
}

fn apply_quota_usage(
    usage: &mut QuotaUsageV1,
    resource: QuotaResourceV1,
    amount: u64,
) -> Result<(), StoreError> {
    let target = match resource {
        QuotaResourceV1::Repositories => &mut usage.repositories,
        QuotaResourceV1::ProviderRequests => &mut usage.provider_requests,
        QuotaResourceV1::DownloadedBytes => &mut usage.downloaded_bytes,
        QuotaResourceV1::ArtifactBytes => &mut usage.artifact_bytes,
    };
    *target = target
        .checked_add(amount)
        .ok_or(StoreError::QuotaExceeded(resource))?;
    Ok(())
}

fn quota_attributes(resource: QuotaResourceV1, amount: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("resource".to_owned(), format!("{resource:?}")),
        ("amount".to_owned(), amount.to_string()),
    ])
}

fn next_after_cursor(job_ids: &[JobId], cursor: Option<&JobId>) -> Option<JobId> {
    job_ids
        .iter()
        .find(|job_id| cursor.is_none_or(|cursor| *job_id > cursor))
        .or_else(|| job_ids.first())
        .cloned()
}

fn checked_add_seconds(now: DateTime<Utc>, seconds: u64) -> DateTime<Utc> {
    let seconds = i64::try_from(seconds).unwrap_or(i64::MAX);
    now.checked_add_signed(TimeDelta::seconds(seconds))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

fn valid_reason_code(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 64
        && reason.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b':' | b'.')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError {
    Domain(DomainError),
    Provider(ProviderError),
    InvalidIdentifier,
    InvalidBatch,
    InvalidLease,
    InvalidReasonCode,
    InvalidReservation,
    JobNotFound,
    JobAlreadyExists,
    QueuedJobLimitExceeded,
    ActiveJobLimitExceeded,
    TaskNotFound,
    TaskIdConflict,
    RepositoryAlreadyQueued,
    IdempotencyConflict,
    InvalidJobTransition,
    ActiveLeasesRemain,
    LeaseNotFound,
    LeaseMismatch,
    LeaseExpired,
    LeaseIdConflict,
    CompletionConflict,
    AttemptOverflow,
    ReservationNotFound,
    ReservationConflict,
    InvalidReconciliation,
    QuotaExceeded(QuotaResourceV1),
    ProgressInvariantViolation,
    EventSequenceOverflow,
    InvalidSnapshot,
}

impl From<DomainError> for StoreError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

impl From<ProviderError> for StoreError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::domain::{RepositoryScopeV1, ScanBoundsV1, ScanTargetV1, Sha256Digest};
    use chrono::TimeZone;

    fn time(second: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
            .unwrap()
            .checked_add_signed(TimeDelta::seconds(second))
            .unwrap()
    }

    fn spec(bounds: ScanBoundsV1) -> ScanSpecV1 {
        ScanSpecV1 {
            schema_version: SCHEMA_VERSION_V1,
            target: ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: RepositoryScopeV1::PublicOnly,
            credential_profile_id: None,
            bounds,
            analyzer_versions: BTreeMap::from([("cargo_evidence".to_owned(), "1".to_owned())]),
        }
    }

    fn submit(store: &mut InMemoryStateStore, bounds: ScanBoundsV1) -> JobId {
        let job_id = JobId("job-1".to_owned());
        store
            .submit_job(SubmitJobV1 {
                job_id: job_id.clone(),
                idempotency_key: "submission-1".to_owned(),
                spec: spec(bounds),
                submitted_at: time(0),
            })
            .unwrap();
        job_id
    }

    fn enqueue(store: &mut InMemoryStateStore, job_id: &JobId, value: u32) -> TaskId {
        let task_id = TaskId(format!("task-{value}"));
        store
            .enqueue_task(NewRepositoryTaskV1 {
                task_id: task_id.clone(),
                job_id: job_id.clone(),
                repository_id: format!("repository-{value}"),
                not_before: time(0),
                created_at: time(0),
            })
            .unwrap();
        task_id
    }

    #[test]
    fn ten_thousand_task_inventory_is_consumed_in_bounded_stable_pages() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        for value in 0..10_000 {
            store
                .enqueue_task(NewRepositoryTaskV1 {
                    task_id: TaskId(format!("task-{value:05}")),
                    job_id: job_id.clone(),
                    repository_id: format!("owner/repository-{value:05}"),
                    not_before: time(0),
                    created_at: time(0),
                })
                .unwrap();
        }

        let mut after = None;
        let mut seen = 0_usize;
        let mut previous = None;
        loop {
            let page = store.tasks_for_job_page(&job_id, after.as_deref(), 257);
            assert!(page.len() <= 257);
            if page.is_empty() {
                break;
            }
            for task in &page {
                assert!(
                    previous
                        .as_ref()
                        .is_none_or(|value: &String| value < &task.repository_id)
                );
                previous = Some(task.repository_id.clone());
            }
            seen += page.len();
            after = page.last().map(|task| task.repository_id.clone());
        }
        assert_eq!(seen, 10_000);
    }

    #[test]
    fn ten_thousand_events_are_indexed_and_paged_without_global_scans() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        for value in 0..10_000_u64 {
            store
                .record_event(
                    &job_id,
                    None,
                    time(i64::try_from(value + 1).unwrap()),
                    JobEventKindV1::TaskHeartbeat,
                    BTreeMap::new(),
                )
                .unwrap();
        }

        let mut after = None;
        let mut sequences = Vec::new();
        loop {
            let page = store.events_for_job_page(&job_id, after, 257);
            assert!(page.len() <= 257);
            let Some(last) = page.last() else {
                break;
            };
            assert!(
                page.windows(2)
                    .all(|pair| pair[0].sequence < pair[1].sequence)
            );
            sequences.extend(page.iter().map(|event| event.sequence));
            after = Some(last.sequence);
        }
        assert_eq!(sequences.len(), 10_001);
        assert_eq!(sequences, (0..10_001).collect::<Vec<_>>());

        let restored = InMemoryStateStore::from_snapshot(store.snapshot()).unwrap();
        assert_eq!(restored.events(), store.events());
        assert_eq!(
            restored.events_for_job_page(&job_id, Some(9_900), 200),
            store.events_for_job_page(&job_id, Some(9_900), 200)
        );
    }

    #[test]
    fn event_pruning_preserves_every_nonterminal_job_event() {
        let mut store = InMemoryStateStore::default();
        let terminal = submit(&mut store, ScanBoundsV1::default());
        store.cancel_job(&terminal, time(2)).unwrap();
        let active = JobId("job-active".to_owned());
        store
            .submit_job(SubmitJobV1 {
                job_id: active.clone(),
                idempotency_key: "submission-active".to_owned(),
                spec: spec(ScanBoundsV1::default()),
                submitted_at: time(0),
            })
            .unwrap();
        store.start_job(&active, time(1)).unwrap();

        assert_eq!(store.prune_events_before(time(3)).unwrap(), 2);
        assert!(store.events_for_job_page(&terminal, None, 10).is_empty());
        assert_eq!(store.events_for_job_page(&active, None, 10).len(), 2);
    }

    #[test]
    fn whole_run_retention_is_bounded_by_age_terminal_state_and_artifacts() {
        let mut store = InMemoryStateStore::default();
        let expired = submit(&mut store, ScanBoundsV1::default());
        enqueue(&mut store, &expired, 1);
        store.cancel_job(&expired, time(2)).unwrap();

        let protected = JobId("job-protected".to_owned());
        store
            .submit_job(SubmitJobV1 {
                job_id: protected.clone(),
                idempotency_key: "submission-protected".to_owned(),
                spec: spec(ScanBoundsV1::default()),
                submitted_at: time(0),
            })
            .unwrap();
        store.cancel_job(&protected, time(2)).unwrap();

        let active = JobId("job-active-retention".to_owned());
        store
            .submit_job(SubmitJobV1 {
                job_id: active.clone(),
                idempotency_key: "submission-active-retention".to_owned(),
                spec: spec(ScanBoundsV1::default()),
                submitted_at: time(0),
            })
            .unwrap();
        store.start_job(&active, time(1)).unwrap();

        let recent = JobId("job-recent".to_owned());
        store
            .submit_job(SubmitJobV1 {
                job_id: recent.clone(),
                idempotency_key: "submission-recent".to_owned(),
                spec: spec(ScanBoundsV1::default()),
                submitted_at: time(8),
            })
            .unwrap();
        store.cancel_job(&recent, time(9)).unwrap();

        let summary =
            store.prune_terminal_runs_before(time(5), &BTreeSet::from([protected.clone()]));
        assert_eq!(summary.jobs, 1);
        assert_eq!(summary.tasks, 1);
        assert_eq!(summary.quotas, 4);
        assert_eq!(summary.idempotency_keys, 1);
        assert!(store.job(&expired).is_none());
        assert!(store.job(&protected).is_some());
        assert!(store.job(&active).is_some());
        assert!(store.job(&recent).is_some());

        let restored = InMemoryStateStore::from_snapshot(store.snapshot()).unwrap();
        assert!(restored.job(&expired).is_none());
        assert!(restored.job(&protected).is_some());

        let outcome = store
            .submit_job(SubmitJobV1 {
                job_id: JobId("job-reused-key".to_owned()),
                idempotency_key: "submission-1".to_owned(),
                spec: spec(ScanBoundsV1::default()),
                submitted_at: time(10),
            })
            .unwrap();
        assert_eq!(
            outcome,
            SubmitOutcome::Created(JobId("job-reused-key".to_owned()))
        );
    }

    fn artifact(value: char) -> ArtifactRefV1 {
        ArtifactRefV1 {
            digest: Sha256Digest::parse(value.to_string().repeat(64)).unwrap(),
            media_type: "application/json".to_owned(),
            stored_bytes: 10,
        }
    }

    #[test]
    fn duplicate_submission_returns_the_original_job() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        let outcome = store
            .submit_job(SubmitJobV1 {
                job_id: JobId("different-generated-id".to_owned()),
                idempotency_key: "submission-1".to_owned(),
                spec: spec(ScanBoundsV1::default()),
                submitted_at: time(5),
            })
            .unwrap();
        assert_eq!(outcome, SubmitOutcome::Existing(job_id));
        assert_eq!(store.events().len(), 1);
    }

    #[test]
    fn twenty_sixth_job_queues_but_cannot_start_at_the_running_limit() {
        let mut store = InMemoryStateStore::default();
        let job_ids = (0..=MAX_RUNNING_JOBS)
            .map(|index| JobId(format!("job-{index:02}")))
            .collect::<Vec<_>>();
        for (index, job_id) in job_ids.iter().enumerate() {
            store
                .submit_job(SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: format!("submission-{index}"),
                    spec: spec(ScanBoundsV1::default()),
                    submitted_at: time(index as i64),
                })
                .unwrap();
        }
        for job_id in &job_ids[..MAX_RUNNING_JOBS] {
            store.start_job(job_id, time(100)).unwrap();
        }

        assert_eq!(
            store.start_job(&job_ids[MAX_RUNNING_JOBS], time(101)),
            Err(StoreError::ActiveJobLimitExceeded)
        );
        assert_eq!(
            store.job(&job_ids[MAX_RUNNING_JOBS]).unwrap().state,
            ScanJobStateV1::Queued
        );

        store.pause_job(&job_ids[0], time(102)).unwrap();
        store
            .start_job(&job_ids[MAX_RUNNING_JOBS], time(103))
            .unwrap();
        assert_eq!(
            store.resume_job(&job_ids[0], time(104)),
            Err(StoreError::ActiveJobLimitExceeded)
        );
    }

    #[test]
    fn atomic_submission_does_not_bypass_older_queued_work() {
        let mut store = InMemoryStateStore::default();
        let older = JobId("job-older".to_owned());
        store
            .submit_job(SubmitJobV1 {
                job_id: older.clone(),
                idempotency_key: "submission-older".to_owned(),
                spec: spec(ScanBoundsV1::default()),
                submitted_at: time(0),
            })
            .unwrap();

        let newer = JobId("job-newer".to_owned());
        let request = SubmitJobV1 {
            job_id: newer.clone(),
            idempotency_key: "submission-newer".to_owned(),
            spec: spec(ScanBoundsV1::default()),
            submitted_at: time(1),
        };
        let tasks = [NewRepositoryTaskV1 {
            task_id: TaskId("task-newer".to_owned()),
            job_id: newer.clone(),
            repository_id: "owner/newer".to_owned(),
            not_before: time(1),
            created_at: time(1),
        }];
        store
            .submit_job_with_tasks_atomic(&request, &tasks, time(1))
            .unwrap();

        assert_eq!(store.job(&older).unwrap().state, ScanJobStateV1::Queued);
        assert_eq!(store.job(&newer).unwrap().state, ScanJobStateV1::Queued);
        assert_eq!(store.start_next_queued_job(time(2)).unwrap(), Some(older));
    }

    #[test]
    fn global_leasing_round_robins_running_jobs_and_restores_its_cursor() {
        let mut store = InMemoryStateStore::default();
        let job_a = JobId("job-a".to_owned());
        let job_b = JobId("job-b".to_owned());
        for (index, job_id) in [&job_a, &job_b].into_iter().enumerate() {
            store
                .submit_job(SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: format!("submission-{index}"),
                    spec: spec(ScanBoundsV1::default()),
                    submitted_at: time(index as i64),
                })
                .unwrap();
            store.start_job(job_id, time(10)).unwrap();
        }
        enqueue(&mut store, &job_a, 1);
        enqueue(&mut store, &job_a, 2);
        enqueue(&mut store, &job_b, 3);
        enqueue(&mut store, &job_b, 4);
        let authorization = AgentAuthorizationV1::default();

        let first = store
            .lease_next_authorized_task(&authorization, "agent", "global-1", 60, time(10))
            .unwrap()
            .unwrap();
        assert_eq!(first.job_id, job_a);

        let mut store = InMemoryStateStore::from_snapshot(store.snapshot()).unwrap();
        let remaining = (2..=4)
            .map(|lease| {
                store
                    .lease_next_authorized_task(
                        &authorization,
                        "agent",
                        &format!("global-{lease}"),
                        60,
                        time(10),
                    )
                    .unwrap()
                    .unwrap()
                    .job_id
            })
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec![job_b.clone(), job_a, job_b]);
    }

    #[test]
    fn global_leasing_stays_fair_with_ten_thousand_indexed_tasks() {
        let mut store = InMemoryStateStore::default();
        let job_a = JobId("job-scale-a".to_owned());
        let job_b = JobId("job-scale-b".to_owned());
        for (index, job_id) in [&job_a, &job_b].into_iter().enumerate() {
            store
                .submit_job(SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: format!("scale-submission-{index}"),
                    spec: spec(ScanBoundsV1::default()),
                    submitted_at: time(index as i64),
                })
                .unwrap();
            store.start_job(job_id, time(1)).unwrap();
            for task_index in 0..5_000_u32 {
                store
                    .enqueue_task(NewRepositoryTaskV1 {
                        task_id: TaskId(format!("scale-{index}-{task_index:05}")),
                        job_id: job_id.clone(),
                        repository_id: format!("owner-{index}/repo-{task_index:05}"),
                        not_before: time(0),
                        created_at: time(0),
                    })
                    .unwrap();
            }
        }
        assert_eq!(
            store
                .pending_tasks_by_job
                .values()
                .map(BTreeSet::len)
                .sum::<usize>(),
            10_000
        );

        let authorization = AgentAuthorizationV1::default();
        let selected = (0..20)
            .map(|lease| {
                store
                    .lease_next_authorized_task(
                        &authorization,
                        "scale-agent",
                        &format!("scale-lease-{lease}"),
                        60,
                        time(2),
                    )
                    .unwrap()
                    .unwrap()
                    .job_id
            })
            .collect::<Vec<_>>();
        for (index, job_id) in selected.iter().enumerate() {
            let expected = if index % 2 == 0 { &job_a } else { &job_b };
            assert_eq!(job_id, expected);
        }
        assert_eq!(
            store
                .pending_tasks_by_job
                .values()
                .map(BTreeSet::len)
                .sum::<usize>(),
            9_980
        );

        let restored = InMemoryStateStore::from_snapshot(store.snapshot()).unwrap();
        assert_eq!(restored.pending_tasks_by_job, store.pending_tasks_by_job);
    }

    #[test]
    fn global_leasing_conceals_unauthorized_private_jobs() {
        let mut store = InMemoryStateStore::default();
        let private_job = JobId("job-private".to_owned());
        let public_job = JobId("job-public".to_owned());
        let mut private_spec = spec(ScanBoundsV1::default());
        private_spec.repository_scope = RepositoryScopeV1::AllVisible;
        private_spec.credential_profile_id = Some("customer-a".to_owned());
        for (job_id, job_spec) in [
            (&private_job, private_spec),
            (&public_job, spec(ScanBoundsV1::default())),
        ] {
            store
                .submit_job(SubmitJobV1 {
                    job_id: job_id.clone(),
                    idempotency_key: format!("submission-{}", job_id.0),
                    spec: job_spec,
                    submitted_at: time(0),
                })
                .unwrap();
            store.start_job(job_id, time(1)).unwrap();
        }
        enqueue(&mut store, &private_job, 1);
        enqueue(&mut store, &public_job, 2);

        let public = store
            .lease_next_authorized_task(
                &AgentAuthorizationV1::default(),
                "public-agent",
                "public-lease",
                60,
                time(1),
            )
            .unwrap()
            .unwrap();
        assert_eq!(public.job_id, public_job);
        assert!(
            store
                .lease_next_authorized_task(
                    &AgentAuthorizationV1::default(),
                    "public-agent",
                    "concealed-lease",
                    60,
                    time(1),
                )
                .unwrap()
                .is_none()
        );

        let private_authorization = AgentAuthorizationV1 {
            private_credential_profiles: BTreeSet::from(["customer-a".to_owned()]),
        };
        let private = store
            .lease_next_authorized_task(
                &private_authorization,
                "private-agent",
                "private-lease",
                60,
                time(1),
            )
            .unwrap()
            .unwrap();
        assert_eq!(private.job_id, private_job);
    }

    #[test]
    fn expired_lease_is_reclaimed_and_late_completion_is_rejected() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        let task_id = enqueue(&mut store, &job_id, 1);
        store.start_job(&job_id, time(0)).unwrap();
        store
            .lease_next_task(&job_id, "agent-a", "lease-a", 60, time(0))
            .unwrap();
        assert_eq!(
            store.reclaim_expired_leases(time(60)).unwrap(),
            vec![task_id.clone()]
        );
        assert_eq!(
            store.complete_task(&task_id, "agent-a", "lease-a", artifact('a'), time(61)),
            Err(StoreError::LeaseNotFound)
        );
        let leased = store
            .lease_next_task(&job_id, "agent-b", "lease-b", 60, time(61))
            .unwrap()
            .unwrap();
        assert_eq!(leased.attempt, 2);
    }

    #[test]
    fn cooperative_defer_releases_lease_without_spending_an_attempt() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        let task_id = enqueue(&mut store, &job_id, 1);
        store.start_job(&job_id, time(0)).unwrap();
        let first = store
            .lease_next_task(&job_id, "agent-a", "lease-a", 60, time(0))
            .unwrap()
            .unwrap();
        assert_eq!(first.attempt, 1);

        store
            .defer_task(
                &task_id,
                "agent-a",
                "lease-a",
                time(30),
                "provider_wait",
                time(1),
            )
            .unwrap();
        let deferred = store.task(&task_id).unwrap();
        assert_eq!(deferred.state, RepositoryTaskStateV1::Pending);
        assert_eq!(deferred.attempt, 0);
        assert_eq!(deferred.not_before, time(30));
        assert!(deferred.lease.is_none());
        assert!(
            store
                .lease_next_task(&job_id, "agent-a", "lease-b", 60, time(29))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .lease_next_task(&job_id, "agent-a", "lease-b", 60, time(30))
                .unwrap()
                .unwrap()
                .attempt,
            1
        );
        assert_eq!(
            store.events().last().unwrap().kind,
            JobEventKindV1::TaskLeased
        );
        assert!(store.events().iter().any(|event| {
            event.kind == JobEventKindV1::TaskDeferred
                && event.attributes
                    == BTreeMap::from([("reason_code".to_owned(), "provider_wait".to_owned())])
        }));
    }

    #[test]
    fn retry_respects_not_before_and_completion_is_idempotent() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        let task_id = enqueue(&mut store, &job_id, 1);
        store.start_job(&job_id, time(0)).unwrap();
        store
            .lease_next_task(&job_id, "agent", "lease-1", 60, time(0))
            .unwrap();
        store
            .fail_task(TaskFailureV1 {
                task_id: task_id.clone(),
                agent_id: "agent".to_owned(),
                lease_id: "lease-1".to_owned(),
                failure: "temporary".to_owned(),
                retry_at: Some(time(30)),
                observed_at: time(1),
            })
            .unwrap();
        assert_eq!(
            store
                .lease_next_task(&job_id, "agent", "lease-2", 60, time(29))
                .unwrap(),
            None
        );
        store
            .lease_next_task(&job_id, "agent", "lease-2", 60, time(30))
            .unwrap();
        let result = artifact('b');
        store
            .complete_task(&task_id, "agent", "lease-2", result.clone(), time(31))
            .unwrap();
        store
            .complete_task(&task_id, "agent", "lease-2", result, time(32))
            .unwrap();
        assert_eq!(store.job(&job_id).unwrap().progress.tasks_succeeded, 1);
    }

    #[test]
    fn quota_reservations_prevent_oversubscription_and_reconcile_once() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(
            &mut store,
            ScanBoundsV1 {
                repository_limit: 2,
                ..ScanBoundsV1::default()
            },
        );
        store.start_job(&job_id, time(0)).unwrap();
        let first = ReservationId("reservation-1".to_owned());
        store
            .reserve_quota(
                first.clone(),
                &job_id,
                QuotaResourceV1::Repositories,
                2,
                time(1),
            )
            .unwrap();
        assert_eq!(
            store.reserve_quota(
                ReservationId("reservation-2".to_owned()),
                &job_id,
                QuotaResourceV1::Repositories,
                1,
                time(2),
            ),
            Err(StoreError::QuotaExceeded(QuotaResourceV1::Repositories))
        );
        assert_eq!(store.job(&job_id).unwrap().state, ScanJobStateV1::Paused);
        store.reconcile_quota(&first, 1, time(3)).unwrap();
        store.reconcile_quota(&first, 1, time(4)).unwrap();
        assert_eq!(
            store.quota(&job_id, QuotaResourceV1::Repositories),
            Some(&QuotaLedgerV1 {
                limit: 2,
                reserved: 0,
                used: 1
            })
        );
    }

    #[test]
    fn partial_job_can_resume_pending_tasks() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        enqueue(&mut store, &job_id, 1);
        store.start_job(&job_id, time(0)).unwrap();
        store
            .finalize_job(
                &job_id,
                BTreeSet::from(["quota_exhausted".to_owned()]),
                time(1),
            )
            .unwrap();
        assert_eq!(
            store.job(&job_id).unwrap().state,
            ScanJobStateV1::CompletedPartial
        );
        store.resume_job(&job_id, time(2)).unwrap();
        assert_eq!(store.job(&job_id).unwrap().state, ScanJobStateV1::Running);
    }

    #[test]
    fn explicit_resume_requeues_failed_tasks_without_repeating_successes() {
        let mut store = InMemoryStateStore::default();
        let job_id = submit(&mut store, ScanBoundsV1::default());
        let failed_task = enqueue(&mut store, &job_id, 1);
        let succeeded_task = enqueue(&mut store, &job_id, 2);
        store.start_job(&job_id, time(0)).unwrap();
        store
            .lease_next_task(&job_id, "agent", "lease-failed", 60, time(1))
            .unwrap();
        store
            .fail_task(TaskFailureV1 {
                task_id: failed_task.clone(),
                agent_id: "agent".to_owned(),
                lease_id: "lease-failed".to_owned(),
                failure: "permanent".to_owned(),
                retry_at: None,
                observed_at: time(2),
            })
            .unwrap();
        store
            .lease_next_task(&job_id, "agent", "lease-succeeded", 60, time(3))
            .unwrap();
        store
            .complete_task(
                &succeeded_task,
                "agent",
                "lease-succeeded",
                artifact('c'),
                time(4),
            )
            .unwrap();
        store
            .finalize_job(&job_id, BTreeSet::new(), time(5))
            .unwrap();
        assert_eq!(
            store.job(&job_id).unwrap().state,
            ScanJobStateV1::CompletedPartial
        );

        store.resume_job(&job_id, time(6)).unwrap();
        assert_eq!(
            store.task(&failed_task).unwrap().state,
            RepositoryTaskStateV1::Pending
        );
        assert_eq!(
            store.task(&succeeded_task).unwrap().state,
            RepositoryTaskStateV1::Succeeded
        );
        assert_eq!(store.job(&job_id).unwrap().state, ScanJobStateV1::Running);
    }
}
