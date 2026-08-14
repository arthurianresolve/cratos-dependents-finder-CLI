//! Deterministic admission, fair task dispatch, and retry policy primitives.
//!
//! This module contains no I/O. Durable stores can persist the versioned
//! records and rebuild the ready-task index after replay or restore.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::domain::{
    AgentAuthorizationV1, JobId, SCHEMA_VERSION_V1, ScanJobStateV1, ScanSpecV1, Sha256Digest,
    TaskId,
};

pub const MAX_QUEUED_JOBS: usize = 1_000;
pub const MAX_RUNNING_JOBS: usize = 25;
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
pub const DEFAULT_MAX_RUN_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;
const PRIORITY_AGING_SECONDS: i64 = 60 * 60;

/// Content-addressed repository input held by a queued job until admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositorySetRefV1 {
    pub schema_version: u16,
    pub digest: Sha256Digest,
    pub repository_count: u64,
}

impl RepositorySetRefV1 {
    pub fn validate(&self) -> Result<(), DispatchError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(DispatchError::UnsupportedSchemaVersion(self.schema_version));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPriorityV1 {
    Low,
    #[default]
    Normal,
    High,
}

impl JobPriorityV1 {
    fn aged(self, waiting_seconds: i64) -> Self {
        let promotions = waiting_seconds.max(0) / PRIORITY_AGING_SECONDS;
        match (self, promotions) {
            (Self::Low, 0) => Self::Low,
            (Self::Low, 1) | (Self::Normal, 0) => Self::Normal,
            _ => Self::High,
        }
    }
}

/// Immutable inputs used to place a job in the admission queue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueuedJobV1 {
    pub schema_version: u16,
    pub job_id: JobId,
    pub idempotency_key: String,
    pub spec: ScanSpecV1,
    pub repository_set: RepositorySetRefV1,
    pub priority: JobPriorityV1,
    pub submitted_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub max_run_age_seconds: u64,
}

impl QueuedJobV1 {
    pub fn validate(&self) -> Result<(), DispatchError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(DispatchError::UnsupportedSchemaVersion(self.schema_version));
        }
        if !normalized_identifier(&self.job_id.0) || !normalized_identifier(&self.idempotency_key) {
            return Err(DispatchError::InvalidIdentifier);
        }
        self.spec
            .validate()
            .map_err(|error| DispatchError::InvalidScanSpec(error.to_string()))?;
        self.repository_set.validate()?;
        if self.repository_set.repository_count == 0 {
            return Err(DispatchError::EmptyRepositorySet);
        }
        if self.repository_set.repository_count > self.spec.bounds.repository_limit {
            return Err(DispatchError::RepositoryLimitExceeded);
        }
        if self.max_run_age_seconds == 0 {
            return Err(DispatchError::InvalidMaxRunAge);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DispatchJobV1 {
    pub schema_version: u16,
    pub request: QueuedJobV1,
    pub state: ScanJobStateV1,
    pub generation: u64,
    pub admitted_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum QueueSubmitOutcomeV1 {
    Created(JobId),
    Existing(JobId),
}

/// Stable admission proposal. A durable adapter commits this together with
/// task materialization so a running job can never exist without its tasks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionPlanV1 {
    pub schema_version: u16,
    pub job_id: JobId,
    pub expected_generation: u64,
    pub repository_set: RepositorySetRefV1,
    pub effective_priority: JobPriorityV1,
}

#[derive(Clone, Debug)]
pub struct AdmissionQueue {
    jobs: BTreeMap<JobId, DispatchJobV1>,
    idempotency_keys: BTreeMap<String, JobId>,
    max_queued_jobs: usize,
    max_running_jobs: usize,
}

impl Default for AdmissionQueue {
    fn default() -> Self {
        Self::with_limits(MAX_QUEUED_JOBS, MAX_RUNNING_JOBS)
    }
}

impl AdmissionQueue {
    pub fn with_limits(max_queued_jobs: usize, max_running_jobs: usize) -> Self {
        Self {
            jobs: BTreeMap::new(),
            idempotency_keys: BTreeMap::new(),
            max_queued_jobs,
            max_running_jobs,
        }
    }

    pub fn submit(&mut self, request: QueuedJobV1) -> Result<QueueSubmitOutcomeV1, DispatchError> {
        request.validate()?;
        if let Some(job_id) = self.idempotency_keys.get(&request.idempotency_key) {
            let existing = &self.jobs[job_id];
            return if existing.request == request {
                Ok(QueueSubmitOutcomeV1::Existing(job_id.clone()))
            } else {
                Err(DispatchError::IdempotencyConflict)
            };
        }
        if self.jobs.contains_key(&request.job_id) {
            return Err(DispatchError::JobAlreadyExists);
        }
        if self.queued_count() >= self.max_queued_jobs {
            return Err(DispatchError::QueuedJobLimitExceeded);
        }

        let job_id = request.job_id.clone();
        self.idempotency_keys
            .insert(request.idempotency_key.clone(), job_id.clone());
        self.jobs.insert(
            job_id.clone(),
            DispatchJobV1 {
                schema_version: SCHEMA_VERSION_V1,
                request,
                state: ScanJobStateV1::Queued,
                generation: 0,
                admitted_at: None,
                finished_at: None,
            },
        );
        Ok(QueueSubmitOutcomeV1::Created(job_id))
    }

    pub fn plan_next_admission(&self, now: DateTime<Utc>) -> Option<AdmissionPlanV1> {
        if self.running_count() >= self.max_running_jobs {
            return None;
        }
        let job = self
            .jobs
            .values()
            .filter(|job| job.state == ScanJobStateV1::Queued && job.request.not_before <= now)
            .max_by_key(|job| {
                let waited = now
                    .signed_duration_since(job.request.submitted_at)
                    .num_seconds();
                (
                    job.request.priority.aged(waited),
                    std::cmp::Reverse(job.request.submitted_at),
                    std::cmp::Reverse(job.request.job_id.clone()),
                )
            })?;
        let waited = now
            .signed_duration_since(job.request.submitted_at)
            .num_seconds();
        Some(AdmissionPlanV1 {
            schema_version: SCHEMA_VERSION_V1,
            job_id: job.request.job_id.clone(),
            expected_generation: job.generation,
            repository_set: job.request.repository_set.clone(),
            effective_priority: job.request.priority.aged(waited),
        })
    }

    /// Commits an admission after the durable adapter has materialized tasks.
    pub fn commit_admission(
        &mut self,
        plan: &AdmissionPlanV1,
        now: DateTime<Utc>,
    ) -> Result<(), DispatchError> {
        if plan.schema_version != SCHEMA_VERSION_V1 {
            return Err(DispatchError::UnsupportedSchemaVersion(plan.schema_version));
        }
        if self.running_count() >= self.max_running_jobs {
            return Err(DispatchError::RunningJobLimitExceeded);
        }
        let job = self
            .jobs
            .get_mut(&plan.job_id)
            .ok_or(DispatchError::JobNotFound)?;
        if job.state != ScanJobStateV1::Queued
            || job.generation != plan.expected_generation
            || job.request.repository_set != plan.repository_set
        {
            return Err(DispatchError::StaleAdmissionPlan);
        }
        if job.request.not_before > now {
            return Err(DispatchError::JobNotReady);
        }
        job.state = ScanJobStateV1::Running;
        job.admitted_at = Some(now);
        job.generation = job
            .generation
            .checked_add(1)
            .ok_or(DispatchError::GenerationOverflow)?;
        Ok(())
    }

    pub fn admit_next(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<Option<AdmissionPlanV1>, DispatchError> {
        let Some(plan) = self.plan_next_admission(now) else {
            return Ok(None);
        };
        self.commit_admission(&plan, now)?;
        Ok(Some(plan))
    }

    pub fn pause(&mut self, job_id: &JobId) -> Result<(), DispatchError> {
        self.transition_nonterminal(job_id, ScanJobStateV1::Running, ScanJobStateV1::Paused)
    }

    pub fn resume(&mut self, job_id: &JobId) -> Result<(), DispatchError> {
        if self.running_count() >= self.max_running_jobs {
            return Err(DispatchError::RunningJobLimitExceeded);
        }
        self.transition_nonterminal(job_id, ScanJobStateV1::Paused, ScanJobStateV1::Running)
    }

    pub fn terminalize(
        &mut self,
        job_id: &JobId,
        terminal_state: ScanJobStateV1,
        now: DateTime<Utc>,
    ) -> Result<(), DispatchError> {
        if !terminal_state.is_terminal() {
            return Err(DispatchError::InvalidJobTransition);
        }
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or(DispatchError::JobNotFound)?;
        if job.state.is_terminal() {
            return if job.state == terminal_state {
                Ok(())
            } else {
                Err(DispatchError::InvalidJobTransition)
            };
        }
        job.state = terminal_state;
        job.finished_at = Some(now);
        job.generation = job
            .generation
            .checked_add(1)
            .ok_or(DispatchError::GenerationOverflow)?;
        Ok(())
    }

    /// Terminalizes admitted jobs whose wall-clock age exceeds their policy.
    pub fn expire_abandoned(&mut self, now: DateTime<Utc>) -> Vec<JobId> {
        let expired = self
            .jobs
            .values()
            .filter(|job| matches!(job.state, ScanJobStateV1::Running | ScanJobStateV1::Paused))
            .filter_map(|job| {
                let admitted_at = job.admitted_at?;
                let age_limit = seconds_delta(job.request.max_run_age_seconds);
                (now >= admitted_at
                    .checked_add_signed(age_limit)
                    .unwrap_or(DateTime::<Utc>::MAX_UTC))
                .then(|| job.request.job_id.clone())
            })
            .collect::<Vec<_>>();
        for job_id in &expired {
            let job = self.jobs.get_mut(job_id).expect("expired job exists");
            job.state = ScanJobStateV1::Failed;
            job.finished_at = Some(now);
            job.generation = job.generation.saturating_add(1);
        }
        expired
    }

    pub fn job(&self, job_id: &JobId) -> Option<&DispatchJobV1> {
        self.jobs.get(job_id)
    }

    pub fn jobs(&self) -> impl Iterator<Item = &DispatchJobV1> {
        self.jobs.values()
    }

    pub fn queued_count(&self) -> usize {
        self.jobs
            .values()
            .filter(|job| job.state == ScanJobStateV1::Queued)
            .count()
    }

    pub fn running_count(&self) -> usize {
        self.jobs
            .values()
            .filter(|job| job.state == ScanJobStateV1::Running)
            .count()
    }

    fn transition_nonterminal(
        &mut self,
        job_id: &JobId,
        expected: ScanJobStateV1,
        target: ScanJobStateV1,
    ) -> Result<(), DispatchError> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or(DispatchError::JobNotFound)?;
        if job.state != expected {
            return Err(DispatchError::InvalidJobTransition);
        }
        job.state = target;
        job.generation = job
            .generation
            .checked_add(1)
            .ok_or(DispatchError::GenerationOverflow)?;
        Ok(())
    }
}

/// Minimal canonical record required to rebuild the derived ready indexes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IndexedTaskV1 {
    pub schema_version: u16,
    pub task_id: TaskId,
    pub job_id: JobId,
    pub not_before: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DispatchSelectionV1 {
    pub schema_version: u16,
    pub task: IndexedTaskV1,
    pub effective_priority: JobPriorityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TaskLocation {
    Ready,
    Deferred(DateTime<Utc>),
}

/// Disposable ready-task indexes with deterministic, priority-aware selection.
#[derive(Clone, Debug, Default)]
pub struct ReadyTaskIndex {
    records: BTreeMap<TaskId, IndexedTaskV1>,
    ready_by_job: BTreeMap<JobId, BTreeSet<(DateTime<Utc>, TaskId)>>,
    deferred: BTreeMap<DateTime<Utc>, BTreeSet<TaskId>>,
    locations: BTreeMap<TaskId, TaskLocation>,
    cursors: BTreeMap<JobPriorityV1, JobId>,
}

impl ReadyTaskIndex {
    pub fn rebuild(
        tasks: impl IntoIterator<Item = IndexedTaskV1>,
        now: DateTime<Utc>,
    ) -> Result<Self, DispatchError> {
        let mut index = Self::default();
        for task in tasks {
            index.insert(task, now)?;
        }
        Ok(index)
    }

    pub fn insert(&mut self, task: IndexedTaskV1, now: DateTime<Utc>) -> Result<(), DispatchError> {
        validate_task(&task)?;
        if let Some(existing) = self.records.get(&task.task_id) {
            return if existing == &task {
                Ok(())
            } else {
                Err(DispatchError::TaskConflict)
            };
        }
        self.index_record(&task, now);
        self.records.insert(task.task_id.clone(), task);
        Ok(())
    }

    pub fn remove(&mut self, task_id: &TaskId) -> Option<IndexedTaskV1> {
        let task = self.records.remove(task_id)?;
        self.remove_location(&task);
        Some(task)
    }

    pub fn defer(
        &mut self,
        task_id: &TaskId,
        not_before: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), DispatchError> {
        let mut task = self.remove(task_id).ok_or(DispatchError::TaskNotFound)?;
        task.not_before = not_before;
        self.insert(task, now)
    }

    pub fn select_next(
        &mut self,
        queue: &AdmissionQueue,
        authorization: &AgentAuthorizationV1,
        now: DateTime<Utc>,
    ) -> Option<DispatchSelectionV1> {
        self.promote_due(now);
        let mut candidates = self
            .ready_by_job
            .iter()
            .filter_map(|(job_id, tasks)| {
                let job = queue.job(job_id)?;
                if job.state != ScanJobStateV1::Running || !authorization.allows(&job.request.spec)
                {
                    return None;
                }
                let ready_since = tasks.first()?.0;
                let waited = now.signed_duration_since(ready_since).num_seconds();
                Some((job.request.priority.aged(waited), job_id.clone()))
            })
            .collect::<Vec<_>>();
        let selected_priority = candidates.iter().map(|(priority, _)| *priority).max()?;
        candidates.retain(|(priority, _)| *priority == selected_priority);
        candidates.sort_by(|(_, left), (_, right)| left.cmp(right));

        let cursor = self.cursors.get(&selected_priority);
        let selected_job = candidates
            .iter()
            .map(|(_, job_id)| job_id)
            .find(|job_id| cursor.is_none_or(|cursor| *job_id > cursor))
            .or_else(|| candidates.first().map(|(_, job_id)| job_id))?
            .clone();
        let task_id = self
            .ready_by_job
            .get(&selected_job)
            .and_then(BTreeSet::first)
            .map(|(_, task_id)| task_id.clone())?;
        let task = self.remove(&task_id)?;
        self.cursors.insert(selected_priority, selected_job.clone());
        Some(DispatchSelectionV1 {
            schema_version: SCHEMA_VERSION_V1,
            task,
            effective_priority: selected_priority,
        })
    }

    pub fn restore_selection(
        &mut self,
        selection: DispatchSelectionV1,
        now: DateTime<Utc>,
    ) -> Result<(), DispatchError> {
        if selection.schema_version != SCHEMA_VERSION_V1 {
            return Err(DispatchError::UnsupportedSchemaVersion(
                selection.schema_version,
            ));
        }
        self.insert(selection.task, now)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), DispatchError> {
        let rebuilt = Self::rebuild(self.records.values().cloned(), now)?;
        if self.ready_by_job != rebuilt.ready_by_job
            || self.deferred != rebuilt.deferred
            || self.locations != rebuilt.locations
        {
            return Err(DispatchError::InvalidReadyIndex);
        }
        Ok(())
    }

    fn promote_due(&mut self, now: DateTime<Utc>) {
        let due_times = self
            .deferred
            .range(..=now)
            .map(|(not_before, _)| *not_before)
            .collect::<Vec<_>>();
        for not_before in due_times {
            let task_ids = self.deferred.remove(&not_before).unwrap_or_default();
            for task_id in task_ids {
                let task = &self.records[&task_id];
                self.ready_by_job
                    .entry(task.job_id.clone())
                    .or_default()
                    .insert((task.not_before, task_id.clone()));
                self.locations.insert(task_id, TaskLocation::Ready);
            }
        }
    }

    fn index_record(&mut self, task: &IndexedTaskV1, now: DateTime<Utc>) {
        if task.not_before <= now {
            self.ready_by_job
                .entry(task.job_id.clone())
                .or_default()
                .insert((task.not_before, task.task_id.clone()));
            self.locations
                .insert(task.task_id.clone(), TaskLocation::Ready);
        } else {
            self.deferred
                .entry(task.not_before)
                .or_default()
                .insert(task.task_id.clone());
            self.locations.insert(
                task.task_id.clone(),
                TaskLocation::Deferred(task.not_before),
            );
        }
    }

    fn remove_location(&mut self, task: &IndexedTaskV1) {
        match self.locations.remove(&task.task_id) {
            Some(TaskLocation::Ready) => {
                remove_set_value(
                    &mut self.ready_by_job,
                    &task.job_id,
                    &(task.not_before, task.task_id.clone()),
                );
            }
            Some(TaskLocation::Deferred(not_before)) => {
                remove_set_value(&mut self.deferred, &not_before, &task.task_id);
            }
            None => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailureKindV1 {
    Timeout,
    Transport,
    ProviderRateLimited,
    ProviderUnavailable,
    LeaseExpired,
    Authentication,
    Authorization,
    RepositoryNotFound,
    InvalidEvidence,
    QuotaExhausted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassV1 {
    Transient,
    Permanent,
}

impl TaskFailureKindV1 {
    pub fn class(self) -> FailureClassV1 {
        match self {
            Self::Timeout
            | Self::Transport
            | Self::ProviderRateLimited
            | Self::ProviderUnavailable
            | Self::LeaseExpired => FailureClassV1::Transient,
            Self::Authentication
            | Self::Authorization
            | Self::RepositoryNotFound
            | Self::InvalidEvidence
            | Self::QuotaExhausted
            | Self::Cancelled => FailureClassV1::Permanent,
        }
    }

    fn reason_code(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::ProviderRateLimited => "provider_rate_limited",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::LeaseExpired => "lease_expired",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::RepositoryNotFound => "repository_not_found",
            Self::InvalidEvidence => "invalid_evidence",
            Self::QuotaExhausted => "quota_exhausted",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetryPolicyV1 {
    pub schema_version: u16,
    pub max_attempts: u32,
    pub initial_delay_seconds: u64,
    pub maximum_delay_seconds: u64,
    pub jitter_percent: u8,
}

impl Default for RetryPolicyV1 {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_delay_seconds: 30,
            maximum_delay_seconds: 60,
            jitter_percent: 10,
        }
    }
}

impl RetryPolicyV1 {
    pub fn validate(&self) -> Result<(), DispatchError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(DispatchError::UnsupportedSchemaVersion(self.schema_version));
        }
        if self.max_attempts == 0
            || self.initial_delay_seconds == 0
            || self.maximum_delay_seconds < self.initial_delay_seconds
            || self.jitter_percent > 50
        {
            return Err(DispatchError::InvalidRetryPolicy);
        }
        Ok(())
    }

    pub fn decide(
        &self,
        task_id: &TaskId,
        completed_attempt: u32,
        failure: TaskFailureKindV1,
        observed_at: DateTime<Utc>,
        provider_not_before: Option<DateTime<Utc>>,
    ) -> Result<RetryDecisionV1, DispatchError> {
        self.validate()?;
        if completed_attempt == 0 {
            return Err(DispatchError::InvalidAttempt);
        }
        if failure.class() == FailureClassV1::Permanent || completed_attempt >= self.max_attempts {
            let reason_code = if failure.class() == FailureClassV1::Permanent {
                failure.reason_code().to_owned()
            } else {
                "attempts_exhausted".to_owned()
            };
            return Ok(RetryDecisionV1::DeadLetter {
                classification: failure.class(),
                reason_code,
            });
        }

        let exponent = completed_attempt.saturating_sub(1).min(63);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let base_delay = self
            .initial_delay_seconds
            .saturating_mul(multiplier)
            .min(self.maximum_delay_seconds);
        let jitter_cap = base_delay.saturating_mul(u64::from(self.jitter_percent)) / 100;
        let jitter = deterministic_jitter(task_id, completed_attempt, jitter_cap);
        let delay_seconds = base_delay.saturating_add(jitter);
        let local_not_before = observed_at
            .checked_add_signed(seconds_delta(delay_seconds))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let not_before = provider_not_before
            .map(|provider| provider.max(local_not_before))
            .unwrap_or(local_not_before);
        Ok(RetryDecisionV1::Retry {
            not_before,
            base_delay_seconds: base_delay,
            jitter_seconds: jitter,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RetryDecisionV1 {
    Retry {
        not_before: DateTime<Utc>,
        base_delay_seconds: u64,
        jitter_seconds: u64,
    },
    DeadLetter {
        classification: FailureClassV1,
        reason_code: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeadLetterTaskV1 {
    pub schema_version: u16,
    pub task_id: TaskId,
    pub job_id: JobId,
    pub completed_attempts: u32,
    pub failure: TaskFailureKindV1,
    pub reason_code: String,
    pub failed_at: DateTime<Utc>,
    pub replay_count: u32,
}

fn validate_task(task: &IndexedTaskV1) -> Result<(), DispatchError> {
    if task.schema_version != SCHEMA_VERSION_V1 {
        return Err(DispatchError::UnsupportedSchemaVersion(task.schema_version));
    }
    if !normalized_identifier(&task.task_id.0) || !normalized_identifier(&task.job_id.0) {
        return Err(DispatchError::InvalidIdentifier);
    }
    Ok(())
}

fn deterministic_jitter(task_id: &TaskId, attempt: u32, cap: u64) -> u64 {
    if cap == 0 {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update(task_id.0.as_bytes());
    hasher.update(attempt.to_be_bytes());
    let digest = hasher.finalize();
    let value = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    );
    value % (cap + 1)
}

fn remove_set_value<K, V>(map: &mut BTreeMap<K, BTreeSet<V>>, key: &K, value: &V)
where
    K: Ord + Clone,
    V: Ord,
{
    let remove_key = map.get_mut(key).is_some_and(|values| {
        values.remove(value);
        values.is_empty()
    });
    if remove_key {
        map.remove(key);
    }
}

fn normalized_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.trim() == value
}

fn seconds_delta(seconds: u64) -> TimeDelta {
    TimeDelta::seconds(i64::try_from(seconds).unwrap_or(i64::MAX))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchError {
    UnsupportedSchemaVersion(u16),
    InvalidIdentifier,
    InvalidScanSpec(String),
    EmptyRepositorySet,
    RepositoryLimitExceeded,
    InvalidMaxRunAge,
    InvalidRetryPolicy,
    InvalidAttempt,
    JobAlreadyExists,
    JobNotFound,
    JobNotReady,
    QueuedJobLimitExceeded,
    RunningJobLimitExceeded,
    IdempotencyConflict,
    InvalidJobTransition,
    StaleAdmissionPlan,
    GenerationOverflow,
    TaskConflict,
    TaskNotFound,
    InvalidReadyIndex,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DispatchError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::domain::{RepositoryScopeV1, ScanBoundsV1, ScanTargetV1, Sha256Digest};
    use chrono::TimeZone;

    fn time(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, hour, minute, 0).unwrap()
    }

    fn spec(scope: RepositoryScopeV1, credential: Option<&str>) -> ScanSpecV1 {
        ScanSpecV1 {
            schema_version: SCHEMA_VERSION_V1,
            target: ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: scope,
            credential_profile_id: credential.map(str::to_owned),
            bounds: ScanBoundsV1::default(),
            analyzer_versions: BTreeMap::new(),
        }
    }

    fn repository_set(count: u64) -> RepositorySetRefV1 {
        RepositorySetRefV1 {
            schema_version: SCHEMA_VERSION_V1,
            digest: Sha256Digest::parse("a".repeat(64)).unwrap(),
            repository_count: count,
        }
    }

    fn request(id: &str, priority: JobPriorityV1, submitted_at: DateTime<Utc>) -> QueuedJobV1 {
        QueuedJobV1 {
            schema_version: SCHEMA_VERSION_V1,
            job_id: JobId(id.to_owned()),
            idempotency_key: format!("key-{id}"),
            spec: spec(RepositoryScopeV1::PublicOnly, None),
            repository_set: repository_set(3),
            priority,
            submitted_at,
            not_before: submitted_at,
            max_run_age_seconds: DEFAULT_MAX_RUN_AGE_SECONDS,
        }
    }

    fn running_queue(job_ids: &[&str]) -> AdmissionQueue {
        let mut queue = AdmissionQueue::with_limits(20, 20);
        for (offset, id) in job_ids.iter().enumerate() {
            queue
                .submit(request(id, JobPriorityV1::Normal, time(0, offset as u32)))
                .unwrap();
            queue.admit_next(time(1, 0)).unwrap().unwrap();
        }
        queue
    }

    #[test]
    fn admission_keeps_jobs_queued_until_committed() {
        let mut queue = AdmissionQueue::with_limits(3, 1);
        queue
            .submit(request("one", JobPriorityV1::Normal, time(0, 0)))
            .unwrap();
        let plan = queue.plan_next_admission(time(0, 1)).unwrap();
        assert_eq!(
            queue.job(&JobId("one".to_owned())).unwrap().state,
            ScanJobStateV1::Queued
        );

        queue.commit_admission(&plan, time(0, 1)).unwrap();
        assert_eq!(
            queue.job(&JobId("one".to_owned())).unwrap().state,
            ScanJobStateV1::Running
        );
        assert!(queue.plan_next_admission(time(0, 2)).is_none());
    }

    #[test]
    fn aged_low_priority_is_eventually_admitted() {
        let mut queue = AdmissionQueue::with_limits(5, 5);
        queue
            .submit(request("low", JobPriorityV1::Low, time(0, 0)))
            .unwrap();
        queue
            .submit(request("normal", JobPriorityV1::Normal, time(1, 30)))
            .unwrap();
        let plan = queue.plan_next_admission(time(2, 1)).unwrap();
        assert_eq!(plan.job_id, JobId("low".to_owned()));
        assert_eq!(plan.effective_priority, JobPriorityV1::High);
    }

    #[test]
    fn running_limit_is_independent_of_queued_capacity() {
        let mut queue = AdmissionQueue::with_limits(3, 1);
        queue
            .submit(request("one", JobPriorityV1::Normal, time(0, 0)))
            .unwrap();
        queue
            .submit(request("two", JobPriorityV1::Normal, time(0, 1)))
            .unwrap();
        queue.admit_next(time(1, 0)).unwrap();
        assert_eq!(queue.queued_count(), 1);
        assert_eq!(queue.running_count(), 1);
        assert!(queue.plan_next_admission(time(1, 0)).is_none());
    }

    #[test]
    fn ready_index_round_robins_jobs_and_promotes_deferred_tasks() {
        let queue = running_queue(&["a", "b"]);
        let mut index = ReadyTaskIndex::rebuild(
            [
                IndexedTaskV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    task_id: TaskId("a-1".to_owned()),
                    job_id: JobId("a".to_owned()),
                    not_before: time(1, 0),
                },
                IndexedTaskV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    task_id: TaskId("a-2".to_owned()),
                    job_id: JobId("a".to_owned()),
                    not_before: time(1, 0),
                },
                IndexedTaskV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    task_id: TaskId("b-1".to_owned()),
                    job_id: JobId("b".to_owned()),
                    not_before: time(1, 0),
                },
                IndexedTaskV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    task_id: TaskId("b-2".to_owned()),
                    job_id: JobId("b".to_owned()),
                    not_before: time(2, 0),
                },
            ],
            time(1, 0),
        )
        .unwrap();
        let authorization = AgentAuthorizationV1::default();

        let first = index
            .select_next(&queue, &authorization, time(1, 1))
            .unwrap();
        let second = index
            .select_next(&queue, &authorization, time(1, 1))
            .unwrap();
        assert_eq!(first.task.job_id, JobId("a".to_owned()));
        assert_eq!(second.task.job_id, JobId("b".to_owned()));
        assert_eq!(index.len(), 2);

        let third = index
            .select_next(&queue, &authorization, time(2, 0))
            .unwrap();
        assert_eq!(third.task.job_id, JobId("a".to_owned()));
        assert!(index.validate(time(2, 0)).is_ok());
    }

    #[test]
    fn private_tasks_require_an_authorized_agent() {
        let mut queue = AdmissionQueue::default();
        let mut private = request("private", JobPriorityV1::Normal, time(0, 0));
        private.spec = spec(RepositoryScopeV1::AllVisible, Some("customer-a"));
        queue.submit(private).unwrap();
        queue.admit_next(time(1, 0)).unwrap();
        let task = IndexedTaskV1 {
            schema_version: SCHEMA_VERSION_V1,
            task_id: TaskId("private-task".to_owned()),
            job_id: JobId("private".to_owned()),
            not_before: time(1, 0),
        };
        let mut index = ReadyTaskIndex::rebuild([task], time(1, 0)).unwrap();
        assert!(
            index
                .select_next(&queue, &AgentAuthorizationV1::default(), time(1, 0))
                .is_none()
        );

        let authorization = AgentAuthorizationV1 {
            private_credential_profiles: BTreeSet::from(["customer-a".to_owned()]),
        };
        assert!(
            index
                .select_next(&queue, &authorization, time(1, 0))
                .is_some()
        );
    }

    #[test]
    fn retry_policy_is_deterministic_and_honors_provider_gate() {
        let policy = RetryPolicyV1::default();
        let task_id = TaskId("task".to_owned());
        let provider_reset = time(0, 45);
        let first = policy
            .decide(
                &task_id,
                1,
                TaskFailureKindV1::ProviderRateLimited,
                time(0, 0),
                Some(provider_reset),
            )
            .unwrap();
        assert_eq!(
            first,
            policy
                .decide(
                    &task_id,
                    1,
                    TaskFailureKindV1::ProviderRateLimited,
                    time(0, 0),
                    Some(provider_reset),
                )
                .unwrap()
        );
        let RetryDecisionV1::Retry { not_before, .. } = first else {
            panic!("transient first attempt should retry");
        };
        assert!(not_before >= provider_reset);

        assert!(matches!(
            policy
                .decide(
                    &task_id,
                    3,
                    TaskFailureKindV1::Timeout,
                    time(0, 0),
                    None,
                )
                .unwrap(),
            RetryDecisionV1::DeadLetter { reason_code, .. }
                if reason_code == "attempts_exhausted"
        ));
        assert!(matches!(
            policy
                .decide(
                    &task_id,
                    1,
                    TaskFailureKindV1::Authentication,
                    time(0, 0),
                    None,
                )
                .unwrap(),
            RetryDecisionV1::DeadLetter { .. }
        ));
    }

    #[test]
    fn abandoned_running_job_expires() {
        let mut queue = AdmissionQueue::default();
        let mut job = request("old", JobPriorityV1::Normal, time(0, 0));
        job.max_run_age_seconds = 60;
        queue.submit(job).unwrap();
        queue.admit_next(time(0, 1)).unwrap();
        assert_eq!(
            queue.expire_abandoned(time(0, 2)),
            vec![JobId("old".to_owned())]
        );
        assert_eq!(
            queue.job(&JobId("old".to_owned())).unwrap().state,
            ScanJobStateV1::Failed
        );
    }
}
