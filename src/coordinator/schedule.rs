//! Versioned UTC schedules and deterministic occurrence planning.
//!
//! Scheduling is deliberately separated from repository materialization and
//! job submission. A durable coordinator can persist the returned occurrence
//! before performing either operation.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, NaiveDate, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};

use crate::secure_cache::sha256_hex;

use super::{
    dispatch::{JobPriorityV1, RepositorySetRefV1},
    domain::{JobId, SCHEMA_VERSION_V1, ScanSpecV1, Sha256Digest},
};

pub const MAX_SCHEDULES: usize = 1_000;
pub const MAX_SCHEDULE_RUN_AGE_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const STALE_REPOSITORY_SET_REASON: &str = "stale_repository_set";
const MAX_CALENDAR_SEARCH_DAYS: usize = 8 * 366;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ScheduleId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OccurrenceId(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct CronField {
    values: BTreeSet<u32>,
    unrestricted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedCron {
    minute: CronField,
    hour: CronField,
    day_of_month: CronField,
    month: CronField,
    day_of_week: CronField,
}

/// A validated numeric five-field cron expression evaluated exclusively in UTC.
///
/// The minute field must resolve to one value, enforcing the one-hour cadence
/// floor without runtime sampling. Numeric lists, ranges, and steps are
/// supported; names and non-UTC time zones are intentionally excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtcCronV1 {
    expression: String,
    parsed: ParsedCron,
}

impl UtcCronV1 {
    pub fn parse(expression: impl AsRef<str>) -> Result<Self, CronError> {
        let parts = expression.as_ref().split_whitespace().collect::<Vec<_>>();
        if parts.len() != 5 {
            return Err(CronError::InvalidFieldCount);
        }
        let parsed = ParsedCron {
            minute: parse_field(parts[0], 0, 59, false)?,
            hour: parse_field(parts[1], 0, 23, false)?,
            day_of_month: parse_field(parts[2], 1, 31, false)?,
            month: parse_field(parts[3], 1, 12, false)?,
            day_of_week: parse_field(parts[4], 0, 7, true)?,
        };
        if parsed.minute.values.len() != 1 {
            return Err(CronError::CadenceBelowOneHour);
        }
        Ok(Self {
            expression: parts.join(" "),
            parsed,
        })
    }

    pub fn expression(&self) -> &str {
        &self.expression
    }

    pub fn matches(&self, instant: DateTime<Utc>) -> bool {
        instant.second() == 0
            && instant.nanosecond() == 0
            && self.parsed.minute.values.contains(&instant.minute())
            && self.parsed.hour.values.contains(&instant.hour())
            && self.matches_date(instant.date_naive())
    }

    pub fn next_after(&self, instant: DateTime<Utc>) -> Result<DateTime<Utc>, CronError> {
        let mut date = instant.date_naive();
        for _ in 0..=MAX_CALENDAR_SEARCH_DAYS {
            if self.matches_date(date) {
                for hour in &self.parsed.hour.values {
                    for minute in &self.parsed.minute.values {
                        let candidate = date
                            .and_hms_opt(*hour, *minute, 0)
                            .expect("validated cron values form a time")
                            .and_utc();
                        if candidate > instant {
                            return Ok(candidate);
                        }
                    }
                }
            }
            date = date.succ_opt().ok_or(CronError::NoFutureOccurrence)?;
        }
        Err(CronError::NoFutureOccurrence)
    }

    pub fn latest_at_or_before(&self, instant: DateTime<Utc>) -> Result<DateTime<Utc>, CronError> {
        let mut date = instant.date_naive();
        for _ in 0..=MAX_CALENDAR_SEARCH_DAYS {
            if self.matches_date(date) {
                for hour in self.parsed.hour.values.iter().rev() {
                    for minute in self.parsed.minute.values.iter().rev() {
                        let candidate = date
                            .and_hms_opt(*hour, *minute, 0)
                            .expect("validated cron values form a time")
                            .and_utc();
                        if candidate <= instant {
                            return Ok(candidate);
                        }
                    }
                }
            }
            date = date.pred_opt().ok_or(CronError::NoPreviousOccurrence)?;
        }
        Err(CronError::NoPreviousOccurrence)
    }

    fn matches_date(&self, date: NaiveDate) -> bool {
        if !self.parsed.month.values.contains(&date.month()) {
            return false;
        }
        let day_of_month_matches = self.parsed.day_of_month.values.contains(&date.day());
        let day_of_week_matches = self
            .parsed
            .day_of_week
            .values
            .contains(&date.weekday().num_days_from_sunday());
        match (
            self.parsed.day_of_month.unrestricted,
            self.parsed.day_of_week.unrestricted,
        ) {
            (true, true) => true,
            (true, false) => day_of_week_matches,
            (false, true) => day_of_month_matches,
            (false, false) => day_of_month_matches || day_of_week_matches,
        }
    }
}

impl Serialize for UtcCronV1 {
    fn serialize<SerializerT>(
        &self,
        serializer: SerializerT,
    ) -> Result<SerializerT::Ok, SerializerT::Error>
    where
        SerializerT: Serializer,
    {
        CronWireV1 {
            schema_version: SCHEMA_VERSION_V1,
            expression: &self.expression,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UtcCronV1 {
    fn deserialize<DeserializerT>(deserializer: DeserializerT) -> Result<Self, DeserializerT::Error>
    where
        DeserializerT: Deserializer<'de>,
    {
        let wire = OwnedCronWireV1::deserialize(deserializer)?;
        if wire.schema_version != SCHEMA_VERSION_V1 {
            return Err(DeserializerT::Error::custom(format!(
                "unsupported cron schema version {}",
                wire.schema_version
            )));
        }
        Self::parse(wire.expression).map_err(DeserializerT::Error::custom)
    }
}

#[derive(Serialize)]
struct CronWireV1<'a> {
    schema_version: u16,
    expression: &'a str,
}

#[derive(Deserialize)]
struct OwnedCronWireV1 {
    schema_version: u16,
    expression: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SavedInventoryQueryRefV1 {
    pub schema_version: u16,
    pub query_id: String,
    pub revision: u64,
}

impl SavedInventoryQueryRefV1 {
    fn validate(&self) -> Result<(), ScheduleError> {
        validate_schema(self.schema_version)?;
        if !normalized_identifier(&self.query_id) || self.revision == 0 {
            return Err(ScheduleError::InvalidRepositorySource);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositorySourceRefV1 {
    Explicit { repository_set: RepositorySetRefV1 },
    SavedQuery { query: SavedInventoryQueryRefV1 },
}

impl RepositorySourceRefV1 {
    fn validate(&self, spec: &ScanSpecV1) -> Result<(), ScheduleError> {
        match self {
            Self::Explicit { repository_set } => {
                repository_set
                    .validate()
                    .map_err(|error| ScheduleError::InvalidDefinition(error.to_string()))?;
                if repository_set.repository_count == 0
                    || repository_set.repository_count > spec.bounds.repository_limit
                {
                    return Err(ScheduleError::InvalidRepositorySource);
                }
            }
            Self::SavedQuery { query } => query.validate()?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleRevisionV1 {
    pub schema_version: u16,
    pub schedule_id: ScheduleId,
    pub revision: u64,
    pub cron: UtcCronV1,
    pub scan_spec: ScanSpecV1,
    pub repository_source: RepositorySourceRefV1,
    pub priority: JobPriorityV1,
    pub max_run_age_seconds: u64,
    pub created_at: DateTime<Utc>,
}

impl ScheduleRevisionV1 {
    pub fn validate(&self) -> Result<(), ScheduleError> {
        validate_schema(self.schema_version)?;
        validate_schedule_id(&self.schedule_id)?;
        if self.revision == 0
            || self.max_run_age_seconds == 0
            || self.max_run_age_seconds > MAX_SCHEDULE_RUN_AGE_SECONDS
        {
            return Err(ScheduleError::InvalidDefinition(
                "revision must be non-zero and maximum run age must be between one second and one year"
                    .to_owned(),
            ));
        }
        self.scan_spec
            .validate()
            .map_err(|error| ScheduleError::InvalidDefinition(error.to_string()))?;
        self.repository_source.validate(&self.scan_spec)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleDefinitionV1 {
    pub schema_version: u16,
    pub cron: UtcCronV1,
    pub scan_spec: ScanSpecV1,
    pub repository_source: RepositorySourceRefV1,
    pub priority: JobPriorityV1,
    pub max_run_age_seconds: u64,
}

impl ScheduleDefinitionV1 {
    fn into_revision(
        self,
        schedule_id: ScheduleId,
        revision: u64,
        created_at: DateTime<Utc>,
    ) -> Result<ScheduleRevisionV1, ScheduleError> {
        validate_schema(self.schema_version)?;
        let revision = ScheduleRevisionV1 {
            schema_version: SCHEMA_VERSION_V1,
            schedule_id,
            revision,
            cron: self.cron,
            scan_spec: self.scan_spec,
            repository_source: self.repository_source,
            priority: self.priority,
            max_run_age_seconds: self.max_run_age_seconds,
            created_at,
        };
        revision.validate()?;
        Ok(revision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateScheduleV1 {
    pub schema_version: u16,
    pub schedule_id: ScheduleId,
    pub enabled: bool,
    pub definition: ScheduleDefinitionV1,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanScheduleV1 {
    pub schema_version: u16,
    pub id: ScheduleId,
    pub current_revision: u64,
    pub enabled: bool,
    pub next_nominal_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceTriggerV1 {
    Scheduled,
    Manual,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceStateV1 {
    Pending,
    Active,
    Completed,
    Failed,
    Blocked,
    Skipped,
    Superseded,
}

impl OccurrenceStateV1 {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Blocked | Self::Skipped | Self::Superseded
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleOccurrenceV1 {
    pub schema_version: u16,
    pub id: OccurrenceId,
    pub schedule_id: ScheduleId,
    pub schedule_revision: u64,
    pub nominal_at: DateTime<Utc>,
    pub trigger: OccurrenceTriggerV1,
    pub state: OccurrenceStateV1,
    pub job_id: Option<JobId>,
    pub superseded_by: Option<OccurrenceId>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OccurrencePlanV1 {
    pub schema_version: u16,
    pub occurrence: ScheduleOccurrenceV1,
    pub superseded_occurrence: Option<OccurrenceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositorySetSnapshotV1 {
    pub schema_version: u16,
    pub repository_set: RepositorySetRefV1,
    pub inventory_watermark: String,
    pub materialized_at: DateTime<Utc>,
}

impl RepositorySetSnapshotV1 {
    fn validate(&self) -> Result<(), ScheduleError> {
        validate_schema(self.schema_version)?;
        self.repository_set
            .validate()
            .map_err(|error| ScheduleError::InvalidDefinition(error.to_string()))?;
        if !normalized_identifier(&self.inventory_watermark) {
            return Err(ScheduleError::InvalidMaterialization);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedQueryRefreshV1 {
    Complete { snapshot: RepositorySetSnapshotV1 },
    Incomplete { reason_code: String },
    Failed { reason_code: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositorySetProvenanceV1 {
    Explicit,
    FreshQuery,
    StaleLastComplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositorySetSelectionV1 {
    pub schema_version: u16,
    pub repository_set: RepositorySetRefV1,
    pub inventory_watermark: Option<String>,
    pub provenance: RepositorySetProvenanceV1,
    pub selected_at: DateTime<Utc>,
    pub partial_reasons: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum MaterializationDecisionV1 {
    Ready {
        selection: RepositorySetSelectionV1,
    },
    SkippedEmpty {
        provenance: RepositorySetProvenanceV1,
        inventory_watermark: Option<String>,
        partial_reasons: BTreeSet<String>,
    },
    Blocked {
        reason_code: String,
    },
}

/// Resolves an occurrence's repository source without mixing partial results
/// into the last known complete set.
pub fn resolve_repository_source(
    source: &RepositorySourceRefV1,
    refresh: Option<&SavedQueryRefreshV1>,
    last_complete: Option<&RepositorySetSnapshotV1>,
    observed_at: DateTime<Utc>,
) -> Result<MaterializationDecisionV1, ScheduleError> {
    match source {
        RepositorySourceRefV1::Explicit { repository_set } => {
            repository_set
                .validate()
                .map_err(|error| ScheduleError::InvalidDefinition(error.to_string()))?;
            if repository_set.repository_count == 0 {
                return Ok(MaterializationDecisionV1::SkippedEmpty {
                    provenance: RepositorySetProvenanceV1::Explicit,
                    inventory_watermark: None,
                    partial_reasons: BTreeSet::new(),
                });
            }
            Ok(MaterializationDecisionV1::Ready {
                selection: RepositorySetSelectionV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    repository_set: repository_set.clone(),
                    inventory_watermark: None,
                    provenance: RepositorySetProvenanceV1::Explicit,
                    selected_at: observed_at,
                    partial_reasons: BTreeSet::new(),
                },
            })
        }
        RepositorySourceRefV1::SavedQuery { query } => {
            query.validate()?;
            if let Some(SavedQueryRefreshV1::Complete { snapshot }) = refresh {
                snapshot.validate()?;
                return decision_from_snapshot(
                    snapshot,
                    RepositorySetProvenanceV1::FreshQuery,
                    BTreeSet::new(),
                    observed_at,
                );
            }

            let failure_reason = match refresh {
                Some(SavedQueryRefreshV1::Incomplete { reason_code }) => reason_code,
                Some(SavedQueryRefreshV1::Failed { reason_code }) => reason_code,
                Some(SavedQueryRefreshV1::Complete { .. }) => unreachable!("handled above"),
                None => "saved_query_refresh_unavailable",
            };
            if !normalized_reason(failure_reason) {
                return Err(ScheduleError::InvalidMaterialization);
            }
            let Some(snapshot) = last_complete else {
                return Ok(MaterializationDecisionV1::Blocked {
                    reason_code: failure_reason.to_owned(),
                });
            };
            snapshot.validate()?;
            decision_from_snapshot(
                snapshot,
                RepositorySetProvenanceV1::StaleLastComplete,
                BTreeSet::from([
                    STALE_REPOSITORY_SET_REASON.to_owned(),
                    failure_reason.to_owned(),
                ]),
                observed_at,
            )
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleStateV1 {
    pub schema_version: u16,
    pub schedule: ScanScheduleV1,
    pub revisions: Vec<ScheduleRevisionV1>,
    pub occurrences: Vec<ScheduleOccurrenceV1>,
    pub active_occurrence: Option<OccurrenceId>,
    pub pending_occurrence: Option<OccurrenceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerSnapshotV1 {
    pub schema_version: u16,
    pub schedules: Vec<ScheduleStateV1>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerRetentionSummaryV1 {
    pub schedules: usize,
    pub revisions: usize,
    pub occurrences: usize,
}

#[derive(Clone, Debug)]
struct ScheduleEntry {
    schedule: ScanScheduleV1,
    revisions: BTreeMap<u64, ScheduleRevisionV1>,
    occurrences: BTreeMap<OccurrenceId, ScheduleOccurrenceV1>,
    active_occurrence: Option<OccurrenceId>,
    pending_occurrence: Option<OccurrenceId>,
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryScheduler {
    schedules: BTreeMap<ScheduleId, ScheduleEntry>,
}

impl InMemoryScheduler {
    pub fn create(&mut self, request: CreateScheduleV1) -> Result<ScheduleId, ScheduleError> {
        validate_schema(request.schema_version)?;
        validate_schedule_id(&request.schedule_id)?;
        if self.schedules.contains_key(&request.schedule_id) {
            return Err(ScheduleError::ScheduleAlreadyExists);
        }
        if self.schedules.len() >= MAX_SCHEDULES {
            return Err(ScheduleError::ScheduleLimitExceeded);
        }
        let revision =
            request
                .definition
                .into_revision(request.schedule_id.clone(), 1, request.created_at)?;
        let next_nominal_at = request
            .enabled
            .then(|| revision.cron.next_after(request.created_at))
            .transpose()?;
        let schedule = ScanScheduleV1 {
            schema_version: SCHEMA_VERSION_V1,
            id: request.schedule_id.clone(),
            current_revision: 1,
            enabled: request.enabled,
            next_nominal_at,
            created_at: request.created_at,
            updated_at: request.created_at,
            deleted_at: None,
        };
        self.schedules.insert(
            request.schedule_id.clone(),
            ScheduleEntry {
                schedule,
                revisions: BTreeMap::from([(1, revision)]),
                occurrences: BTreeMap::new(),
                active_occurrence: None,
                pending_occurrence: None,
            },
        );
        Ok(request.schedule_id)
    }

    pub fn revise(
        &mut self,
        schedule_id: &ScheduleId,
        expected_revision: u64,
        definition: ScheduleDefinitionV1,
        now: DateTime<Utc>,
    ) -> Result<u64, ScheduleError> {
        let entry = self.entry_mut(schedule_id)?;
        ensure_live(entry)?;
        if entry.schedule.current_revision != expected_revision {
            return Err(ScheduleError::RevisionConflict);
        }
        let revision_number = expected_revision
            .checked_add(1)
            .ok_or(ScheduleError::RevisionOverflow)?;
        let revision = definition.into_revision(schedule_id.clone(), revision_number, now)?;
        let next_nominal_at = entry
            .schedule
            .enabled
            .then(|| revision.cron.next_after(now))
            .transpose()?;
        entry.schedule.current_revision = revision_number;
        entry.schedule.updated_at = now;
        entry.schedule.next_nominal_at = next_nominal_at;
        entry.revisions.insert(revision_number, revision);
        Ok(revision_number)
    }

    pub fn set_enabled(
        &mut self,
        schedule_id: &ScheduleId,
        expected_revision: u64,
        enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<(), ScheduleError> {
        let entry = self.entry_mut(schedule_id)?;
        ensure_live(entry)?;
        if entry.schedule.current_revision != expected_revision {
            return Err(ScheduleError::RevisionConflict);
        }
        if entry.schedule.enabled == enabled {
            return Ok(());
        }
        let next_nominal_at = if enabled {
            Some(current_revision(entry)?.cron.next_after(now)?)
        } else {
            None
        };
        entry.schedule.enabled = enabled;
        entry.schedule.next_nominal_at = next_nominal_at;
        entry.schedule.updated_at = now;
        Ok(())
    }

    pub fn delete(
        &mut self,
        schedule_id: &ScheduleId,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<(), ScheduleError> {
        let entry = self.entry_mut(schedule_id)?;
        if entry.schedule.current_revision != expected_revision {
            return Err(ScheduleError::RevisionConflict);
        }
        if entry.schedule.deleted_at.is_some() {
            return Ok(());
        }
        entry.schedule.deleted_at = Some(now);
        entry.schedule.enabled = false;
        entry.schedule.next_nominal_at = None;
        entry.schedule.updated_at = now;
        Ok(())
    }

    /// Plans at most one newest missed occurrence per enabled schedule.
    pub fn tick(&mut self, now: DateTime<Utc>) -> Result<Vec<OccurrencePlanV1>, ScheduleError> {
        let schedule_ids = self.schedules.keys().cloned().collect::<Vec<_>>();
        let mut planned = Vec::new();
        for schedule_id in schedule_ids {
            let entry = self
                .schedules
                .get_mut(&schedule_id)
                .expect("schedule ID came from the map");
            if !entry.schedule.enabled || entry.schedule.deleted_at.is_some() {
                continue;
            }
            let Some(next_nominal_at) = entry.schedule.next_nominal_at else {
                return Err(ScheduleError::InvalidSnapshot);
            };
            if next_nominal_at > now {
                continue;
            }
            let revision = current_revision(entry)?.clone();
            let latest = revision.cron.latest_at_or_before(now)?;
            if latest < next_nominal_at {
                continue;
            }
            entry.schedule.next_nominal_at = Some(revision.cron.next_after(latest)?);
            entry.schedule.updated_at = now;
            let occurrence = new_occurrence(
                &schedule_id,
                revision.revision,
                latest,
                OccurrenceTriggerV1::Scheduled,
                now,
            );
            planned.push(place_pending(entry, occurrence)?);
        }
        Ok(planned)
    }

    pub fn manual_trigger(
        &mut self,
        schedule_id: &ScheduleId,
        requested_at: DateTime<Utc>,
    ) -> Result<OccurrencePlanV1, ScheduleError> {
        let entry = self.entry_mut(schedule_id)?;
        ensure_live(entry)?;
        let revision = entry.schedule.current_revision;
        let occurrence = new_occurrence(
            schedule_id,
            revision,
            requested_at,
            OccurrenceTriggerV1::Manual,
            requested_at,
        );
        place_pending(entry, occurrence)
    }

    pub fn claim_pending(
        &mut self,
        schedule_id: &ScheduleId,
    ) -> Result<Option<ScheduleOccurrenceV1>, ScheduleError> {
        let entry = self.entry_mut(schedule_id)?;
        if entry.active_occurrence.is_some() {
            return Err(ScheduleError::ActiveOccurrenceExists);
        }
        let Some(occurrence_id) = entry.pending_occurrence.take() else {
            return Ok(None);
        };
        let occurrence = entry
            .occurrences
            .get_mut(&occurrence_id)
            .ok_or(ScheduleError::InvalidSnapshot)?;
        if occurrence.state != OccurrenceStateV1::Pending {
            return Err(ScheduleError::InvalidOccurrenceTransition);
        }
        occurrence.state = OccurrenceStateV1::Active;
        entry.active_occurrence = Some(occurrence_id);
        Ok(Some(occurrence.clone()))
    }

    pub fn attach_job(
        &mut self,
        schedule_id: &ScheduleId,
        occurrence_id: &OccurrenceId,
        job_id: JobId,
    ) -> Result<(), ScheduleError> {
        let entry = self.entry_mut(schedule_id)?;
        if entry.active_occurrence.as_ref() != Some(occurrence_id) {
            return Err(ScheduleError::InvalidOccurrenceTransition);
        }
        let occurrence = entry
            .occurrences
            .get_mut(occurrence_id)
            .ok_or(ScheduleError::OccurrenceNotFound)?;
        match &occurrence.job_id {
            Some(existing) if existing == &job_id => Ok(()),
            Some(_) => Err(ScheduleError::OccurrenceJobConflict),
            None => {
                occurrence.job_id = Some(job_id);
                Ok(())
            }
        }
    }

    pub fn finish_active(
        &mut self,
        schedule_id: &ScheduleId,
        occurrence_id: &OccurrenceId,
        terminal_state: OccurrenceStateV1,
        now: DateTime<Utc>,
    ) -> Result<(), ScheduleError> {
        if !terminal_state.is_terminal() || terminal_state == OccurrenceStateV1::Superseded {
            return Err(ScheduleError::InvalidOccurrenceTransition);
        }
        let entry = self.entry_mut(schedule_id)?;
        if entry.active_occurrence.as_ref() != Some(occurrence_id) {
            let occurrence = entry
                .occurrences
                .get(occurrence_id)
                .ok_or(ScheduleError::OccurrenceNotFound)?;
            return if occurrence.state == terminal_state {
                Ok(())
            } else {
                Err(ScheduleError::InvalidOccurrenceTransition)
            };
        }
        let occurrence = entry
            .occurrences
            .get_mut(occurrence_id)
            .ok_or(ScheduleError::OccurrenceNotFound)?;
        if occurrence.state != OccurrenceStateV1::Active {
            return Err(ScheduleError::InvalidOccurrenceTransition);
        }
        occurrence.state = terminal_state;
        occurrence.finished_at = Some(now);
        entry.active_occurrence = None;
        Ok(())
    }

    pub fn schedule(&self, schedule_id: &ScheduleId) -> Option<&ScanScheduleV1> {
        self.schedules.get(schedule_id).map(|entry| &entry.schedule)
    }

    pub fn revision(&self, schedule_id: &ScheduleId, revision: u64) -> Option<&ScheduleRevisionV1> {
        self.schedules.get(schedule_id)?.revisions.get(&revision)
    }

    pub fn occurrence(
        &self,
        schedule_id: &ScheduleId,
        occurrence_id: &OccurrenceId,
    ) -> Option<&ScheduleOccurrenceV1> {
        self.schedules
            .get(schedule_id)?
            .occurrences
            .get(occurrence_id)
    }

    /// Remove terminal schedule history older than `cutoff` while preserving
    /// every current revision and every revision referenced by retained work.
    pub fn prune_before(&mut self, cutoff: DateTime<Utc>) -> SchedulerRetentionSummaryV1 {
        let mut summary = SchedulerRetentionSummaryV1::default();
        let schedule_ids = self.schedules.keys().cloned().collect::<Vec<_>>();
        for schedule_id in schedule_ids {
            let remove_schedule = {
                let entry = self
                    .schedules
                    .get_mut(&schedule_id)
                    .expect("schedule ID came from the map");
                let before_occurrences = entry.occurrences.len();
                let active_occurrence = entry.active_occurrence.clone();
                let pending_occurrence = entry.pending_occurrence.clone();
                entry.occurrences.retain(|occurrence_id, occurrence| {
                    let pointed_to = active_occurrence.as_ref() == Some(occurrence_id)
                        || pending_occurrence.as_ref() == Some(occurrence_id);
                    pointed_to
                        || !occurrence.state.is_terminal()
                        || occurrence
                            .finished_at
                            .is_none_or(|finished_at| finished_at >= cutoff)
                });
                summary.occurrences += before_occurrences - entry.occurrences.len();

                let referenced_revisions = entry
                    .occurrences
                    .values()
                    .map(|occurrence| occurrence.schedule_revision)
                    .chain(std::iter::once(entry.schedule.current_revision))
                    .collect::<BTreeSet<_>>();
                let before_revisions = entry.revisions.len();
                entry.revisions.retain(|revision_number, revision| {
                    referenced_revisions.contains(revision_number) || revision.created_at >= cutoff
                });
                summary.revisions += before_revisions - entry.revisions.len();

                entry
                    .schedule
                    .deleted_at
                    .is_some_and(|deleted_at| deleted_at < cutoff)
                    && entry.active_occurrence.is_none()
                    && entry.pending_occurrence.is_none()
                    && entry.occurrences.is_empty()
            };
            if remove_schedule && let Some(entry) = self.schedules.remove(&schedule_id) {
                summary.schedules += 1;
                summary.revisions += entry.revisions.len();
                summary.occurrences += entry.occurrences.len();
            }
        }
        summary
    }

    pub fn retained_occurrence_ids(&self) -> BTreeSet<OccurrenceId> {
        self.schedules
            .values()
            .flat_map(|entry| entry.occurrences.keys().cloned())
            .collect()
    }

    /// Execution jobs still referenced by retained schedule history.
    ///
    /// Whole-run retention uses this set so it cannot remove a terminal job
    /// before the scheduler has durably reconciled and retained its occurrence.
    pub fn referenced_job_ids(&self) -> impl Iterator<Item = &JobId> {
        self.schedules
            .values()
            .flat_map(|entry| entry.occurrences.values())
            .filter_map(|occurrence| occurrence.job_id.as_ref())
    }

    pub fn referenced_repository_sets(&self) -> BTreeSet<Sha256Digest> {
        self.schedules
            .values()
            .flat_map(|entry| entry.revisions.values())
            .filter_map(|revision| match &revision.repository_source {
                RepositorySourceRefV1::Explicit { repository_set } => {
                    Some(repository_set.digest.clone())
                }
                RepositorySourceRefV1::SavedQuery { .. } => None,
            })
            .collect()
    }

    pub fn referenced_credential_profiles(&self) -> BTreeSet<String> {
        self.schedules
            .values()
            .flat_map(|entry| entry.revisions.values())
            .filter_map(|revision| revision.scan_spec.credential_profile_id.clone())
            .collect()
    }

    pub fn snapshot(&self) -> SchedulerSnapshotV1 {
        SchedulerSnapshotV1 {
            schema_version: SCHEMA_VERSION_V1,
            schedules: self
                .schedules
                .values()
                .map(|entry| ScheduleStateV1 {
                    schema_version: SCHEMA_VERSION_V1,
                    schedule: entry.schedule.clone(),
                    revisions: entry.revisions.values().cloned().collect(),
                    occurrences: entry.occurrences.values().cloned().collect(),
                    active_occurrence: entry.active_occurrence.clone(),
                    pending_occurrence: entry.pending_occurrence.clone(),
                })
                .collect(),
        }
    }

    pub fn restore(snapshot: SchedulerSnapshotV1) -> Result<Self, ScheduleError> {
        validate_schema(snapshot.schema_version)?;
        if snapshot.schedules.len() > MAX_SCHEDULES {
            return Err(ScheduleError::ScheduleLimitExceeded);
        }
        let mut scheduler = Self::default();
        for state in snapshot.schedules {
            validate_schema(state.schema_version)?;
            validate_schema(state.schedule.schema_version)?;
            validate_schedule_id(&state.schedule.id)?;
            let schedule_id = state.schedule.id.clone();
            if scheduler.schedules.contains_key(&schedule_id) {
                return Err(ScheduleError::InvalidSnapshot);
            }
            let revisions = state
                .revisions
                .into_iter()
                .map(|revision| {
                    revision.validate()?;
                    if revision.schedule_id != schedule_id {
                        return Err(ScheduleError::InvalidSnapshot);
                    }
                    Ok((revision.revision, revision))
                })
                .collect::<Result<BTreeMap<_, _>, ScheduleError>>()?;
            if !revisions.contains_key(&state.schedule.current_revision) {
                return Err(ScheduleError::InvalidSnapshot);
            }
            let occurrences = state
                .occurrences
                .into_iter()
                .map(|occurrence| {
                    if occurrence.schedule_id != schedule_id {
                        return Err(ScheduleError::InvalidSnapshot);
                    }
                    Ok((occurrence.id.clone(), occurrence))
                })
                .collect::<Result<BTreeMap<_, _>, ScheduleError>>()?;
            validate_occurrence_pointer(
                &occurrences,
                state.active_occurrence.as_ref(),
                OccurrenceStateV1::Active,
            )?;
            validate_occurrence_pointer(
                &occurrences,
                state.pending_occurrence.as_ref(),
                OccurrenceStateV1::Pending,
            )?;
            scheduler.schedules.insert(
                schedule_id,
                ScheduleEntry {
                    schedule: state.schedule,
                    revisions,
                    occurrences,
                    active_occurrence: state.active_occurrence,
                    pending_occurrence: state.pending_occurrence,
                },
            );
        }
        Ok(scheduler)
    }

    fn entry_mut(&mut self, schedule_id: &ScheduleId) -> Result<&mut ScheduleEntry, ScheduleError> {
        self.schedules
            .get_mut(schedule_id)
            .ok_or(ScheduleError::ScheduleNotFound)
    }
}

fn place_pending(
    entry: &mut ScheduleEntry,
    mut occurrence: ScheduleOccurrenceV1,
) -> Result<OccurrencePlanV1, ScheduleError> {
    if let Some(existing) = entry.occurrences.get(&occurrence.id) {
        return Ok(OccurrencePlanV1 {
            schema_version: SCHEMA_VERSION_V1,
            occurrence: existing.clone(),
            superseded_occurrence: None,
        });
    }

    let mut superseded_occurrence = None;
    if let Some(existing_id) = entry.pending_occurrence.clone() {
        let existing = entry
            .occurrences
            .get_mut(&existing_id)
            .ok_or(ScheduleError::InvalidSnapshot)?;
        if existing.nominal_at > occurrence.nominal_at {
            occurrence.state = OccurrenceStateV1::Superseded;
            occurrence.superseded_by = Some(existing_id.clone());
            occurrence.finished_at = Some(occurrence.created_at);
        } else {
            existing.state = OccurrenceStateV1::Superseded;
            existing.superseded_by = Some(occurrence.id.clone());
            existing.finished_at = Some(occurrence.created_at);
            entry.pending_occurrence = Some(occurrence.id.clone());
            superseded_occurrence = Some(existing_id);
        }
    } else {
        entry.pending_occurrence = Some(occurrence.id.clone());
    }
    entry
        .occurrences
        .insert(occurrence.id.clone(), occurrence.clone());
    Ok(OccurrencePlanV1 {
        schema_version: SCHEMA_VERSION_V1,
        occurrence,
        superseded_occurrence,
    })
}

fn new_occurrence(
    schedule_id: &ScheduleId,
    revision: u64,
    nominal_at: DateTime<Utc>,
    trigger: OccurrenceTriggerV1,
    created_at: DateTime<Utc>,
) -> ScheduleOccurrenceV1 {
    ScheduleOccurrenceV1 {
        schema_version: SCHEMA_VERSION_V1,
        id: occurrence_id(schedule_id, revision, nominal_at, trigger),
        schedule_id: schedule_id.clone(),
        schedule_revision: revision,
        nominal_at,
        trigger,
        state: OccurrenceStateV1::Pending,
        job_id: None,
        superseded_by: None,
        created_at,
        finished_at: None,
    }
}

fn occurrence_id(
    schedule_id: &ScheduleId,
    revision: u64,
    nominal_at: DateTime<Utc>,
    trigger: OccurrenceTriggerV1,
) -> OccurrenceId {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, schedule_id.0.as_bytes());
    hash_part(&mut hasher, &revision.to_be_bytes());
    hash_part(&mut hasher, &nominal_at.timestamp_micros().to_be_bytes());
    hash_part(
        &mut hasher,
        match trigger {
            OccurrenceTriggerV1::Scheduled => b"scheduled",
            OccurrenceTriggerV1::Manual => b"manual",
        },
    );
    OccurrenceId(format!("occ-{}", sha256_hex(&hasher.finalize())))
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn decision_from_snapshot(
    snapshot: &RepositorySetSnapshotV1,
    provenance: RepositorySetProvenanceV1,
    partial_reasons: BTreeSet<String>,
    observed_at: DateTime<Utc>,
) -> Result<MaterializationDecisionV1, ScheduleError> {
    snapshot.validate()?;
    if snapshot.repository_set.repository_count == 0 {
        return Ok(MaterializationDecisionV1::SkippedEmpty {
            provenance,
            inventory_watermark: Some(snapshot.inventory_watermark.clone()),
            partial_reasons,
        });
    }
    Ok(MaterializationDecisionV1::Ready {
        selection: RepositorySetSelectionV1 {
            schema_version: SCHEMA_VERSION_V1,
            repository_set: snapshot.repository_set.clone(),
            inventory_watermark: Some(snapshot.inventory_watermark.clone()),
            provenance,
            selected_at: observed_at,
            partial_reasons,
        },
    })
}

fn parse_field(
    expression: &str,
    minimum: u32,
    maximum: u32,
    sunday_alias: bool,
) -> Result<CronField, CronError> {
    if expression.is_empty() {
        return Err(CronError::InvalidField(expression.to_owned()));
    }
    let mut values = BTreeSet::new();
    for component in expression.split(',') {
        if component.is_empty() {
            return Err(CronError::InvalidField(expression.to_owned()));
        }
        let (base, step) = match component.split_once('/') {
            Some((base, step)) if !base.is_empty() && !step.is_empty() => {
                let step = parse_number(step, 1, maximum - minimum + 1)?;
                (base, step)
            }
            Some(_) => return Err(CronError::InvalidField(expression.to_owned())),
            None => (component, 1),
        };
        let (start, end) = if base == "*" {
            (minimum, maximum)
        } else if let Some((start, end)) = base.split_once('-') {
            let start = parse_number(start, minimum, maximum)?;
            let end = parse_number(end, minimum, maximum)?;
            if start > end {
                return Err(CronError::InvalidField(expression.to_owned()));
            }
            (start, end)
        } else {
            let start = parse_number(base, minimum, maximum)?;
            let end = if component.contains('/') {
                maximum
            } else {
                start
            };
            (start, end)
        };
        for value in start..=end {
            if (value - start) % step == 0 {
                values.insert(if sunday_alias && value == 7 { 0 } else { value });
            }
        }
    }
    if values.is_empty() {
        return Err(CronError::InvalidField(expression.to_owned()));
    }
    let domain_size = if sunday_alias {
        7
    } else {
        maximum - minimum + 1
    };
    Ok(CronField {
        unrestricted: values.len() == domain_size as usize,
        values,
    })
}

fn parse_number(value: &str, minimum: u32, maximum: u32) -> Result<u32, CronError> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| CronError::InvalidField(value.to_owned()))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(CronError::InvalidField(value.to_owned()));
    }
    Ok(parsed)
}

fn current_revision(entry: &ScheduleEntry) -> Result<&ScheduleRevisionV1, ScheduleError> {
    entry
        .revisions
        .get(&entry.schedule.current_revision)
        .ok_or(ScheduleError::InvalidSnapshot)
}

fn ensure_live(entry: &ScheduleEntry) -> Result<(), ScheduleError> {
    if entry.schedule.deleted_at.is_some() {
        return Err(ScheduleError::ScheduleDeleted);
    }
    Ok(())
}

fn validate_schema(schema_version: u16) -> Result<(), ScheduleError> {
    if schema_version != SCHEMA_VERSION_V1 {
        return Err(ScheduleError::UnsupportedSchemaVersion(schema_version));
    }
    Ok(())
}

fn validate_schedule_id(schedule_id: &ScheduleId) -> Result<(), ScheduleError> {
    if !normalized_identifier(&schedule_id.0) {
        return Err(ScheduleError::InvalidScheduleId);
    }
    Ok(())
}

fn validate_occurrence_pointer(
    occurrences: &BTreeMap<OccurrenceId, ScheduleOccurrenceV1>,
    occurrence_id: Option<&OccurrenceId>,
    expected_state: OccurrenceStateV1,
) -> Result<(), ScheduleError> {
    if let Some(occurrence_id) = occurrence_id
        && occurrences
            .get(occurrence_id)
            .is_none_or(|occurrence| occurrence.state != expected_state)
    {
        return Err(ScheduleError::InvalidSnapshot);
    }
    Ok(())
}

fn normalized_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.trim() == value
}

fn normalized_reason(value: &str) -> bool {
    normalized_identifier(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CronError {
    InvalidFieldCount,
    InvalidField(String),
    CadenceBelowOneHour,
    NoFutureOccurrence,
    NoPreviousOccurrence,
}

impl std::fmt::Display for CronError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CronError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScheduleError {
    Cron(CronError),
    UnsupportedSchemaVersion(u16),
    InvalidScheduleId,
    InvalidDefinition(String),
    InvalidRepositorySource,
    InvalidMaterialization,
    ScheduleAlreadyExists,
    ScheduleNotFound,
    ScheduleDeleted,
    ScheduleLimitExceeded,
    RevisionConflict,
    RevisionOverflow,
    OccurrenceNotFound,
    ActiveOccurrenceExists,
    OccurrenceJobConflict,
    InvalidOccurrenceTransition,
    InvalidSnapshot,
}

impl From<CronError> for ScheduleError {
    fn from(error: CronError) -> Self {
        Self::Cron(error)
    }
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ScheduleError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::dispatch::DEFAULT_MAX_RUN_AGE_SECONDS;
    use crate::coordinator::domain::{RepositoryScopeV1, ScanBoundsV1, ScanTargetV1, Sha256Digest};
    use chrono::TimeZone;

    fn time(day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, day, hour, minute, 0).unwrap()
    }

    fn spec() -> ScanSpecV1 {
        ScanSpecV1 {
            schema_version: SCHEMA_VERSION_V1,
            target: ScanTargetV1 {
                crate_name: "fs2".to_owned(),
                version_spec: "=0.4.3".to_owned(),
            },
            repository_scope: RepositoryScopeV1::PublicOnly,
            credential_profile_id: None,
            bounds: ScanBoundsV1::default(),
            analyzer_versions: BTreeMap::new(),
        }
    }

    fn set(digit: char, count: u64) -> RepositorySetRefV1 {
        RepositorySetRefV1 {
            schema_version: SCHEMA_VERSION_V1,
            digest: Sha256Digest::parse(digit.to_string().repeat(64)).unwrap(),
            repository_count: count,
        }
    }

    fn definition(cron: &str) -> ScheduleDefinitionV1 {
        ScheduleDefinitionV1 {
            schema_version: SCHEMA_VERSION_V1,
            cron: UtcCronV1::parse(cron).unwrap(),
            scan_spec: spec(),
            repository_source: RepositorySourceRefV1::Explicit {
                repository_set: set('a', 3),
            },
            priority: JobPriorityV1::Normal,
            max_run_age_seconds: DEFAULT_MAX_RUN_AGE_SECONDS,
        }
    }

    fn scheduler(cron: &str) -> InMemoryScheduler {
        let mut scheduler = InMemoryScheduler::default();
        scheduler
            .create(CreateScheduleV1 {
                schema_version: SCHEMA_VERSION_V1,
                schedule_id: ScheduleId("hourly".to_owned()),
                enabled: true,
                definition: definition(cron),
                created_at: time(1, 0, 1),
            })
            .unwrap();
        scheduler
    }

    #[test]
    fn cron_enforces_hourly_floor_and_round_trips() {
        assert_eq!(
            UtcCronV1::parse("0,30 * * * *"),
            Err(CronError::CadenceBelowOneHour)
        );
        let cron = UtcCronV1::parse("0 */2 * * 0-6").unwrap();
        let encoded = serde_json::to_string(&cron).unwrap();
        let decoded: UtcCronV1 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, cron);
        assert_eq!(cron.next_after(time(1, 0, 30)).unwrap(), time(1, 2, 0));
    }

    #[test]
    fn cron_uses_standard_dom_or_dow_semantics() {
        let cron = UtcCronV1::parse("0 12 31 * 1").unwrap();
        let monday = Utc.with_ymd_and_hms(2026, 8, 3, 12, 0, 0).unwrap();
        let month_end = Utc.with_ymd_and_hms(2026, 8, 31, 12, 0, 0).unwrap();
        assert!(cron.matches(monday));
        assert!(cron.matches(month_end));
    }

    #[test]
    fn tick_coalesces_missed_and_overlapping_occurrences() {
        let mut scheduler = scheduler("0 * * * *");
        let first = scheduler.tick(time(1, 5, 15)).unwrap().pop().unwrap();
        assert_eq!(first.occurrence.nominal_at, time(1, 5, 0));
        let active = scheduler
            .claim_pending(&ScheduleId("hourly".to_owned()))
            .unwrap()
            .unwrap();
        assert_eq!(active.id, first.occurrence.id);

        let pending = scheduler.tick(time(1, 8, 10)).unwrap().pop().unwrap();
        assert_eq!(pending.occurrence.nominal_at, time(1, 8, 0));
        assert_eq!(
            scheduler
                .occurrence(&ScheduleId("hourly".to_owned()), &active.id)
                .unwrap()
                .state,
            OccurrenceStateV1::Active
        );
        let newer = scheduler.tick(time(1, 10, 1)).unwrap().pop().unwrap();
        assert_eq!(newer.occurrence.nominal_at, time(1, 10, 0));
        assert_eq!(newer.superseded_occurrence, Some(pending.occurrence.id));
    }

    #[test]
    fn retention_job_references_match_retained_occurrences() {
        let mut scheduler = scheduler("0 * * * *");
        let schedule_id = ScheduleId("hourly".to_owned());

        let old = scheduler
            .manual_trigger(&schedule_id, time(1, 1, 0))
            .unwrap()
            .occurrence;
        scheduler.claim_pending(&schedule_id).unwrap();
        scheduler
            .attach_job(&schedule_id, &old.id, JobId("old-job".to_owned()))
            .unwrap();
        scheduler
            .finish_active(
                &schedule_id,
                &old.id,
                OccurrenceStateV1::Completed,
                time(1, 2, 0),
            )
            .unwrap();

        let recent = scheduler
            .manual_trigger(&schedule_id, time(2, 1, 0))
            .unwrap()
            .occurrence;
        scheduler.claim_pending(&schedule_id).unwrap();
        scheduler
            .attach_job(&schedule_id, &recent.id, JobId("recent-job".to_owned()))
            .unwrap();
        scheduler
            .finish_active(
                &schedule_id,
                &recent.id,
                OccurrenceStateV1::Completed,
                time(2, 2, 0),
            )
            .unwrap();

        let active = scheduler
            .manual_trigger(&schedule_id, time(3, 1, 0))
            .unwrap()
            .occurrence;
        scheduler.claim_pending(&schedule_id).unwrap();
        scheduler
            .attach_job(&schedule_id, &active.id, JobId("active-job".to_owned()))
            .unwrap();

        scheduler.prune_before(time(2, 2, 0));
        assert_eq!(
            scheduler
                .referenced_job_ids()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                JobId("active-job".to_owned()),
                JobId("recent-job".to_owned()),
            ])
        );
        assert!(scheduler.occurrence(&schedule_id, &old.id).is_none());
        assert!(scheduler.occurrence(&schedule_id, &recent.id).is_some());
        assert!(scheduler.occurrence(&schedule_id, &active.id).is_some());
    }

    #[test]
    fn revision_only_changes_future_nominal_times() {
        let mut scheduler = scheduler("0 * * * *");
        let old = scheduler.tick(time(1, 1, 1)).unwrap().pop().unwrap();
        let revision = scheduler
            .revise(
                &ScheduleId("hourly".to_owned()),
                1,
                definition("30 2 * * *"),
                time(1, 1, 5),
            )
            .unwrap();
        assert_eq!(revision, 2);
        assert_eq!(old.occurrence.schedule_revision, 1);
        assert!(scheduler.tick(time(1, 2, 29)).unwrap().is_empty());
        let new = scheduler.tick(time(1, 2, 30)).unwrap().pop().unwrap();
        assert_eq!(new.occurrence.schedule_revision, 2);
    }

    #[test]
    fn stale_last_complete_is_explicit_and_empty_sets_skip() {
        let source = RepositorySourceRefV1::SavedQuery {
            query: SavedInventoryQueryRefV1 {
                schema_version: SCHEMA_VERSION_V1,
                query_id: "linux-consumers".to_owned(),
                revision: 4,
            },
        };
        let last_complete = RepositorySetSnapshotV1 {
            schema_version: SCHEMA_VERSION_V1,
            repository_set: set('b', 2),
            inventory_watermark: "watermark-17".to_owned(),
            materialized_at: time(1, 0, 0),
        };
        let refresh = SavedQueryRefreshV1::Incomplete {
            reason_code: "projection_lag".to_owned(),
        };
        let decision =
            resolve_repository_source(&source, Some(&refresh), Some(&last_complete), time(1, 1, 0))
                .unwrap();
        let MaterializationDecisionV1::Ready { selection } = decision else {
            panic!("last complete set should be selected");
        };
        assert_eq!(
            selection.provenance,
            RepositorySetProvenanceV1::StaleLastComplete
        );
        assert!(
            selection
                .partial_reasons
                .contains(STALE_REPOSITORY_SET_REASON)
        );

        let empty = RepositorySetSnapshotV1 {
            repository_set: set('c', 0),
            ..last_complete
        };
        assert!(matches!(
            resolve_repository_source(
                &source,
                Some(&SavedQueryRefreshV1::Complete { snapshot: empty }),
                None,
                time(1, 1, 0)
            )
            .unwrap(),
            MaterializationDecisionV1::SkippedEmpty { .. }
        ));
    }

    #[test]
    fn no_complete_set_blocks_failed_saved_query() {
        let source = RepositorySourceRefV1::SavedQuery {
            query: SavedInventoryQueryRefV1 {
                schema_version: SCHEMA_VERSION_V1,
                query_id: "all".to_owned(),
                revision: 1,
            },
        };
        assert!(matches!(
            resolve_repository_source(
                &source,
                Some(&SavedQueryRefreshV1::Failed {
                    reason_code: "database_unavailable".to_owned()
                }),
                None,
                time(1, 0, 0)
            )
            .unwrap(),
            MaterializationDecisionV1::Blocked { reason_code }
                if reason_code == "database_unavailable"
        ));
    }

    #[test]
    fn snapshot_restore_preserves_active_and_pending_occurrences() {
        let mut scheduler = scheduler("0 * * * *");
        scheduler.tick(time(1, 1, 0)).unwrap();
        scheduler
            .claim_pending(&ScheduleId("hourly".to_owned()))
            .unwrap();
        scheduler.tick(time(1, 2, 0)).unwrap();
        let snapshot = scheduler.snapshot();
        let restored = InMemoryScheduler::restore(snapshot.clone()).unwrap();
        assert_eq!(restored.snapshot(), snapshot);
    }
}
