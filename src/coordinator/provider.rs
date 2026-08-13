use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::domain::{PermitId, RepositoryScopeV1};

const GITHUB_REPOSITORY_ANALYSIS_MAX_IN_FLIGHT: u32 = 16;
const GITHUB_REPOSITORY_ANALYSIS_PERMIT_TTL_SECONDS: u64 = 10 * 60;
const PUBLIC_GITHUB_PRINCIPAL: &str = "public";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProviderKeyV1 {
    pub provider: String,
    pub principal_id: String,
    pub resource: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitPolicyV1 {
    pub failure_threshold: u32,
    pub failure_window_seconds: u64,
    pub initial_cooldown_seconds: u64,
    pub maximum_cooldown_seconds: u64,
}

impl Default for CircuitPolicyV1 {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            failure_window_seconds: 30,
            initial_cooldown_seconds: 30,
            maximum_cooldown_seconds: 5 * 60,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPolicyV1 {
    pub max_in_flight: u32,
    pub minimum_interval_millis: u64,
    pub permit_ttl_seconds: u64,
    pub circuit: CircuitPolicyV1,
}

impl ProviderPolicyV1 {
    /// Shared admission policy for one GitHub credential and repository scope.
    ///
    /// A permit covers one repository-analysis attempt. GitHub performs its
    /// own rate limiting, so this gate only bounds concurrent attempts and
    /// propagates observed provider cooldowns.
    pub fn github_repository_analysis() -> Self {
        Self {
            max_in_flight: GITHUB_REPOSITORY_ANALYSIS_MAX_IN_FLIGHT,
            minimum_interval_millis: 0,
            permit_ttl_seconds: GITHUB_REPOSITORY_ANALYSIS_PERMIT_TTL_SECONDS,
            circuit: CircuitPolicyV1::default(),
        }
    }

    pub fn crates_io_api() -> Self {
        Self {
            max_in_flight: 1,
            minimum_interval_millis: 1_000,
            permit_ttl_seconds: 60,
            circuit: CircuitPolicyV1::default(),
        }
    }

    pub fn crates_io_sparse_index() -> Self {
        Self {
            max_in_flight: 8,
            minimum_interval_millis: 0,
            permit_ttl_seconds: 60,
            circuit: CircuitPolicyV1::default(),
        }
    }
}

impl ProviderKeyV1 {
    /// Stable key shared by job submission and workers for GitHub repository
    /// analysis.
    ///
    /// Public unauthenticated work shares a conservative principal.
    /// Credentialed work is isolated by the operator-supplied profile
    /// identifier, while the resource dimension prevents public and
    /// all-visible work from sharing rate or circuit state.
    pub fn github_repository_analysis(
        scope: RepositoryScopeV1,
        credential_profile_id: Option<&str>,
    ) -> Self {
        let scope = match scope {
            RepositoryScopeV1::PublicOnly => "public_only",
            RepositoryScopeV1::AllVisible => "all_visible",
        };
        Self {
            provider: "github".to_owned(),
            principal_id: credential_profile_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(PUBLIC_GITHUB_PRINCIPAL)
                .to_owned(),
            resource: format!("repository_analysis:{scope}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CircuitPhaseV1 {
    Closed,
    Open {
        until: DateTime<Utc>,
        cooldown_seconds: u64,
    },
    HalfOpen {
        cooldown_seconds: u64,
        probe_permit_id: Option<PermitId>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderRateStateV1 {
    pub next_allowed_at: Option<DateTime<Utc>>,
    pub blocked_until: Option<DateTime<Utc>>,
    pub remaining: Option<u64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub circuit_phase: CircuitPhaseV1,
    pub recent_failures: Vec<DateTime<Utc>>,
}

impl Default for ProviderRateStateV1 {
    fn default() -> Self {
        Self {
            next_allowed_at: None,
            blocked_until: None,
            remaining: None,
            reset_at: None,
            circuit_phase: CircuitPhaseV1::Closed,
            recent_failures: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderPermitV1 {
    pub id: PermitId,
    pub key: ProviderKeyV1,
    pub agent_id: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub half_open_probe: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOutcomeClassV1 {
    Success,
    TransportFailure,
    Timeout,
    RateLimited,
    ServerError,
    AuthorizationError,
    NotFound,
    OtherClientError,
}

impl ProviderOutcomeClassV1 {
    fn qualifies_for_circuit(self) -> bool {
        matches!(
            self,
            Self::TransportFailure | Self::Timeout | Self::RateLimited | Self::ServerError
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RateLimitObservationV1 {
    pub remaining: Option<u64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PermitDecision {
    Granted(ProviderPermitV1),
    WaitUntil(DateTime<Utc>),
    CapacityExhausted,
    HalfOpenProbeInFlight,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProviderEntry {
    policy: ProviderPolicyV1,
    rate: ProviderRateStateV1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProviderGate {
    providers: BTreeMap<ProviderKeyV1, ProviderEntry>,
    active_permits: BTreeMap<PermitId, ProviderPermitV1>,
    completed_permits: BTreeSet<PermitId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProviderGateSnapshotV1 {
    providers: Vec<(ProviderKeyV1, ProviderEntry)>,
    active_permits: Vec<ProviderPermitV1>,
    completed_permits: Vec<PermitId>,
}

impl ProviderGate {
    pub(crate) fn snapshot(&self) -> ProviderGateSnapshotV1 {
        ProviderGateSnapshotV1 {
            providers: self
                .providers
                .iter()
                .map(|(key, entry)| (key.clone(), entry.clone()))
                .collect(),
            active_permits: self.active_permits.values().cloned().collect(),
            completed_permits: self.completed_permits.iter().cloned().collect(),
        }
    }

    pub(crate) fn from_snapshot(snapshot: ProviderGateSnapshotV1) -> Result<Self, ProviderError> {
        let mut gate = Self::default();
        for (key, entry) in snapshot.providers {
            validate_policy(entry.policy)?;
            if gate.providers.insert(key, entry).is_some() {
                return Err(ProviderError::InvalidSnapshot);
            }
        }
        for permit in snapshot.active_permits {
            if !gate.providers.contains_key(&permit.key)
                || gate
                    .active_permits
                    .insert(permit.id.clone(), permit)
                    .is_some()
            {
                return Err(ProviderError::InvalidSnapshot);
            }
        }
        for permit_id in snapshot.completed_permits {
            if gate.active_permits.contains_key(&permit_id)
                || !gate.completed_permits.insert(permit_id)
            {
                return Err(ProviderError::InvalidSnapshot);
            }
        }
        Ok(gate)
    }

    pub fn configure(
        &mut self,
        key: ProviderKeyV1,
        policy: ProviderPolicyV1,
    ) -> Result<(), ProviderError> {
        validate_policy(policy)?;
        match self.providers.get(&key) {
            Some(existing) if existing.policy == policy => Ok(()),
            Some(_) => Err(ProviderError::ConflictingPolicy),
            None => {
                self.providers.insert(
                    key,
                    ProviderEntry {
                        policy,
                        rate: ProviderRateStateV1::default(),
                    },
                );
                Ok(())
            }
        }
    }

    pub fn state(&self, key: &ProviderKeyV1) -> Option<&ProviderRateStateV1> {
        self.providers.get(key).map(|entry| &entry.rate)
    }

    pub fn acquire(
        &mut self,
        key: &ProviderKeyV1,
        permit_id: PermitId,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<PermitDecision, ProviderError> {
        self.reclaim_expired_permits(now);
        if let Some(permit) = self.active_permits.get(&permit_id) {
            if &permit.key == key && permit.agent_id == agent_id {
                return Ok(PermitDecision::Granted(permit.clone()));
            }
            return Err(ProviderError::PermitIdConflict);
        }
        if self.completed_permits.contains(&permit_id) {
            return Err(ProviderError::PermitAlreadyFinished);
        }

        let active_for_key = self
            .active_permits
            .values()
            .filter(|permit| &permit.key == key)
            .count();
        let entry = self
            .providers
            .get_mut(key)
            .ok_or(ProviderError::UnknownProvider)?;

        refresh_circuit_phase(&mut entry.rate, now);
        match &entry.rate.circuit_phase {
            CircuitPhaseV1::Open { until, .. } => {
                let until = effective_wait_until(&entry.rate, now)
                    .map_or(*until, |rate_until| rate_until.max(*until));
                return Ok(PermitDecision::WaitUntil(until));
            }
            CircuitPhaseV1::HalfOpen {
                probe_permit_id: Some(_),
                ..
            } => return Ok(PermitDecision::HalfOpenProbeInFlight),
            CircuitPhaseV1::Closed | CircuitPhaseV1::HalfOpen { .. } => {}
        }

        if let Some(until) = effective_wait_until(&entry.rate, now) {
            return Ok(PermitDecision::WaitUntil(until));
        }
        if active_for_key >= entry.policy.max_in_flight as usize {
            return Ok(PermitDecision::CapacityExhausted);
        }

        let half_open_probe = matches!(
            &entry.rate.circuit_phase,
            CircuitPhaseV1::HalfOpen {
                probe_permit_id: None,
                ..
            }
        );
        let expires_at = checked_add_seconds(now, entry.policy.permit_ttl_seconds);
        let permit = ProviderPermitV1 {
            id: permit_id.clone(),
            key: key.clone(),
            agent_id: agent_id.to_owned(),
            granted_at: now,
            expires_at,
            half_open_probe,
        };
        if half_open_probe
            && let CircuitPhaseV1::HalfOpen {
                probe_permit_id, ..
            } = &mut entry.rate.circuit_phase
        {
            *probe_permit_id = Some(permit_id.clone());
        }
        if entry.policy.minimum_interval_millis != 0 {
            entry.rate.next_allowed_at = Some(checked_add_millis(
                now,
                entry.policy.minimum_interval_millis,
            ));
        }
        self.active_permits.insert(permit_id, permit.clone());
        Ok(PermitDecision::Granted(permit))
    }

    pub fn finish(
        &mut self,
        permit_id: &PermitId,
        agent_id: &str,
        outcome: ProviderOutcomeClassV1,
        observation: &RateLimitObservationV1,
        now: DateTime<Utc>,
    ) -> Result<(), ProviderError> {
        self.reclaim_expired_permits(now);
        if self.completed_permits.contains(permit_id) {
            return Ok(());
        }
        let permit = self
            .active_permits
            .get(permit_id)
            .ok_or(ProviderError::UnknownPermit)?;
        if permit.agent_id != agent_id {
            return Err(ProviderError::PermitOwnerMismatch);
        }
        let permit = self
            .active_permits
            .remove(permit_id)
            .expect("permit ownership was just validated");
        let entry = self
            .providers
            .get_mut(&permit.key)
            .expect("permits are only created for configured providers");

        apply_rate_observation(&mut entry.rate, observation, now);
        update_circuit(&mut entry.rate, entry.policy.circuit, outcome, now);
        self.completed_permits.insert(permit_id.clone());
        Ok(())
    }

    pub fn reclaim_expired_permits(&mut self, now: DateTime<Utc>) -> Vec<PermitId> {
        let expired = self
            .active_permits
            .values()
            .filter(|permit| permit.expires_at <= now)
            .map(|permit| permit.id.clone())
            .collect::<Vec<_>>();
        for permit_id in &expired {
            if let Some(permit) = self.active_permits.remove(permit_id)
                && permit.half_open_probe
                && let Some(entry) = self.providers.get_mut(&permit.key)
            {
                update_circuit(
                    &mut entry.rate,
                    entry.policy.circuit,
                    ProviderOutcomeClassV1::Timeout,
                    now,
                );
            }
            self.completed_permits.insert(permit_id.clone());
        }
        expired
    }
}

fn validate_policy(policy: ProviderPolicyV1) -> Result<(), ProviderError> {
    let circuit = policy.circuit;
    if policy.max_in_flight == 0
        || policy.permit_ttl_seconds == 0
        || circuit.failure_threshold == 0
        || circuit.failure_window_seconds == 0
        || circuit.initial_cooldown_seconds == 0
        || circuit.initial_cooldown_seconds > circuit.maximum_cooldown_seconds
    {
        return Err(ProviderError::InvalidPolicy);
    }
    Ok(())
}

fn refresh_circuit_phase(rate: &mut ProviderRateStateV1, now: DateTime<Utc>) {
    let (until, cooldown_seconds) = match &rate.circuit_phase {
        CircuitPhaseV1::Open {
            until,
            cooldown_seconds,
        } => (*until, *cooldown_seconds),
        CircuitPhaseV1::Closed | CircuitPhaseV1::HalfOpen { .. } => return,
    };
    if until <= now {
        rate.circuit_phase = CircuitPhaseV1::HalfOpen {
            cooldown_seconds,
            probe_permit_id: None,
        };
    }
}

fn effective_wait_until(rate: &ProviderRateStateV1, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    [rate.next_allowed_at, rate.blocked_until]
        .into_iter()
        .flatten()
        .filter(|instant| *instant > now)
        .max()
}

fn apply_rate_observation(
    rate: &mut ProviderRateStateV1,
    observation: &RateLimitObservationV1,
    now: DateTime<Utc>,
) {
    rate.remaining = observation.remaining.or(rate.remaining);
    rate.reset_at = observation.reset_at.or(rate.reset_at);
    if observation.remaining == Some(0)
        && let Some(reset_at) = observation.reset_at
    {
        rate.blocked_until = Some(max_instant(rate.blocked_until, reset_at));
    }
    if let Some(seconds) = observation.retry_after_seconds {
        let retry_at = checked_add_seconds(now, seconds);
        rate.blocked_until = Some(max_instant(rate.blocked_until, retry_at));
    }
}

fn update_circuit(
    rate: &mut ProviderRateStateV1,
    policy: CircuitPolicyV1,
    outcome: ProviderOutcomeClassV1,
    now: DateTime<Utc>,
) {
    if let CircuitPhaseV1::HalfOpen {
        cooldown_seconds, ..
    } = &rate.circuit_phase
    {
        let cooldown_seconds = *cooldown_seconds;
        if outcome.qualifies_for_circuit() {
            let next_cooldown = cooldown_seconds
                .saturating_mul(2)
                .min(policy.maximum_cooldown_seconds);
            open_circuit(rate, now, next_cooldown);
        } else {
            close_circuit(rate);
        }
        return;
    }

    let window =
        TimeDelta::seconds(i64::try_from(policy.failure_window_seconds).unwrap_or(i64::MAX));
    let cutoff = now
        .checked_sub_signed(window)
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    rate.recent_failures
        .retain(|failure| *failure >= cutoff && *failure <= now);
    if !outcome.qualifies_for_circuit() {
        return;
    }
    rate.recent_failures.push(now);
    if rate.recent_failures.len() >= policy.failure_threshold as usize {
        open_circuit(rate, now, policy.initial_cooldown_seconds);
    }
}

fn open_circuit(rate: &mut ProviderRateStateV1, now: DateTime<Utc>, cooldown_seconds: u64) {
    rate.circuit_phase = CircuitPhaseV1::Open {
        until: checked_add_seconds(now, cooldown_seconds),
        cooldown_seconds,
    };
    rate.recent_failures.clear();
}

fn close_circuit(rate: &mut ProviderRateStateV1) {
    rate.circuit_phase = CircuitPhaseV1::Closed;
    rate.recent_failures.clear();
}

fn checked_add_seconds(now: DateTime<Utc>, seconds: u64) -> DateTime<Utc> {
    let seconds = i64::try_from(seconds).unwrap_or(i64::MAX);
    now.checked_add_signed(TimeDelta::seconds(seconds))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

fn checked_add_millis(now: DateTime<Utc>, millis: u64) -> DateTime<Utc> {
    let millis = i64::try_from(millis).unwrap_or(i64::MAX);
    now.checked_add_signed(TimeDelta::milliseconds(millis))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

fn max_instant(current: Option<DateTime<Utc>>, candidate: DateTime<Utc>) -> DateTime<Utc> {
    current.map_or(candidate, |current| current.max(candidate))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderError {
    UnknownProvider,
    UnknownPermit,
    PermitOwnerMismatch,
    InvalidPolicy,
    ConflictingPolicy,
    PermitIdConflict,
    PermitAlreadyFinished,
    InvalidSnapshot,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProviderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn time(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
            .unwrap()
            .checked_add_signed(TimeDelta::seconds(i64::from(second)))
            .unwrap()
    }

    fn key() -> ProviderKeyV1 {
        ProviderKeyV1 {
            provider: "crates.io".to_owned(),
            principal_id: "installation".to_owned(),
            resource: "api".to_owned(),
        }
    }

    fn permit(value: u32) -> PermitId {
        PermitId(format!("permit-{value}"))
    }

    fn finish_failure(gate: &mut ProviderGate, value: u32, at: u32) {
        let key = key();
        let decision = gate
            .acquire(&key, permit(value), "agent", time(at))
            .unwrap();
        assert!(matches!(decision, PermitDecision::Granted(_)));
        gate.finish(
            &permit(value),
            "agent",
            ProviderOutcomeClassV1::ServerError,
            &RateLimitObservationV1::default(),
            time(at),
        )
        .unwrap();
    }

    #[test]
    fn one_request_per_second_is_global() {
        let mut gate = ProviderGate::default();
        gate.configure(key(), ProviderPolicyV1::crates_io_api())
            .unwrap();
        let first = gate.acquire(&key(), permit(1), "agent-a", time(0)).unwrap();
        assert!(matches!(first, PermitDecision::Granted(_)));
        gate.finish(
            &permit(1),
            "agent-a",
            ProviderOutcomeClassV1::Success,
            &RateLimitObservationV1::default(),
            time(0),
        )
        .unwrap();
        assert_eq!(
            gate.acquire(&key(), permit(2), "agent-b", time(0)).unwrap(),
            PermitDecision::WaitUntil(time(1))
        );
    }

    #[test]
    fn circuit_opens_after_five_qualifying_failures() {
        let mut gate = ProviderGate::default();
        gate.configure(
            key(),
            ProviderPolicyV1 {
                minimum_interval_millis: 0,
                ..ProviderPolicyV1::crates_io_api()
            },
        )
        .unwrap();
        for value in 0..5 {
            finish_failure(&mut gate, value, value);
        }
        assert_eq!(
            gate.acquire(&key(), permit(5), "agent", time(5)).unwrap(),
            PermitDecision::WaitUntil(time(34))
        );
    }

    #[test]
    fn half_open_allows_one_probe_and_doubles_failed_cooldown() {
        let mut gate = ProviderGate::default();
        gate.configure(
            key(),
            ProviderPolicyV1 {
                max_in_flight: 8,
                minimum_interval_millis: 0,
                ..ProviderPolicyV1::crates_io_api()
            },
        )
        .unwrap();
        for value in 0..5 {
            finish_failure(&mut gate, value, value);
        }
        let probe = gate
            .acquire(&key(), permit(5), "agent-a", time(34))
            .unwrap();
        assert!(matches!(probe, PermitDecision::Granted(_)));
        assert_eq!(
            gate.acquire(&key(), permit(6), "agent-b", time(34))
                .unwrap(),
            PermitDecision::HalfOpenProbeInFlight
        );
        gate.finish(
            &permit(5),
            "agent-a",
            ProviderOutcomeClassV1::Timeout,
            &RateLimitObservationV1::default(),
            time(34),
        )
        .unwrap();
        assert_eq!(
            gate.acquire(&key(), permit(7), "agent", time(35)).unwrap(),
            PermitDecision::WaitUntil(time(94))
        );
    }

    #[test]
    fn authorization_errors_do_not_trip_the_circuit() {
        let mut gate = ProviderGate::default();
        gate.configure(
            key(),
            ProviderPolicyV1 {
                minimum_interval_millis: 0,
                ..ProviderPolicyV1::crates_io_api()
            },
        )
        .unwrap();
        for value in 0..10 {
            gate.acquire(&key(), permit(value), "agent", time(value))
                .unwrap();
            gate.finish(
                &permit(value),
                "agent",
                ProviderOutcomeClassV1::AuthorizationError,
                &RateLimitObservationV1::default(),
                time(value),
            )
            .unwrap();
        }
        assert!(matches!(
            &gate.state(&key()).unwrap().circuit_phase,
            CircuitPhaseV1::Closed
        ));
    }

    #[test]
    fn github_repository_analysis_policy_has_fixed_bounded_concurrency() {
        let policy = ProviderPolicyV1::github_repository_analysis();
        assert_eq!(policy.max_in_flight, 16);
        assert_eq!(policy.minimum_interval_millis, 0);
        assert_eq!(policy.permit_ttl_seconds, 600);
        validate_policy(policy).unwrap();
    }

    #[test]
    fn github_repository_analysis_keys_isolate_scope_and_principal() {
        let public = ProviderKeyV1::github_repository_analysis(RepositoryScopeV1::PublicOnly, None);
        let private = ProviderKeyV1::github_repository_analysis(
            RepositoryScopeV1::AllVisible,
            Some(" installation-42 "),
        );

        assert_eq!(public.provider, "github");
        assert_eq!(public.principal_id, "public");
        assert_eq!(public.resource, "repository_analysis:public_only");
        assert_eq!(private.principal_id, "installation-42");
        assert_eq!(private.resource, "repository_analysis:all_visible");
        assert_ne!(public, private);
    }
}
