# ADR 0005: Coordinator schedules, fair queue, and searchable inventory

- Status: accepted
- Date: 2026-08-14

## Decision

The self-hosted coordinator gains an in-process UTC scheduler, a global fair
task queue, a separate control/read REST interface, and a normalized searchable
inventory projection. The existing mutual-TLS worker protocol and standalone
scan path remain supported.

Schedules use five-field UTC cron with a one-hour minimum cadence, at most one
active run, and latest-occurrence coalescing. A revision selects either an
explicit repository set or a saved inventory query. Every occurrence records a
content digest of the exact repository membership before queue admission. If a
saved query cannot be evaluated completely, only its last complete materialized
set may be reused, with explicit stale-membership evidence.

The coordinator accepts up to 1,000 enabled schedules, queues bounded jobs, and
runs at most 25 jobs concurrently. Agents may lease globally across authorized
jobs. Dispatch is fair across jobs, while task leases, retries, provider waits,
and quotas remain durable.

The existing durable job/task store is the sole execution authority. Schedule
state records occurrence and repository-set provenance, then submits work to
that store; it does not maintain a shadow task or lease state machine.

`EvidenceBundleV1` remains canonical. A normalized Turso read model projects
repository attempts, immutable snapshots, exact target observations, and
package presence. Search returns latest-attempt state by default and retains
bounded observations for history and as-of queries. Arbitrary package graph
edges and distributed range evidence are outside this version.

Latest-state search is executed by indexed Turso queries with keyset cursors.
Historical observations remain durable and are not replayed into an unbounded
in-memory search index at startup.

The control/read interface is distinct from the worker interface. Human access
uses trusted-proxy OIDC and automation uses scoped service tokens. OIDC claims
are accepted only when the control listener authenticates the configured proxy
leaf certificate by SHA-256; arbitrary forwarding headers never establish the
proxy capability. Canonical private evidence remains application-encrypted.
The chosen rich private search mode permits normalized private metadata in the
Turso read model only with an explicit deployment opt-in, restrictive
filesystem permissions, full-disk encryption, encrypted backups, and
credential-profile authorization applied before every query operation.

Private scheduled scans use short-lived GitHub App installation credentials
obtained through an external broker. The coordinator stores only profile,
principal, secret-reference, version, and health metadata.

## Why these seams are deep

The schedule module hides cadence, misfire, revision, and occurrence
idempotency behind one interface. The dispatch module hides admission, fairness,
retry, and readiness indexes. The inventory module hides projection, freshness,
history, cursor stability, and search ranking. The control-auth module hides
OIDC and service-token identity behind role and scope decisions.

Deleting any of these modules would force its invariants back into the state
store, Axum handlers, worker loop, and tests. Their interfaces therefore provide
leverage and locality rather than acting as pass-through adapters.

## Operational targets and release gate

The design target is 10,000 repositories per job and 16 enrolled agents, with
at most 25 running jobs and 1,000 enabled schedules. This becomes a supported
capacity only after the full 25-job/250,000-task restart, queue, projection,
backup, and restore load gate passes. Evidence and inventory observations retain
for 365 days by default. Terminal execution and control-plane state follows the
same reference-aware retention boundary; active runs and state referenced by a
retained schedule or artifact are preserved. Distributed provider admission
uses retry-safe per-request permit identities. Recovery targets (RPO/RTO) are
currently aspirational and should be validated by repeated restore rehearsals.
