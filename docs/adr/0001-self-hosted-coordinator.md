# ADR 0001: Single-owner self-hosted coordinator

- Status: accepted
- Date: 2026-08-13

## Decision

The commercial execution mode uses one coordinator process as the sole owner of
a locally embedded Turso database. Up to 16 LAN agents communicate with it over
mutual TLS. The standalone local `scan` command remains available and unchanged
by default.

The coordinator persists versioned jobs, tasks, leases, events, quotas, provider
rate gates, circuit state, cache metadata, and artifact references. Repository
and evidence payloads live in an application-encrypted content-addressed store.
Turso experimental multiprocess, MVCC, and database-encryption switches are not
enabled; encryption is provided by the application envelope.

A durable job materializes exactly one task per normalized `owner/name` entry in
the operator-supplied repository list. Registry and code-search discovery remain
standalone inventory inputs; the job protocol does not carry discovery switches
that the coordinator cannot execute.

## Why this seam is deep

The state-store interface hides schema migrations and the embedded database from
job orchestration. The mTLS protocol hides LAN transport from task execution.
Removing either implementation would leave the domain records and deterministic
analyzers usable with the in-memory adapter or standalone CLI, without spreading
storage or transport details into Cargo evidence analysis.

## Operational limits

The supported deployment target is 10,000 repositories per job, 25 concurrent
jobs, and 16 enrolled agents. The availability objective is 99.5%; reports keep
platform time separate from upstream provider waits, user limits, quota waits,
and cancellations.
