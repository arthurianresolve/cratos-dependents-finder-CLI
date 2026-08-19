# Release readiness checklist (dev branch)

This document defines the gates for release confidence on `crate-dependent-repos`.
Current implementation status is strong for correctness and architecture, but performance
and recovery characteristics are validated via explicit diagnostics that are intentionally
invoked manually (`#[ignore]`).

## 0) Baseline validation (mandatory)

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --lib`

## 1) Functional correctness gates (mandatory)

- [ ] `cargo test --locked --all-targets --all-features`
- [ ] Targeted auth/privacy/security checks
  - service token issue/verify flows
  - trusted-proxy OIDC policy and transport identity binding
  - private namespace concealment and authorization before query execution
- [ ] Schedule/control-plane checks
  - create/retry/trigger/revise/list/show jobs and schedules
  - queue limit and fair global leasing
  - provider retry/circuit semantics

## 2) Scale/perf readiness gate (explicitly run, measured)

The following tests are `#[ignore]` by design and must be run with explicit environment
variables and single-threaded execution.

- [ ] `cargo test --locked --test-threads=1 --lib rollout_gates::coordinator_and_catalog_capacity_gate`
  - **Required env vars**
    - `CDR_LOAD_GATE_STATE=<fresh, initialized coordinator directory>`
    - `CDR_LOAD_GATE_METRICS=<new JSONL file>`
  - Coverage:
    - 25 jobs × 10k tasks submission
    - queue promotion + running/queued semantics
    - 16-job fair global lease sampling
    - restart idempotency with compaction
    - 250k durable catalog rebuild + cursor paging

- [ ] `cargo test --locked --test-threads=1 --lib rollout_gates::catalog_rebuild_diagnostic_gate`
  - **Required env vars**
    - `CDR_LOAD_GATE_STATE=<fresh, initialized coordinator directory>`
    - `CDR_LOAD_GATE_METRICS=<new JSONL file>`
    - `CDR_CATALOG_DIAGNOSTIC_COUNT=<projection count>`

- [ ] `cargo test --locked --test-threads=1 --lib rollout_gates::catalog_search_diagnostic_gate`
  - **Required env vars**
    - `CDR_LOAD_GATE_STATE=<fresh, initialized coordinator directory>`
    - `CDR_LOAD_GATE_METRICS=<new JSONL file>`
    - `CDR_CATALOG_DIAGNOSTIC_COUNT=<projection count>`
  - Verifies bounded restart + deterministic page/cursor behavior and exact lookups.

## 3) Restore/backup coherence gate (mandatory before release claim)

- [ ] `cargo test --locked --test-threads=1 --lib rollout_gates::restored_capacity_state_gate`
  - **Required env vars**
    - `CDR_LOAD_GATE_STATE=<restored full-scale directory>`
    - `CDR_LOAD_GATE_METRICS=<new JSONL file>`
  - Confirms restored coordinator + restored catalog state still satisfy expected
    job/task/projection invariants.

- [ ] End-to-end coherent backup restore rehearsal
  - `cargo run --locked -- coordinator backup --directory ... --backup-set ...`
  - `cargo run --locked -- coordinator restore --backup-set ... --sidecars ... --directory ...`
  - Re-run representative submit/search commands on restored state and compare identity-sensitive outputs.

## 4) Pass/fail interpretation

- **PASS**: all mandatory gates are green and all scale/perf + restore checks
  executed with saved metrics artifacts.
- **BLOCK**:
  - any gate that changes observed cardinalities (paging/cursor/order), fails restart
    replays, or drops private-scoped concealment.
  - missing metrics artifacts for capacity/restore gates.
- **RPO/RTO status is claim-level** until at least two timed rehearsals demonstrate cadence.

## 5) Evidence records to archive

- Save:
  - command transcript (`--exact`/`--threads=1` test invocations)
  - metrics JSONL files (`CDR_LOAD_GATE_METRICS`)
  - backup-set manifest and restore manifest
  - restore rehearsal duration and validation summary

## 6) Governance note on architecture and churn

- This release path is intentionally architecture-first with low churn:
  preserve command schemas and queue interfaces, avoid introducing new external
  services, and keep performance gates explicit rather than implicit assumptions.
