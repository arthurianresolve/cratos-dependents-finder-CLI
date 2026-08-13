# Domain context

`crate-dependent-repos` collects bounded, provenance-rich evidence about Cargo
consumers. It does not claim exhaustive GitHub coverage and it keeps discovery,
current manifest declarations, recorded lockfile presence, graph reachability,
policy decisions, and operational health as separate facts.

## Core language

- **Scan specification**: the immutable, versioned description of a scan target,
  repository visibility, materialized repository inputs, safety bounds, and
  analyzer versions. Standalone candidate discovery is recorded separately.
- **Candidate**: a crate or repository found by crates.io metadata or bounded
  GitHub discovery. A candidate is not yet a confirmed dependent.
- **Repository snapshot**: a canonical GitHub repository ID plus immutable
  default-branch head, tree, and blob identities used for analysis.
- **Evidence bundle**: the canonical, versioned JSON record from which CSV,
  Markdown explanations, and policy reports are projected.
- **Explanation witness**: a deterministic path or declaration showing why a
  repository was included. Presence without a reachable lock graph remains
  unclassified evidence.
- **Policy report**: a deterministic pass, fail, or indeterminate evaluation of
  one evidence bundle against a versioned TOML policy and pinned data snapshots.
- **Coordinator**: the single self-hosted process that owns the embedded Turso
  database, durable job state, leases, quotas, provider gates, encrypted cache,
  and audit events.
- **Agent**: an enrolled LAN worker authenticated with a client certificate. It
  leases idempotent tasks and never owns the coordinator database.
- **Public scope**: the compatibility default. Credentials do not widen it.
- **All-visible scope**: an explicit authenticated opt-in that includes every
  public, private, or internal repository visible to the credential.

## Invariants

1. Public scans retain their request count, shared `--jobs` bound, deterministic
   ordering, and output semantics unless a versioned schema says otherwise.
2. One coordinator process owns the Turso files. Agents use only the mTLS API.
3. Raw private content is not retained. Any future operator-approved raw cache
   must be tenant-scoped, application-encrypted, and never deduplicated across
   tenants.
4. External provider waits are persisted as `not_before`; workers do not sleep
   while holding task or GitHub concurrency permits.
5. Partial, unavailable, and unknown evidence never become an implicit pass.
6. Tokens, private content, and private repository names are excluded from
   metrics and non-tenant operational logs.
7. Versioned evidence, policy, event, and protocol records are additive and
   reject unsupported major schema versions.
