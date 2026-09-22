# Domain context

`crate-dependent-repos` collects bounded, provenance-rich evidence about Cargo
consumers. It does not claim exhaustive GitHub coverage and it keeps discovery,
current manifest declarations, recorded lockfile presence, graph reachability,
policy decisions, and operational health as separate facts.

Cratos identifies dependent repositories so maintainers can choose which
userbase to optimize for and assess replacing unmaintained dependencies with
maintained alternatives. Its current sources are crates.io and GitHub. GitHub
access is read-only; discovery does not authorize automated outreach or prove
that a successor is technically compatible.

## Core language

- **Scan specification**: the immutable, versioned description of a scan target,
  repository visibility, materialized repository inputs, safety bounds, and
  analyzer versions. Standalone candidate discovery is recorded separately.
- **Candidate**: a crate or repository found by crates.io metadata or bounded
  GitHub discovery. A candidate is not yet a confirmed dependent.
- **Target selector**: either one exact package version or a Cargo requirement
  whose evidence remains bound to concrete published and lockfile versions.
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
- **Schedule revision**: an immutable UTC cadence, scan specification,
  repository source, and execution policy used to create future occurrences.
- **Schedule occurrence**: one idempotent nominal run of a schedule. It records
  repository-set materialization, queue admission, and the resulting job.
- **Saved inventory query**: a revisioned, typed repository query evaluated at
  one inventory watermark and materialized before a scheduled job is queued.
- **Inventory observation**: a retained, searchable projection of one accepted
  repository attempt and its canonical evidence. The encrypted evidence bundle
  remains authoritative and the projection is rebuildable.
- **Control identity**: an OIDC subject or scoped service token authorized for
  human and automation operations. Control identities never lease worker tasks.
- **Public scope**: the compatibility default. Credentials do not widen it.
- **All-visible scope**: an explicit authenticated opt-in that includes every
  public, private, or internal repository visible to the credential.
- **Suppression policy**: a durable deployment-bound exclusion of a repository
  identity and known aliases in explicit namespaces. It prevents new collection
  and evidence access independently of cleanup progress.
- **Removal request**: an idempotent administrative instruction whose bounded
  cleanup removes evidence and inventory while retaining operational history
  under existing expiry/reference rules.
- **Independent suppression ledger**: authenticated encrypted policy retained
  separately from old backups so restoration can reapply current exclusions.

## Invariants

1. Successful unsuppressed public scans retain their request count, shared `--jobs` bound, deterministic
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
8. Range inventory never fans out repository work per matching release and does
   not reinterpret exact evidence or distributed-job protocols.
9. Schedule ticks materialize an exact repository set before queue admission.
   Saved-query failure may reuse only the last complete materialization and must
   record that the membership is stale.
10. Inventory authorization is applied before search ranking, aggregation, or
    pagination. Private observations never cross credential-profile scopes.
11. Forwarded OIDC claims establish identity only when the control listener
    authenticates the explicitly allowlisted proxy certificate; headers alone
    never create a trusted-proxy capability.
12. GitHub deadlines cannot be shortened by concurrent success, a profile
    change, or coordinator restart. Secondary recovery probes are bounded and
    suspension requires explicit Admin resume without erasing deadlines.
13. Explicit and all-profile private grants resolve current profile eligibility
    consistently. Local disablement is not upstream revocation or evidence
    removal.
14. Accepted suppression precedes ranking, pagination, evidence access, and
    durable acceptance of new evidence. Cleanup failure does not lift policy;
    already serialized responses and external exports cannot be recalled.
15. Removal retains encrypted operational history under existing retention.
    Physical cleanup checks references; neither removal nor encrypted storage
    is a secure-erasure or oblivious-storage claim.
16. Restoration applies current supplied policy in staging before exposure.
    An old backup plus an equally old ledger cannot establish latestness;
    legacy identity adoption requires an explicit operator attestation.
17. These engineering controls do not establish GitHub approval or contractual
    compliance. Legal interpretation and individually reviewed contributions
    remain separate decisions.
