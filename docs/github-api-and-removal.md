# GitHub access and repository-removal operations

Cratos discovers repositories using a crate or library so its maintainer can
understand which users to optimize for and assess migrations from unmaintained
dependencies to maintained replacements. Its current discovery sources are
crates.io and GitHub. A discovery candidate is not proof of dependency use or
proof that a replacement is compatible.

GitHub access is read-only. Cratos does not post issues, open pull requests,
send migration email, or automate outreach. Review each proposed contribution
against the target project's instructions and technical requirements. Keep
declines and do-not-contact decisions outside the submission workflow; the
repository suppression facility below prevents further collection by the
configured deployment, not communication by other tools.

These are engineering and operating controls, not a representation of GitHub
approval or contractual compliance. Review the current [Registered Developer
Agreement](https://docs.github.com/en/site-policy/github-terms/github-registered-developer-agreement),
[Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service),
and [Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies)
separately. Contract interpretation, support-contact publication, and legal
decisions are not performed by the CLI.

## Credentials and rate-limit recovery

Standalone credential precedence is `GITHUB_APP_TOKEN`, then `GITHUB_TOKEN`,
then `GH_TOKEN`; blank values are ignored. `GITHUB_APP_TOKEN` selects GitHub App
installation-token mode. The other names select user-token mode. The client
does not infer type from token contents or silently substitute a credential
after a permission error.

All-visible repository enumeration uses `/installation/repositories` for
installation tokens and `/user/repos` for user tokens. `--include-private` is
still required; merely supplying a token does not widen public scope. The
explicit-repository worker path does not need enumeration. Provision the
least permissions necessary through GitHub or the configured credential broker.

The client classifies bounded error bodies before reporting the response to
provider admission. It respects applicable `Retry-After` and exhausted primary
reset deadlines, uses a minimum one-minute fallback for secondary limits with
no usable deadline, and never treats an ordinary permission-denied `403` as a
reason to retry. A successful response with no primary requests remaining is
returned normally while subsequent requests are blocked. Standalone clones
share cooldowns and use at most three attempts and five seconds of cumulative
inline waiting; longer waits return a deferred outcome.

The coordinator conservatively shares primary deadlines by resource across
profiles and a secondary cooldown across GitHub work. Profiles are not a way
to acquire fresh rate-limit allowances. After a secondary cooldown, only one
recovery probe is admitted. Three unsuccessful automatic probes suspend
GitHub admission durably. Queued work remains pending subject to its ordinary
deadline and cancellation rules. Restarting or resubmitting jobs does not
clear suspension.

Use the product control listener, normally port 8444. Both its client
certificate and an Admin service token are required; the worker `operator`
identity alone is not an Admin grant. Keep token files outside source control.

```powershell
$control = @(
  '--control-url', 'https://coordinator.lan:8444/',
  '--ca', '.cdr-state/pki/ca.pem',
  '--certificate', '.cdr-state/pki/operator.pem',
  '--private-key', '.cdr-state/pki/operator.key',
  '--token-file', 'admin.token'
)

cargo run --locked -- coordinator github status @control
# Inspect the upstream failure and existing deadlines before permitting a probe:
cargo run --locked -- coordinator github resume @control
```

Alternatively use `--token-env VARIABLE_NAME`; without either token option,
the client reads `CRATOS_CONTROL_TOKEN`. Never put the token value in the
command line. Resume preserves upstream deadlines and allows a single probe;
it does not restore unrestricted traffic. [GitHub's API operational guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
is useful when diagnosing repeated limits.

## Profile disablement is not removal

Disabling, expiring, or invalidating a credential profile removes its
eligibility for private inventory and new private execution. Selected-profile
and all-profile grants use the same current eligibility check. Local profile
disablement does not revoke a token at GitHub, erase evidence, or prove that an
upstream token was revoked. Retained privileged archival access has separate
authorization; suppression overrides evidence access.

Private searchable metadata remains plaintext in the normalized database when
explicitly enabled. Apply restrictive filesystem access, full-disk encryption,
and protected backups. Application-encrypted evidence and operational history
do not make every database column encrypted.

## Plan, suppress, and remove evidence online

Removal targets one exact numeric GitHub repository ID and an explicit scope:

- `--scope public` selects the public namespace.
- `--scope profile --credential-profile PROFILE` selects one private namespace.
- `--scope all` requires a grant covering public and all private namespaces.

No wildcard or repository-name CLI selector is supported. Obtain the immutable
ID from inventory or repository metadata. The server records known aliases;
aliases are supplementary matches, not a replacement for stable identity.
Plan files may contain private repository names and must be protected.

```powershell
cargo run --locked -- coordinator privacy plan @control `
  --repository-id 42 --scope public --output removal-plan.json

$removalId = [guid]::NewGuid().ToString()
cargo run --locked -- coordinator privacy remove @control `
  --plan removal-plan.json --request-id $removalId

cargo run --locked -- coordinator privacy status @control --request-id $removalId
# Correct an operational failure before requesting another cleanup attempt:
cargo run --locked -- coordinator privacy retry @control --request-id $removalId
```

Planning is non-destructive and reports estimates, not a frozen set of rows.
Removal binds deployment, repository identity, scope, and resolved aliases.
Changed aliases require a fresh plan; newly arriving evidence for the same
target is still covered. Save the request UUID and exact plan before submitting.
After an uncertain response, query status or retry that same request. Do not
invent a new UUID to work around a conflicting request.

An accepted response means suppression has been durably published, not that
all physical cleanup has finished. Suppression is applied before inventory
ranking, counts, and pagination and invalidates previously issued cursors.
Collection, cache reuse, exports, uploads, projection, and recovery consult the
policy. Cleanup proceeds in bounded batches while unrelated work continues.
Failed cleanup remains suppressed and visibly incomplete; retry does not lift
the policy. No expiry or unsuppress command is provided.

Monitor `coordinator_privacy_removals_incomplete` and
`coordinator_privacy_removal_failures_total` for cleanup that needs attention.
These aggregate metrics contain no repository or profile labels. Policy
publication failures make readiness and evidence access unavailable; after
correcting the cause, resubmit the same request or retry its cleanup.

The equivalent product-control routes are:

| Operation | Route |
| --- | --- |
| GitHub status | `GET /api/v1/providers/github` |
| GitHub recovery probe | `POST /api/v1/providers/github/resume` |
| Removal plan | `POST /api/v1/privacy/removal-plans` |
| Submit removal | `POST /api/v1/privacy/removals` |
| Removal status | `GET /api/v1/privacy/removals/{id}` |
| Retry cleanup | `POST /api/v1/privacy/removals/{id}/retry` |

The planning body supplies `repository_id`, `scope`, and an empty `aliases`
array; the server resolves authoritative aliases. Submission carries the
returned `plan` and caller-selected UUID `request_id`. Scope uses `kind` values
`public`, `credential_profile` (with `credential_profile_id`), or `all`.
Authorization is evaluated for every selected namespace, not inferred from
the possession of a plan file or an mTLS certificate.

The CLI prints cleanup counters and explicit retention limitations. In
particular:

- Catalog observations, package/requirement rows, aliases, projection payloads,
  reuse records, and unreferenced evidence artifacts are removal targets.
- Encrypted operational job/task history, errors, events, names, identifiers,
  and digests remain subject to existing reference-aware retention. Referenced
  schedule/repository-set/saved-query records are not universally erased.
- Responses already serialized before suppression cannot be recalled.
- Old exports, copied plan files, old backups, filesystem remnants, and copies
  held by other deployments need separate operator handling. This is not secure
  erasure and does not rewrite historical job outcomes.

## Independent ledger and recovery

Initialization creates `suppression.ledger` and a dedicated `suppression.key`
in the state directory. Retain a current, protected copy independently of
ordinary database backups. The ledger contains encrypted policy records and
is authenticated with the dedicated key. Protect both the key and ledger from
replacement; encryption is not protection against an authorized operator
deliberately presenting an old pair.

`coordinator serve` accepts paired `--suppression-ledger` and
`--suppression-key-file` options for an independently managed location. Use
the same pair with `coordinator backup` when that location is non-default.
Missing keys, missing known policy, corrupt authentication, or conflicting
deployment identities fail closed. Interrupted database/ledger publication
is reconciled before policy readiness. Mutable cleanup progress remains in
the encrypted database and does not rewrite the independent ledger every batch.

Ledger replacement flushes file contents before publication and, on Unix,
also synchronizes the parent directory after the atomic replacement. The
portable Windows path does not provide that parent-directory synchronization;
do not assume identical power-loss guarantees across filesystems. Rehearse
recovery on the deployment's actual storage and independently retain current
policy rather than relying on one local copy. Publication errors keep policy
readiness closed until repair.

Backup-set format 3 records policy deployment, revision, and a digest of
immutable policy, alongside the existing database/artifact integrity contract.
It does not include the suppression key or a trusted current ledger. Preserve
the ordinary recovery sidecars separately as before.

```powershell
cargo run --locked -- coordinator restore `
  --backup-set backups/cdr-2026-09-22 `
  --sidecars recovered-secrets --directory .cdr-state-restored `
  --suppression-ledger recovery-policy/suppression.ledger `
  --suppression-key-file recovery-policy/suppression.key
```

Every format-3 restore requires the current independent ledger, including a
backup whose recorded policy revision is zero: suppression may have been added
after that backup was made.
It rejects known-stale, conflicting, or unauthenticated policy. It merges
applicable suppression into a separate staging directory, resets cleanup
progress, purges restored evidence, and closes/checkpoints storage before
publishing the destination. A failed rehearsal must not be used as a live
state directory. Never overwrite the only database copy.

Older format-2 sets remain readable. A set predating privacy identifiers cannot
prove its association with a supplied ledger through a stored deployment ID:
the operator must independently verify that association before selecting the
ledger and attest using `--accept-legacy-ledger-binding`. The flag is required
when a nonempty supplied policy is applied to a legacy backup with no policy
identity or retained suppression; it does not override identity checks on new
sets. Ordinary recovered sidecars are still fingerprint-verified. An old
backup paired with an equally old ledger cannot establish that no later
suppression exists; a newer trusted checkpoint or independently retained
current ledger is essential.

Legacy sets cannot prove that they predate every suppression. Restoring one
without the applicable current ledger can resurrect evidence; do not use that
compatibility path when later removal policy exists.

Database-only legacy backups cannot preserve suppression-aware recovery and
are rejected once the newer storage format is in use, even if its suppression
revision is zero. Older immutable backups and
external exports remain the operator's responsibility; do not distribute them
as if online removal had modified them.

## Standalone scans

Configure both files before scanning:

```powershell
cargo run --locked -- scan fs2 --version 0.4.3 --output inventory.csv `
  --suppression-ledger recovery-policy/suppression.ledger `
  --suppression-key-file recovery-policy/suppression.key
```

The equivalent environment variables are `CRATOS_SUPPRESSION_LEDGER` and
`CRATOS_SUPPRESSION_KEY_FILE`. A configured missing or invalid ledger is an
error, not permission to scan without policy. Known aliases are checked before
repository requests and stable IDs after metadata resolution. Because a
standalone scan has no coordinator profile mapping, it conservatively applies
the union of every namespace in the supplied ledger.

Where a stable numeric identity is available, it takes precedence over a
reused alias. Before a request has established that identity, an alias match
is conservatively blocked; a name reused by a different repository may need
operator review. Do not remove an existing suppression merely to bypass an
ambiguous alias.

Immediately before writing results, the scan reloads and authenticates policy,
rejects rollback/deployment changes, and refuses publication of newly
suppressed results. This check does not lock another process's ledger writer;
later policy updates cannot recall already published output. Unconfigured
independent scans and offline processing of old exports are outside the
deployment's suppression guarantee.

## Release checklist

Record exact revision, toolchain, commands, and outcomes. These are required
checks, not a statement that a particular checkout has passed them:

See the [2026-09-22 implementation validation record](github-controls-validation-2026-09-22.md)
for executed checks and their limits.

- [ ] Rust 1.98.1 formatting, strict Clippy, unit, integration, and CLI suites.
- [ ] Native Windows and Linux checks, including checkpoint/close/rename
  behaviour and restrictive recovery-file handling.
- [ ] Mocked headerless and header-based limits, secondary error messages,
  ordinary `403`, extreme deadlines, cancellation, shared cooldowns, probe
  exhaustion, restart persistence, and explicit resume.
- [ ] User/installation-token endpoint selection and bounded pagination.
- [ ] Disabled/expired/missing profiles across explicit and all-profile grants,
  saved queries, scheduling, cache use, and authorization-bound cursors.
- [ ] Removal authorization, exact scopes, idempotency/conflicts, changed
  aliases, every search/history path, and unrelated mixed-job progress.
- [ ] Late uploads, pending projection, shared artifacts, partial failures,
  restart recovery, and a completed removal that cannot reappear on rebuild.
- [ ] New/legacy backup rehearsals with correct, missing, wrong, stale, and
  interrupted policy publication and explicit legacy-binding attestation;
  verify suppression before destination exposure.
- [ ] Standalone missing/corrupt policy, alias-before-request, stable-ID checks,
  publication-time policy changes, and output/key collision rejection.
- [ ] Confirm operational-history, export, backup, and secure-erasure
  limitations are present in operator receipts and documentation.

Measure search overhead, purge batch duration, and representative recovery
resource use with fixed fixtures and preserved provenance. Report raw results
and limitations; no performance non-inferiority rollout gate is reinstated.
