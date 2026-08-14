# crate-dependent-repos

`crate-dependent-repos` builds an evidence-oriented inventory of Rust
repositories that declare a crate or record an exact crate version in a
default-branch `Cargo.lock`. Public scope is the default; private and internal
repositories require explicit authenticated opt-in.

It deliberately keeps these observations separate:

- a current published crate version directly declares the target, according to
  crates.io and its sparse index;
- a current default-branch `Cargo.toml` directly declares the target;
- a current default-branch `Cargo.lock` records the exact target version;
- the lockfile graph records that version as direct, transitive, both, or merely
  present but unclassifiable from the available roots.

None of those observations proves that a dependency is enabled for a particular
feature set, target, deployed binary, or runtime path.

## Toolchain

The project uses Rust **1.97.1** and Rust edition **2024**. The exact toolchain is
pinned in `rust-toolchain.toml`.

```powershell
cargo build --locked --release
```

The resulting executable is
`target\release\crate-dependent-repos.exe` on Windows.

## Commands

### Resolve a name

```powershell
cargo run --locked -- resolve fs2
cargo run --locked -- resolve fs2-rs
cargo run --locked -- resolve https://github.com/danburkert/fs2-rs
cargo run --locked -- resolve fs2 --json
cargo run --locked -- resolve owner/private-repo --include-private
```

Exact crates.io names are selected automatically. Fuzzy names are ranked but
are not silently scanned. Bare repository names use a bounded public GitHub
name search by default; use `owner/repo` when that search is ambiguous.
Repository URLs are resolved through canonical GitHub metadata and a bounded
inspection of default-branch package manifests. A repository that maps to
several crates requires an explicit `--crate-name` on `links` or `scan`.

### Generate bounded discovery links

```powershell
cargo run --locked -- links fs2 --version 0.4.3
```

This prints:

- an exact multiline `Cargo.lock` query for GitHub's new web code search;
- common direct-declaration and explicit `=0.4.3` queries for `Cargo.toml`;
- the crates.io reverse-dependency API URL;
- the repository's GitHub Dependents page when a GitHub URL is known;
- the Cargo requirement and GitHub search-limit documentation.

The links are supplemental. The CLI does not scrape GitHub's Dependents page,
and it does not send new-web regex syntax to the materially different REST code
search endpoint.

### Scan candidates and write CSV

```powershell
$env:GITHUB_TOKEN = gh auth token

cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --requirement-filter accepts `
  --output fs2-0.4.3.csv `
  --summary-json fs2-0.4.3.summary.json
```

Exact pins only:

```powershell
cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --requirement-filter exact `
  --output fs2-exact-pins.csv
```

Scan a Cargo-compatible release series without scanning each version
separately:

```powershell
cargo run --locked -- scan fs2 `
  --version-range '^0.4' `
  --requirement-filter accepts `
  --output fs2-0.4-series.csv `
  --summary-json fs2-0.4-series.summary.json
```

Range scans fetch the target crate's sparse-index release catalog once,
including yanked releases, and use it to prove whether published dependency
requirements intersect the selector. Every repository and Cargo file is still
fetched and parsed once. Lockfile results retain each concrete matching version
and source. Range mode currently emits CSV/summary evidence only; canonical
exact evidence bundles, policies, pinned data snapshots, durable jobs, and
`links` remain exact-version interfaces.

Stale repositories whose default-branch HEAD commit is at least two years old:

```powershell
cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --stale-after-days 730 `
  --activity stale `
  --output fs2-stale.csv
```

Explicit date bounds are also available:

```powershell
cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --committed-before 2024-01-01 `
  --output fs2-before-2024.csv
```

The default discovery source is `crates-io`. `--discovery github-code` or
`--discovery both` adds a bounded legacy GitHub REST code-search seed. Those
rows remain labeled as bounded and are verified from the repository's current
default-branch snapshot.

Run `cargo run --locked -- scan --help` for kind, optional-dependency,
fork/archive, candidate cap, file-size, activity, partial-result, and
require-match controls.

Private and internal repositories are included only with explicit opt-in:

```powershell
$env:GITHUB_TOKEN = "<read-only token>"
cargo run --locked -- scan fs2 --version 0.4.3 --include-private --output inventory.csv
```

`--include-private` requires `GITHUB_APP_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`. It removes the
public-only qualifier from bounded name/code searches and adds a paginated,
10,000-repository inventory of every public, private, or internal repository
visible to that credential. Repository IDs are deduplicated. Permission
failures or reaching the inventory bound produce partial evidence. The default
path retains its public qualifiers and does not perform this inventory request.

### Report an existing CSV

`report` performs offline sorting/grouping, so it does not contact crates.io or
GitHub:

```powershell
cargo run --locked -- report fs2-0.4.3.csv `
  --sort msrv-asc `
  --group-by stale

cargo run --locked -- report fs2-0.4.3.csv --json
```

The report command expects the current scan CSV schema and fails with a clear
column error when given an unrelated CSV.

## What `scan` does

For a crates.io-seeded run, the CLI:

1. resolves the requested crate without silently accepting an ambiguous fuzzy
   match;
2. pages through crates.io's reverse-dependency endpoint at no more than one
   API request per second;
3. joins dependency records to dependent versions by `version_id`;
4. reads the corresponding sparse-index entry to recover every matching
   declaration, including renamed and duplicated dependencies;
5. evaluates requirements with Cargo-compatible SemVer rules;
6. groups candidate crates by canonical GitHub repository;
7. resolves each repository and freezes its default branch to an immutable
   commit and tree SHA;
8. enumerates files whose final component is exactly `Cargo.lock` or
   `Cargo.toml`, subject to recorded per-repository safety bounds;
9. parses those blobs structurally and emits one CSV row per repository and
   lockfile, including negative and partial states;
10. classifies staleness from the frozen default-branch HEAD commit time while
    also reporting GitHub's repository-wide `pushed_at` value.

If GitHub truncates the recursive tree response, the client adaptively reads
immutable subtrees under recorded request, unique-path, depth, JSON-byte,
path-length, elapsed-time, and concurrency bounds. Successful recovery can
prove file absence; a failed or capped recovery preserves observed files and is
marked partial. The normal repository path still performs one tree request.

Repository inspection is public-only unless `--include-private` is supplied.
Without opt-in, private search results or repositories visible to the supplied
token are discarded. Per-file, per-repository matched
file-count, cumulative download, request-time, and JSON-response bounds prevent
a pathological repository from consuming unbounded resources; reaching one of
those bounds is recorded as partial evidence. Cargo manifest blobs are fetched
concurrently while one shared `--jobs` limit bounds GitHub request pressure
across all repository inspections.

## Requirement filters

`--requirement-filter` has three modes:

- `accepts` (default): retain a published declaration when at least one matching
  requirement accepts the exact version, or intersects the requested range over
  the complete published release catalog;
- `exact`: retain it only when at least one declaration is an explicit, single
  exact comparator such as `=0.4.3` which is selected by the exact version or
  range;
- `any`: retain declarations without filtering on the requested version.

If sparse-index enrichment fails for an individual candidate, semantic filters
retain it with `unknown`/partial evidence instead of turning missing declaration
data into a false negative.

Cargo's bare `0.4.3` syntax is a caret-compatible range, not a pin. It accepts
compatible `0.4.x` releases at or above `0.4.3`; it is not treated as exact.

## CSV evidence

The CSV is designed for audit and follow-up rather than a single optimistic
boolean. Schema V2 appends selector-generic fields to the original exact fields,
so exact consumers can continue reading their established columns. It includes:

- input, canonical crate, target version, collection time, discovery source,
  `globally_exhaustive: false`, candidate scope, and the applied scan policy;
- dependent crate/version, every published matching requirement, kind, target,
  optional status, acceptance, and exact-pin status;
- original and canonical repository URLs, GitHub repository ID, branch, immutable
  commit/tree identities, commit time, `pushed_at`, fork/archive state, and stale
  classification;
- inventory completeness, tree truncation, blob/path identities, parse status,
  every resolved target version/source, exact occurrence counts, and exact
  crates.io-registry occurrence counts;
- selector kind, canonical requirement, catalog digest, final tree-inventory
  completeness, matching concrete versions/sources/counts, and matching graph
  witnesses;
- current manifest declarations and requirements;
- declared MSRV observations and effective MSRV source, plus OS names inferred
  from `cfg(target_os = "...")` dependency selectors;
- recorded direct/transitive relation and shortest lockfile-graph depth when it
  can be established;
- row-level error codes and messages.

`not_found`, `absent`, `unknown`, `truncated`, and `failed` remain distinct.
Untrusted text is protected from spreadsheet formula execution in CSV cells.
A selected package entry is confirmed as a dependent only when the lock graph
supports a direct or transitive path from a recorded root; root-only or
unreachable presence remains visible but does not satisfy `--require-match`.

## Authentication and rate limits

Set a short-lived `GITHUB_APP_TOKEN` (preferred for self-hosted workers), a
fine-grained `GITHUB_TOKEN`, or `GH_TOKEN`. Public repository APIs can be used
without authentication, but GitHub's unauthenticated primary limit is too small
for useful inventories, and REST code search requires authentication. A token is
never written to output or error details. Credential-bearing GitHub URLs, URL
queries, and fragments are rejected before any network request or output.
Supplying a token alone never widens repository scope; `--include-private` is
required for private or internal access. GitHub App installation-token minting
is intentionally left to the organization's existing secret broker so this
process never loads a GitHub App private signing key.

## Policy, evidence, and self-hosted execution

`scan` can emit the canonical evidence record and evaluate a versioned TOML
policy in the same run:

```powershell
cargo run --locked -- scan fs2 --version 0.4.3 `
  --output fs2.csv `
  --evidence-json fs2.evidence.json `
  --data-snapshot security-data.json `
  --policy policy.toml `
  --policy-report policy-report.json

cargo run --locked -- policy validate policy.toml
cargo run --locked -- policy check --policy policy.toml --evidence fs2.evidence.json
cargo run --locked -- explain fs2.evidence.json
```

Policies cover current direct requirements, exact recorded resolution,
direct/transitive relation, repository age, MSRV, SPDX license expressions, and
pinned RustSec/OSV vulnerability data. Unknown evidence is indeterminate by
default (exit `4`); violations use exit `5`. Full-graph license or vulnerability
rules remain indeterminate unless the evidence explicitly states that the full
package inventory was retained. Policy reports include canonical evidence and
policy SHA-256 values, and exceptions require exact repository/crate/version
subjects plus justification, ticket, approver, approval time, and expiry.

Pinned offline source data is normalized with:

```powershell
cargo run --locked -- data sync `
  --rustsec rustsec-input --rustsec-revision <commit> `
  --osv osv.json --osv-revision <snapshot> `
  --crates crates.json --crates-revision <snapshot> `
  --output security-data.json
```

For larger self-hosted runs, initialize one coordinator, enroll LAN workers,
and issue control-API service tokens while the coordinator is stopped. The
runtime admits at most 25 running jobs, retains a bounded queue behind them,
and lets workers lease fairly across every job they are authorized to see:

```powershell
cargo run --locked -- coordinator init --directory .cdr-state --server-name coordinator.lan
cargo run --locked -- agent enroll --directory .cdr-state --agent-id worker-1 --output worker-1
# Private jobs require an explicit per-profile worker grant:
cargo run --locked -- agent enroll --directory .cdr-state --agent-id private-worker `
  --allow-credential-profile production --output private-worker
cargo run --locked -- coordinator token issue --directory .cdr-state `
  --role scan-operator --expires-hours 24

cargo run --locked -- coordinator serve --directory .cdr-state `
  --listen 0.0.0.0:8443 --control-listen 127.0.0.1:8444

cargo run --locked -- job submit `
  --coordinator https://coordinator.lan:8443/ `
  --ca .cdr-state/pki/ca.pem `
  --certificate .cdr-state/pki/operator.pem `
  --private-key .cdr-state/pki/operator.key `
  --crate-name fs2 --version 0.4.3 --repositories repositories.txt

cargo run --locked -- agent run `
  --coordinator https://coordinator.lan:8443/ `
  --ca worker-1/ca.pem --certificate worker-1/worker-1.pem `
  --private-key worker-1/worker-1.key --agent-id worker-1

cargo run --locked -- job export `
  --coordinator https://coordinator.lan:8443/ `
  --ca .cdr-state/pki/ca.pem `
  --certificate .cdr-state/pki/operator.pem `
  --private-key .cdr-state/pki/operator.key `
  --format json --output evidence.json `
  --policy policy.toml --data-snapshot data-snapshot.json `
  --policy-report policy-report.json <job-id>

# For jobs that can exceed the normalized 128 MiB representation:
cargo run --locked -- job export `
  --coordinator https://coordinator.lan:8443/ `
  --ca .cdr-state/pki/ca.pem `
  --certificate .cdr-state/pki/operator.pem `
  --private-key .cdr-state/pki/operator.key `
  --format ndjson --output evidence-shards <job-id>
```

Create a coherent offline recovery unit while the coordinator is stopped:

```powershell
cargo run --locked -- coordinator backup `
  --directory .cdr-state --backup-set backups/cdr-2026-08-14

cargo run --locked -- coordinator restore `
  --backup-set backups/cdr-2026-08-14 `
  --sidecars recovered-secrets --directory .cdr-state-restored
```

The versioned set contains the checkpointed database, the deployment manifest,
and a sorted size/SHA-256 inventory of every encrypted artifact file. It does
not contain the envelope key, inventory cursor key, CA key, server key,
operator key, or their PKI files. Instead, `backup-set.json` records required
role-bound fingerprints. `--sidecars` must provide those files in coordinator
state layout (`envelope.key`, `inventory-cursor.key`, and `pki/*`); restore
verifies every fingerprint before staging a new state directory and never
overwrites an existing destination. Worker enrollment packages live outside
the coordinator state directory and therefore require separate protected
escrow or worker re-enrollment after recovery.

The database itself is integrity-checked but is not wrapped in a second backup
encryption layer. A backup set can contain normalized public or explicitly
enabled private inventory metadata and must therefore be stored on access-
controlled encrypted media. Secret sidecars require a separate protected
recovery channel.

The older database-only interface remains available with `backup --output DB
--manifest JSON` and `restore --backup DB --manifest JSON --database NEW_DB`.
It does not capture encrypted artifacts or external recovery dependencies and
is retained only for compatibility. Neither mode is an online snapshot, secret
escrow, or evidence that the one-hour RPO/four-hour RTO objectives have been
met; those claims require a timed restore rehearsal.

`agent run` leases globally by default. `--job-id` remains available for a
compatibility worker pinned to one job. A lost lease response is retried with
the same client-generated lease ID; provider waits and transient GitHub
failures durably defer the task instead of sleeping while a lease is held.

The product REST/JSON interface is served separately on `--control-listen`.
Its OpenAPI 3.1 document is available at `/api/v1/openapi.json`. It provides
schedule CRUD and manual triggers, bounded job submission/control, credential-
profile metadata administration, saved inventory queries, and latest/history
inventory search. Search cursors are opaque, authorization-bound, and pinned
to one inventory watermark so newly completed scans cannot reorder later
pages. Repository/package filters, completeness, evidence strength, relation,
MSRV, revision, time, and freshness operate on normalized `EvidenceBundleV1`
projections rather than CSV output.

Schedules use five-field UTC cron, enforce a one-hour minimum cadence, allow
one active occurrence, and coalesce missed instants to the newest occurrence.
Each run materializes and records the exact repository-set digest from either
an explicit list or a saved inventory-query revision before queueing work. A
failed saved-query refresh may use only that schedule's last complete set, and
the occurrence records that the membership is stale. Schedule priority is
currently fixed to `normal`; unsupported values are rejected rather than
silently ignored.

The control API always requires mTLS plus either a scoped service token or an
explicitly configured trusted OIDC proxy. Configure the latter with
`--trusted-oidc-proxy FILE`; the JSON file binds a proxy ID and issuer/audience
policy to one exact client-certificate SHA-256. The proxy must strip and
replace `X-CDR-OIDC-Claims`; claims arriving over any other client certificate
are rejected. Service-token secrets are shown once and only their SHA-256
records are retained.

```json
{
  "schema_version": 1,
  "proxy_id": "corp-oidc-proxy",
  "certificate_sha256": "<64 lowercase hex characters>",
  "policy": {
    "schema_version": 1,
    "trusted_proxy_ids": ["corp-oidc-proxy"],
    "issuer": "https://issuer.example",
    "audience": "crate-dependent-repos",
    "max_clock_skew_seconds": 30
  }
}
```

Private searchable metadata is disabled unless `--enable-private-inventory`
is supplied. Enabling it deliberately stores normalized private repository and
package metadata in the Turso read model, so the host must provide restrictive
ACLs, full-disk encryption, encrypted backups, and explicit credential-profile
authorization. Public and private namespaces are filtered before ranking,
counts, and pagination.

`job export` is available once a job is terminal, or while a paused job has a
partial result. The coordinator enumerates tasks in stable, job-scoped pages;
it never clones the global event history. JSON and Markdown fetch at most eight
retained task artifacts concurrently and atomically write one normalized bundle
up to 128 MiB. `--format ndjson` is the scalable contract for jobs up to 10,000
repositories: it writes bounded 64 MiB NDJSON shards plus a digest-checked
`manifest.json` into a new directory, staging the complete directory before one
rename. Each input artifact remains bounded to 8 MiB, and the aggregate input
cannot exceed the job's durable artifact-byte quota. Stable repository ordering
and per-shard SHA-256 digests make retries and downstream ingestion
deterministic. Missing expired artifacts are listed in the manifest. Pass the
directory to `explain` to verify and stream its records without materializing
the complete export.

Durable jobs execute exactly the normalized `owner/name` repositories supplied
to `job submit`; candidate discovery remains a separate standalone `scan`
operation and is not represented by inert job metadata. Add `--policy` and the
required `--policy-report` to a merged JSON or Markdown export to evaluate the
canonical TOML policy against that exact bundle. `--data-snapshot` optionally
applies pinned license, RustSec, and OSV records before both evidence rendering
and evaluation. The durable job update time is the evaluation time, so repeated
exports of unchanged job evidence produce the same report. Policy violations
exit with code 5; incomplete or indeterminate results exit with code 4.

The coordinator is the sole embedded-Turso owner. Its command journal and
derived evidence artifacts are application-encrypted with AES-256-GCM; private
artifacts use a credential-principal namespace. The retention policy reserves a
30-day class for raw private content and retains derived evidence for 365 days.
The same 365-day sweep prunes terminal jobs, tasks, quotas, schedule
occurrences, obsolete revisions, unreferenced repository sets, and expired
control-plane tombstones while preserving active and still-referenced state.
Worker enrollments are public-only by default. Repeat
`--allow-credential-profile PROFILE` during `agent enroll` to authorize a
worker for specific all-visible job profiles. The coordinator checks this grant
before returning job status, events, repository leases, task mutations, or a
private provider permit, so an untrusted worker cannot learn a private job's
repository names. The operator identity remains unrestricted.
The current worker does not persist raw Cargo blobs. Authenticated `/metrics` exposes
low-cardinality OpenMetrics data; setting `OTEL_EXPORTER_OTLP_ENDPOINT` enables
OTLP/HTTP spans. `sla report` evaluates a versioned observation ledger and keeps
platform unavailability separate from provider, user-limit, quota, and
cancellation time. It returns an indeterminate result when monitoring coverage
is incomplete rather than inferring uptime from sparse job events.

Distributed scans incrementally reuse only complete derived evidence. Every
task still resolves current repository metadata and the default-branch HEAD.
When the immutable tree, exact target, analyzer/evidence versions, semantic file
and byte bounds, and cache namespace match, the worker reads the authenticated
encrypted evidence artifact and skips recursive-tree and Cargo-blob downloads.
Public evidence has one shared namespace; all-visible evidence is isolated by
the explicit credential-profile principal. Partial, expired, corrupt,
schema-incompatible, or mismatched entries are not reused. Cache reuse is
recorded as an explanation step in the resulting evidence.

Raw Cargo blobs are deliberately not retained, which is stricter than the
reserved 30-day raw-content retention class and minimizes private source data.
The raw class remains available for a future operator-approved workflow; only
derived evidence currently enters the encrypted cache.

The configured scale ceiling is 10,000 repositories per job, 25 running jobs,
1,000 schedules, and 16 enrolled agents. It is a design target—not a supported
capacity claim—until the documented 250,000-task restart, compaction, search,
backup, and restore load gate passes. The recovery objectives are RPO at most
one hour and RTO at most four hours, likewise contingent on a successful
restore rehearsal.

The client uses the current versioned GitHub REST API, pins repository content to
an immutable commit, and treats search caps, `incomplete_results`, rate limits,
incomplete adaptive tree recovery, oversized blobs, parse failures, and missing
repositories as explicit evidence states.

CSV and summary paths must be different after lexical path normalization.
Explicit file outputs are written through a temporary file and atomically
replace an existing target only after serialization succeeds.

crates.io asks API clients to remain at or below one request per second and to
send an identifying user agent. Broad historical or ecosystem-wide analysis is
better served by the daily crates.io database dump; this CLI's default workflow
uses the current reverse-dependency API plus the sparse index.

## Known completeness limits

The run summary always records `globally_exhaustive: false` because:

- GitHub code search covers indexed default branches only, omits documented
  content classes, does not support exhaustive search, and shows at most 100
  results in the new web UI;
- REST code search is a distinct, legacy, authenticated and rate-limited seed,
  capped at 1,000 results per query;
- GitHub Dependents is public-only, approximate, unversioned, and has no supported
  enumeration API;
- crates.io's reverse endpoint currently represents current non-yanked default
  dependent versions, not every historical release;
- repository URLs are publisher metadata and may be missing, stale, non-GitHub,
  or shared by multiple crates;
- a library repository may intentionally omit `Cargo.lock`;
- a lockfile entry can be optional, target-specific, unused by the build of
  interest, or impossible to classify when its graph roots are ambiguous.

Primary references:

- [Cargo dependency requirements](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
- [Cargo registry index format](https://doc.rust-lang.org/cargo/reference/registry-index.html)
- [crates.io data-access policy](https://crates.io/data-access)
- [GitHub code-search limitations](https://docs.github.com/en/search-github/github-code-search/about-github-code-search#limitations)
- [GitHub REST code search](https://docs.github.com/en/rest/search/search#search-code)
- [GitHub Git Trees API](https://docs.github.com/en/rest/git/trees#get-a-tree)

## Exit codes

- `0`: output was produced under the requested completeness policy;
- `1`: a fatal failure occurred before useful output;
- `2`: command-line usage or argument validation failed (Clap's conventional
  usage-error code);
- `3`: `--require-match` was set and no direct or transitive selected lockfile
  resolution was confirmed;
- `4`: usable output exists but the run or policy result is indeterminate;
- `5`: policy evaluation found a definitive violation.

When a run is both partial and has no confirmed match, partial-result code `4`
takes precedence unless `--allow-partial` is set. A definitive policy violation
uses `5` even when other evidence is partial.

## Development checks

```powershell
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

Live network smoke tests should never assert a fixed public result count: crates,
repository heads, indexes, and search totals change over time.
