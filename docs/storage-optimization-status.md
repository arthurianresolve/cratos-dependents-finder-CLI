# Storage optimization implementation status

Updated: 2026-09-22.

The active repository toolchain and declared MSRV are Rust 1.98.1. Historical
validation entries retain their original Rust 1.97.1 identity so those results
are not misrepresented as 1.98.1 evidence.

## Baseline and validation boundary

Work began on `dev` at `4c2e85e850426108df593720380dd083bdd0b135`.
The Slice 1 changes are validated on Rust 1.98.1 and are being published as a
separate implementation checkpoint. This is not a benchmark result or a
release readiness declaration. The corrected semantic benchmark baseline has
**not** been frozen.

At the latest validation, the drive had approximately 5.8 GiB free. Full-scale
benchmark fixtures, database copies, engine evaluation and migration rehearsals
remain deferred until their capacity and provenance requirements are met.
Existing benchmark databases and logs were not removed.

## Slice 1 changes

- Latest fuzzy search unions all query-trigram postings before applying the
  existing integer Jaccard score and threshold. Generic and historical fuzzy
  queries score canonical terms without depending on a single anchor bucket.
- Substring queries can prepare and use the existing trigram index, with
  watermark checks binding index readiness to the query snapshot. Short and
  normalized-empty queries retain the reference implementation's behavior.
- Access, namespace authorization, query, page and signed-cursor validation
  precede index preparation. Stale cursor watermarks are checked before lazy
  preparation and checked again within the search read transaction.
- Malformed posting tuples fail the indexed path rather than dropping matches.
  Search falls back to canonical terms; projection invalidates corrupt,
  disposable buckets without rejecting otherwise valid canonical data.
- Automatic compaction failures wait at least 60 seconds before another
  attempt. Oversized snapshots additionally require a committed state reduction
  or an explicit compaction request. Retry state survives journal replay after
  an append failure.
- Snapshot serialization stops at the existing size limit. Successful durable
  commands retain successful acknowledgments when later compaction fails.
- Maintenance and fallback warnings use categorical reasons, without private
  identifiers or exception payloads. An empty search is not logged as a failure.

Regression tests were added for fuzzy anchor omissions and pagination,
validation-before-preparation, normalized short searches, stale signed cursors,
malformed postings and projection recovery, compaction cooldown and oversize
policies, bounded serialization, and acknowledged commands surviving failed
maintenance and subsequent append failures.

The existing whole-state snapshot construction and global index invalidation
still exist. Their replacement belongs to later slices; this patch only
contains their immediate failure modes. Complete candidate generation can do
more work than the former incomplete fast path. No speedup is claimed.

## Checks performed

Current toolchain: Rust 1.98.1, `x86_64-pc-windows-msvc`, LLVM 22.1.8.

| Check | Result |
| --- | --- |
| `cargo metadata --locked --no-deps --format-version 1` | Passed; edition 2024 and `rust_version = 1.98.1` |
| `cargo fmt --all -- --check` | Passed |
| `git diff --check` | Passed |
| Focused coordinator compaction tests | Passed; 3/3 |
| Full release tests, locked, serial and no-fail-fast | Passed; 326 library tests and 12 CLI tests; 5 large-scale gates ignored by design |
| All-target release Clippy with `-D warnings` | Passed after fixing three Rust 1.98 `chunks_exact_to_as_chunks` findings in unchanged support code |
| 10k/250k benchmarks and database comparison | Not run |

The Windows ACL tests require the process identity to match the identity used
by the test environment when restricting secret files. The validation run set
that identity explicitly; this was an environment setup correction, not a
production ACL-policy change.

The failed test attempt's stdout/stderr are retained under
`target/slice1-validation-20260917/`. Old release artifacts are not evidence for
this checkout's locked dependency set or these changes. Neither the manifest
nor the lockfile was changed to bypass the missing cache.

Retry at 2026-09-17 07:16 UTC: C: had 743,546,880 bytes free (about 0.69 GiB).
Locked offline dependency resolution was retried with `cargo metadata --locked
--offline --format-version 1 --filter-platform x86_64-pc-windows-msvc`; it exited
101 before compilation with the same missing `aes-gcm` error. Logs are retained
under `target/slice1-retry-20260917-071603/`. Formatting and `git diff --check`
passed again. No build, benchmark, migration or source-code change was made
during this retry.

Historical Rust 1.98.1 validation, run after capacity recovered, used the locked
dependency set and one build job:

| Check | Result |
| --- | --- |
| `cargo metadata --locked --no-deps --format-version 1` | Passed; package reports `rust_version = 1.98.1`, edition 2024 |
| `cargo check --release --locked --lib` | Passed; native exit 0, 4m34s; log directory `target/rust-1.98.1-check-20260917-074008/` |
| `cargo test --release --locked --lib catalog:: -- --test-threads=1` | Passed; native exit 0, 36 passed / 0 failed, 2.30s test execution; log directory `target/rust-1.98.1-catalog-test-20260917-074534/` |
| `cargo fmt --all -- --check` with Rust 1.98.1 | Passed |

The first parallel release-test attempt also had a dependency compilation
failure in `turso_sync_sdk_kit`; the successful single-job check and test runs
supersede it for source validation, while its retained log remains diagnostic.

## Remaining sequence

1. Provide build/benchmark capacity and restore the locked dependency cache.
   Compile and run the catalog and coordinator compaction tests, then the
   required formatting, Clippy, unit, integration and CLI checks. Resolve any
   failures before freezing the corrected semantic baseline.
2. Implement benchmark provenance and phase/resource measurements, deterministic
   mixed and history-heavy fixtures, capacity preflight and phase timeouts.
   Preserve the original failed-attempt fixture. Pass 10k smoke runs before
   measuring 250k workloads with independent state directories.
3. Introduce the narrow asynchronous coordinator seam and pure inventory
   projector. Compare corrected Turso, patched bundled SQLite and PostgreSQL
   under the same host/resource budget; include PostgreSQL server resources.
   Record an engine-selection ADR only after correctness, encryption,
   durability, recovery and absolute workload targets have been evaluated.
4. Replace JSON posting buckets with incremental namespace-scoped term and
   membership tables. Verify complete authorized recall against the reference.
5. Bound candidate selection, ordering, hydration, package/alias batching and
   cancellation without arbitrary recall-limiting candidate caps.
6. Replace routine snapshots with atomic changed-record encrypted persistence,
   bounded rosters/events, durable idempotency and projection records, and
   active-state startup. Operational metadata must remain encrypted.
7. Implement staged bounded maintenance, resumable rebuilding, notification-led
   recovery, reference-aware retention and streaming coherent backup/restore.
   Then implement and rehearse explicit offline migration to a separate
   destination with verification, ownership locking and a preserved original.

SQLite remains a preference, not a selected engine. Prefer it if both candidates
meet the agreed targets; otherwise follow the approved selection rule. Do not
ship a losing prototype as another supported production backend.

The public API, worker protocol, standalone scanning and `EvidenceBundleV1`
remain unchanged. Correctness and recovery remain gates. Performance evidence
informs selection; the removed performance non-inferiority rollout gate must
not be reinstated. No in-place conversion of the only database copy is allowed,
and returning to the original database after new writes requires verified
reverse export or fix-forward recovery.
