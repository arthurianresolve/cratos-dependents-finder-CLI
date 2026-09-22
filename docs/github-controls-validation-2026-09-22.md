# GitHub controls: validation on 2026-09-22

This record covers the uncommitted implementation on `dev`, based on
`d1c9f54e0e3ecbb675097eb9b76761e24c790631`. It does not describe the contents of
that base commit alone. Source was frozen before the final suites; this record
and its documentation link were added afterward. No commit or push was made.

## Execution identity

- Rust 1.98.1, compiler commit
  `48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8.
- `Cargo.lock` SHA-256:
  `FC94A08EEF13AFA02CBB85343C79D39BA68DAED2F459316D30EEDC86A4A35A4C`.
- Cargo manifest, lockfile, and toolchain declaration were unchanged.
- Windows: native `x86_64-pc-windows-msvc`, repository-owner account.
- Linux: Ubuntu 24.04 in WSL, Linux toolchain, ext4 build-output directory;
  checkout accessed through `/mnt/c`. This is not an independent Linux host run.
- Both test builds disabled incremental compilation and development debug info.
  Linux compilation used two build jobs. Tests used the debug/test profile.

## Final results

| Check | Windows | Linux / WSL |
| --- | --- | --- |
| `cargo fmt --all -- --check` | Passed | Not separately run |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed | Not run |
| `cargo test --locked --all-targets --all-features --no-fail-fast -- --quiet` | Passed | Passed |
| Library tests | 375 passed, 0 failed, 5 ignored | 375 passed, 0 failed, 5 ignored |
| CLI integration tests | 14 passed, 0 failed | 14 passed, 0 failed |
| Main binary tests | 0 tests | 0 tests |

The final library test runtimes were 5.48 seconds on Windows and 5.90 seconds
on Linux; CLI tests took 1.13 and 0.15 seconds respectively. These are harness
observations, not controlled performance comparisons or production latency
measurements. Linux rebuilt dependencies after its temporary cache disappeared.

An initial Windows run under the restricted tool account encountered
access-denied errors opening owner-protected recovery files. Validation was
rerun as the repository owner without weakening key or certificate permissions.
Two genuine fixture failures exposed by that rerun were corrected before the
final suites: schedule cadence and the eligible private-profile setup.

## Recovery and compatibility evidence

The final suites include a real coherent backup/restore regression with two
repositories and encrypted artifacts. It restores an older revision-zero
backup using current completed suppression, verifies physical removal of the
target artifact and catalog evidence, preserves the other repository and
operational history, and closes storage before renaming the restored directory.
That regression also passed separately on Windows.

Additional regressions cover suppression publication/reconciliation, cleanup
retry and durable deletion intent, terminal command retries without evidence
resurrection, private-profile eligibility, provider recovery suspension, and
serialization readable by the existing worker permit-decision variants.

## Boundaries and outstanding release work

The five existing explicitly ignored tests were not run:

- `coordinator_and_catalog_capacity_gate`
- `restored_capacity_state_gate`
- `restored_fuzzy_search_gate`
- `catalog_rebuild_diagnostic_gate`
- `catalog_search_diagnostic_gate`

No 250k capacity run, representative purge/recovery resource benchmark,
production RPO/RTO determination, or real power-loss test is claimed. The
performance non-inferiority gate remains removed. API behavior tests use
controlled fixtures; they do not establish current upstream permission grants
or legal compliance. The [operator guide](github-api-and-removal.md) documents
retained operational history, external-copy handling, independent ledger
freshness, and platform durability limits. Its release checklist remains a
deployment checklist rather than a blanket certification by these test results.
