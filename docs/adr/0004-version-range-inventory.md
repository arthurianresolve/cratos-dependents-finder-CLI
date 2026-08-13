# ADR 0004: Standalone version-range inventory

## Status

Accepted.

## Decision

Standalone `scan` accepts either `--version VERSION` or
`--version-range REQUIREMENT`. A fully specified `=x.y.z` range is normalized
to the exact selector. Range scans produce CSV and summary output; canonical
evidence bundles, policy evaluation, data-snapshot enrichment, durable jobs,
cache fingerprints, and `links` remain exact-version contracts.

Published requirement overlap is evaluated against one complete crates.io
sparse-index release catalog for the target crate. Yanked releases remain in
that universe because existing lockfiles may retain them. The catalog's exact
response digest is recorded. Invalid declarations remain unknown, and a false
intersection is asserted only after a complete catalog was parsed.

Each repository snapshot, manifest, and lockfile is fetched and parsed once.
Range lock evidence records every concrete matching version and source, plus
deterministic direct and transitive witnesses. A match is confirmed only when a
recorded root reaches at least one selected concrete package. Root-only or
unreachable presence stays unclassified.

CSV schema V2 appends selector-generic columns while retaining the existing
exact columns and meanings. In range rows, exact-only status is
`not_applicable`; selector-generic matching fields carry the range result.

## Consequences

- A range scan adds exactly one target-catalog request, not one scan per release.
- Cargo prerelease semantics come from `semver::VersionReq`.
- Bounded GitHub code discovery searches by crate name for range lockfiles and
  remains supplemental and non-exhaustive.
- A future range-aware policy or distributed protocol requires a separate
  versioned evidence artifact and agent capability; it cannot silently mutate
  exact V1 evidence.
