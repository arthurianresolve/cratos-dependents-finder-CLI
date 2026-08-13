# ADR 0002: Explicit repository scope and deterministic policy

- Status: accepted
- Date: 2026-08-13

## Decision

Repository visibility is a typed scope. `public_only` is the compatibility
default even when a broad credential is present. `all_visible` requires the
explicit `--include-private` opt-in and authentication, and includes public,
private, and internal repositories visible to that credential.

Policy is versioned TOML evaluated against a canonical evidence bundle. License
and vulnerability rules use pinned, locally recorded data snapshots. Exceptions
are metadata-only, exact-subject, approved, justified, and expiring. Unknown or
incomplete evidence is indeterminate by default and maps to exit code 4; a known
policy violation maps to exit code 5.

Distributed jobs do not accept an unverifiable policy hash. At export, the
operator supplies the canonical TOML policy, an explicit report destination,
and optionally a pinned data snapshot. Evaluation uses the durable job update
time and the exact merged bundle, making unchanged exports reproducible.

## Consequences

Private discovery adds no calls to the public path. Private cache namespaces are
credential-principal scoped and encrypted. Policy evaluation performs no
per-repository network calls, is stable-sorted, and can run offline. CSV and
Markdown are adapters over typed evidence rather than policy inputs.
