# ADR 0003: Versioned evidence and encrypted retention

- Status: accepted
- Date: 2026-08-13

## Decision

The canonical product record is `EvidenceBundleV1`, including immutable source
identities, deterministic inclusion witnesses, categorical evidence strength,
completeness, limitations, and collection/reuse provenance. Existing CSV remains
an additive projection.

The implementation does not retain raw Cargo content. A 30-day raw-content
retention class is reserved for a future explicitly approved workflow, but data
minimization currently wins: only derived evidence is application-encrypted with
AES-256-GCM. Evidence and audit records expire after 365 days by default. Cache
objects are addressed by an internal SHA-256 digest; GitHub blob SHA values
remain source provenance and are never trusted as the internal integrity digest.

Corrupt, expired, or analyzer-incompatible objects are quarantined or refetched,
never emitted as evidence. The coordinator indexes only complete derived
evidence by repository ID, immutable tree, exact target, semantic analyzer
bounds, analyzer version, and evidence-profile version. Public entries use the
public namespace; all-visible entries use an exact credential-profile principal
namespace. Every scan still resolves current repository metadata and the
default-branch HEAD. A matching immutable tree can reuse authenticated evidence
without downloading the recursive tree or Cargo blobs, and the new observation
records that reuse in its explanation chain.
