# ADR 0006: GitHub admission and durable repository suppression

- Status: accepted; release validation required
- Date: 2026-09-22

## Context

Cratos identifies dependent repositories to inform maintainer priorities and
evaluate migration from unmaintained dependencies to maintained alternatives.
It currently collects bounded evidence from crates.io and GitHub. Personal
operation and individually reviewed contributions are the selected use case;
GitHub outreach-writing automation and hosted third-party services are not
introduced by this decision.

The GitHub client previously classified rate limits before reading error
bodies, used overly short fallbacks, and did not share standalone cooldowns.
Private inventory grants needed consistent current-profile eligibility.
Existing age-based retention did not provide explicit repository suppression
and targeted evidence removal.

## Decision

Centralize GitHub response classification in the client. Read bounded error
bodies before permit feedback, preserve sensitive-header/redaction controls,
and share cooldowns across standalone client clones. Preserve bounded retries;
return structured deferral instead of sleeping through long provider waits.
Keep installation and user-token modes explicit without inspecting secrets.

The single coordinator retains encrypted provider state. In this personal-use
deployment, primary deadlines are shared per GitHub resource and secondary
recovery is deployment-wide. Recovery admits one probe at a time, suspends
after three unsuccessful automatic probes, and requires explicit Admin resume.
Resume cannot erase an upstream deadline. Existing permits, task leases,
authorization, and idempotency remain distinct authorities.

One privacy-policy service coordinates suppression publication with inventory
and artifact operations. Admin control endpoints plan exact repository-ID and
namespace removal, publish durable suppression, and expose cleanup status and
retry. Aliases supplement stable identity. Accepted suppression excludes the
repository before search selection/ranking/pagination and before new evidence
acceptance; already serialized responses cannot be recalled.

Small encrypted policy/progress records belong to the coordinator actor.
Physical cleanup is bounded, restartable, and reference-aware. Failed cleanup
does not restore visibility. Operational job/task history retains its existing
expiry/reference rules rather than being rewritten to imply that past work
never happened. Suppression has no automatic expiry or unsuppress operation.

Publish an independently retained authenticated encrypted ledger using a
dedicated key. Publish immutable policy on admission, not the entire ledger
after every cleanup batch. Reconcile interrupted publication before readiness.
Backup-set format 3 binds policy identity, revision, and digest; every restore,
including a revision-zero backup, requires current independently retained
policy and repeats cleanup in staging before exposure.
Suppression-aware storage rejects older runtimes that would ignore its policy.

Standalone scans can opt into the ledger. They conservatively apply the union
of scopes because no coordinator credential-profile mapping exists, check
aliases/IDs during collection, and recheck policy before output publication.
An independent unconfigured scan is not governed by another deployment's ledger.

## Consequences and limits

No database replacement, plaintext operational queue index, worker outreach
protocol, or evidence-format change is required. Private searchable metadata
still needs restrictive host permissions, full-disk encryption, and protected
backups; encrypted evidence does not encrypt the entire read model.

Provider throttling can be more conservative than a multi-account deployment
needs. That tradeoff is intentional for personal use, not an assertion that
all GitHub credentials have independent quotas.

An accepted removal is distinct from completed cleanup, retained operational
history, upstream GitHub token revocation, and local profile disablement.
External exports, older backups, and filesystem remnants are not erased.
This design is encrypted storage, not oblivious storage or secure erasure;
record counts, ciphertext sizes, equality, and access patterns can remain
observable.

Latestness requires an independently retained current ledger or trusted newer
checkpoint. An equally old backup/ledger pair cannot prove absence of later
policy. Legacy sets predating deployment identity additionally require an
operator-verified association with their supplied ledger; new sets carry an
explicit binding. Applying nonempty policy to an unbound legacy set requires
the explicit `--accept-legacy-ledger-binding` operator attestation.

These controls do not settle interpretation of GitHub's agreements, establish
approval, or create a legal-compliance guarantee. Publication of support/data
handling contacts and review of individually submitted contributions remain
operator responsibilities.

## Verification

The [operator release checklist](../github-api-and-removal.md#release-checklist)
covers rate-limit recovery, current-profile authorization, suppression races,
bounded cleanup, independent policy publication, and staged recovery on Windows
and Linux. Performance measurements inform tuning; they do not reinstate the
removed performance non-inferiority gate. Test results and recovery-capacity
claims require dated execution evidence rather than this ADR alone.
