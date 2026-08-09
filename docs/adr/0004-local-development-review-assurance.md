# ADR 0004: Sole-maintainer assurance for local development

- **Status:** Accepted
- **Date:** 2026-08-09
- **Decision owner:** `un3v3rKn0u`, sole maintainer, Product Owner, Security Lead, and
  repository owner
- **Review classification:** Sole-maintainer security review — non-independent

## Context

PentAI currently has one human maintainer. The former governance rule required an
independent reviewer for all signing-key custody, which made local development unable
to progress after the implementation had otherwise passed its technical and
cross-platform checks. PR #26 was merged before that governance requirement was met.

Calling the maintainer or an AI system independent would be inaccurate. Silently
ignoring the requirement would also make the repository's assurance claims unreliable.

## Decision

The sole-maintainer exception may cover signing-key custody only for local development
keys confined to the maintainer's device. Every use must be recorded as
non-independent, include a separate security-review pass, disclose all roles held by
the reviewer, record evidence and residual risk, and pass every applicable automated
check.

This exception does not cover production or release signing/notarization, distributed
or third-party keys, customer systems, production release authorization, destructive
migrations, disclosure decisions involving another party, or any external requirement
for independent or dual-control review.

Local-development approval does not authorize target-facing networking by itself.
Gateway containment, controlled DNS, route and source-IP attestation, redirect
reauthorization, emergency stops, revocation, negative bypass tests, and the applicable
Phase exit gates remain mandatory.

## Consequences and accepted risk

Development can continue without misrepresenting the review as independent. Assurance
is lower because one person designed, implemented, and reviewed the custody path, and
shared assumptions may remain undiscovered. The project explicitly accepts that risk
for synthetic, owned local fixtures only.

Independent review remains the preferred upgrade and becomes mandatory when the scope
crosses any excluded boundary. When another qualified regular reviewer becomes
available, the exception must be re-evaluated prospectively.

## Compatibility and rollback

This decision changes governance claims, not runtime behavior, contracts, schemas,
migrations, keys, or persisted records. Reverting it restores the independent-review
gate without changing application data. Work that crossed the restored gate would
become blocked until independently reviewed; it would not become retrospectively
independent.
