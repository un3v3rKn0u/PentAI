# Phase 0 status matrix

This matrix separates implementation from verification and approval. A checked roadmap
item means code exists; it does not imply that the Phase 0 exit gate is approved.

| Safety area | Implemented | Locally verified | Cross-platform verified | Approved | Remaining gate |
|---|---:|---:|---:|---:|---|
| Authenticated desktop-to-core bootstrap | Yes | Yes | Pending hosted CI | No | Independent security review |
| Packaged core ownership and lifecycle | Yes | Yes on macOS | Pending hosted CI | No | Windows and Ubuntu CI evidence |
| Sidecar provenance | SHA-256 before spawn | Yes on macOS | Pending hosted CI | No | Developer signing/notarization |
| Authorization vertical slice | Yes | Yes | Python CI pending | No | Independent security review |
| Contract compatibility | Seven schemas plus Approval 1.1 | Yes | CI pending | No | Record schema owners/approvers |
| Canonicalization | Fixture coverage | Yes | CI pending | No | Property and differential testing |
| OS credential store | No | No | No | No | Platform proof of concept |
| Threat model | Local transport model exists | Reviewed in-tree | No | No | Workshop, owners, approval |
| Security invariants | Proposed register exists | Partial test mapping | No | No | Owners and formal approval |

## Local trust-boundary evidence

- Every `/api/v1/*` route requires the current per-launch bearer credential.
- The authenticated principal is server-side; submitted display identifiers are not
  treated as proof of authority.
- Missing, malformed, incorrect, and absent credentials receive uniform denial.
- Desktop startup waits for authenticated readiness and fails closed.
- Normal desktop shutdown terminates and reaps the owned core.
- Packaged sidecar smoke coverage includes unauthenticated callers, incorrect
  credentials, authenticated shutdown, port collision, and credential-output checks.
- The sidecar digest is embedded at desktop build time and verified before execution.

## Invariant evidence

`INV-AUTH-005` is partially enforced by removing caller-controlled activation authority
and binding approval/activation to the authenticated local desktop session. Automated
tests prove that request actor metadata cannot establish that principal. Strong human
identity or user-presence proof is not yet implemented, so the invariant remains
proposed and requires an owner and security approval.

## Decision

Do not begin ActionGrant issuance or target-facing networking until hosted
cross-platform lifecycle checks pass and the local trust boundary receives independent
security approval. The broader Phase 0 exit gate also remains open for canonicalization,
credential-store, ownership, and approval evidence.
