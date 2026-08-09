# PentAI Versioned Technical Contracts

The Phase 0 contracts are stored under `schemas/v1/` and use JSON Schema Draft 2020-12.

## Contracts

- `engagement-manifest-v2.schema.json` — normalized human-reviewed engagement data.
- `policy-ir-v1.schema.json` — deterministic compiled authorization policy.
- `action-intent-v1.schema.json` — immutable request for an external effect.
- `policy-decision-v1.schema.json` — deterministic decision and rule references.
- `approval-v1.schema.json` — typed human approval that satisfies policy conditions.
  Version 1.2 uses Ed25519 over the canonical document; v1.1 transactional
  attestations remain historical and cannot activate newly signed policy.
- `action-grant-v1.schema.json` — short-lived, signed, single-use execution authority.
- `network-attestation-v1.schema.json` — measured route and source identity bound to
  one active policy.
- `destination-decision-v1.schema.json` — immutable, non-executing DNS and destination
  reauthorization result.
- `canonical-types-v1.schema.json` — reusable canonical target value objects.

## Ownership and review

| Schema | Owning role | Compatibility and versioning | Required reviewers |
|---|---|---|---|
| Engagement Manifest v2 | Product Safety Lead | Contract Maintainer | Product Owner, Policy Maintainer, Security Reviewer |
| Policy IR v1 | Policy Maintainer | Contract Maintainer | Core Maintainer, independent Security Reviewer |
| ActionIntent v1 | Execution Safety Lead | Contract Maintainer | Policy Maintainer, independent Security Reviewer |
| PolicyDecision v1 | Policy Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| Approval v1.1 | Core Security Maintainer | Contract Maintainer | Product Safety Lead, independent Security Reviewer |
| ActionGrant v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| NetworkAttestation v1 | Gateway Maintainer | Contract Maintainer | Execution Safety Lead, independent Security Reviewer |
| DestinationDecision v1 | Gateway Maintainer | Contract Maintainer | Policy Maintainer, independent Security Reviewer |
| Canonical Types v1 | Policy Maintainer | Contract Maintainer | Gateway Maintainer, independent Security Reviewer |

The owning role is accountable for semantics and consumers. The Contract Maintainer is
accountable for compatibility analysis, schema release notes, and version changes.
Security-critical changes also require the heightened review policy in
`GIT_WORKFLOW.md`. While PentAI has only one maintainer, the documented
sole-maintainer exception may replace independence for internal project approval, but
the review must be recorded as non-independent and cannot satisfy an external
independent-review requirement.

## Compatibility

- `$id` is the stable contract identity.
- Additive optional fields require a minor contract release.
- New required fields, changed semantics, or removed values require a new major contract.
- Producers include `schema_version`; consumers reject unsupported major versions.
- Unknown fields are rejected in authorization-critical objects.
- Persisted contracts are immutable and content-addressed after approval or decision.

## Authority

The manifest is reviewed input. Policy IR is compiled output. An `Approval` can satisfy only a condition already declared by Policy IR. Only the policy decision service may create a `PolicyDecision`, and only the execution broker may mint an `ActionGrant`.
