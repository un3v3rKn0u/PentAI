# PentAI Versioned Technical Contracts

The Phase 0 contracts are stored under `schemas/v1/` and use JSON Schema Draft 2020-12.

## Contracts

- `engagement-manifest-v2.schema.json` — normalized human-reviewed engagement data.
- `policy-ir-v1.schema.json` — deterministic compiled authorization policy.
- `action-intent-v1.schema.json` — immutable request for an external effect.
- `policy-decision-v1.schema.json` — deterministic decision and rule references.
- `approval-v1.schema.json` — typed human approval that satisfies policy conditions.
  Version 1.1 adds an explicitly non-cryptographic `local-transaction-sha256`
  attestation for the Phase 0 local ledger; Ed25519 remains reserved for real
  cryptographic signatures.
- `action-grant-v1.schema.json` — short-lived, signed, single-use execution authority.
- `canonical-types-v1.schema.json` — reusable canonical target value objects.

## Compatibility

- `$id` is the stable contract identity.
- Additive optional fields require a minor contract release.
- New required fields, changed semantics, or removed values require a new major contract.
- Producers include `schema_version`; consumers reject unsupported major versions.
- Unknown fields are rejected in authorization-critical objects.
- Persisted contracts are immutable and content-addressed after approval or decision.

## Authority

The manifest is reviewed input. Policy IR is compiled output. An `Approval` can satisfy only a condition already declared by Policy IR. Only the policy decision service may create a `PolicyDecision`, and only the execution broker may mint an `ActionGrant`.
