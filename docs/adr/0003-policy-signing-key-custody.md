# ADR 0003: Local policy-signing key custody

- **Status:** Proposed — independent security approval required
- **Date:** 2026-08-09
- **Decision owner:** Security Lead
- **Approval constraint:** `GIT_WORKFLOW.md` forbids the sole-maintainer exception for
  signing-key custody.

## Context

Phase 1 requires active policies and human approvals to be cryptographically verified.
The existing transactional SHA-256 attestation linked database fields but was not a
signature and could not establish possession of a signing key.

## Proposed decision

The desktop creates a 32-byte Ed25519 seed using the operating-system CSPRNG only when
the credential service definitively reports no existing entry. It stores that seed as
`policy-signing-seed-v1` under `local.pentai.desktop`, retrieves it fail-closed, and
delivers it once to the authenticated core over inherited standard input. The seed is
not placed in arguments, environment variables, logs, APIs, SQLite, or audit events.

The core derives a stable key ID from SHA-256 of the raw public key. The Policy IR
content hash binds both the unsigned policy document and that signer key ID, and the
core signs the domain-separated hash and canonical Approval v1.2 document. Policy
activation and evaluation require matching database/document key IDs and valid
Ed25519 signatures. Missing, malformed, wrong-key, or altered signatures deny.

## Compatibility and recovery

Unsigned and transaction-attested legacy policies remain readable as history but are
ineligible for activation. They must be recompiled and reapproved with the current
key. Loss or corruption of the credential-store entry blocks compilation, approval,
activation, and evaluation; it does not silently generate a replacement except for a
definite missing-entry result. Recovery requires an explicit key-rotation procedure,
recompilation, and new human approvals. Key rotation and backup remain deferred.

Rolling back application code does not remove the credential or signed records.

## Review gate

This ADR and its implementation must not be merged or described as approved until a
qualified independent security reviewer accepts key generation, storage, delivery,
domain separation, verification, loss behavior, and cross-platform credential-service
evidence. The sole-maintainer review exception is not applicable.
