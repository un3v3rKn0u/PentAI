# Supervised network profile setup

## Outcome

PentAI can inspect the host's current default interface, gateway, and resolver
addresses and present them as a short-lived `Network Profile Proposal v1`. This reduces
manual transcription while preserving the human authorization boundary.

The proposal is not a profile, approval, attestation, or grant. It is never persisted
and cannot enable execution. The authenticated local API and UI always leave route
confirmation, resolver-mode selection, and registered public source-IP entry
unresolved. Discovery does not call public-IP observers or any target.

## Failure and authority boundaries

- Missing, malformed, oversized, ambiguous, or unsupported observations
  return the fixed `NETWORK_PROFILE_DISCOVERY_FAILED` diagnostic.
- Identical resolver entries emitted by the OS are canonicalized to one value.
- Raw command output and exception details are not returned to the UI.
- Proposal lifetime is bounded to ten minutes; the default is five minutes.
- Route and resolver identifiers are deterministic hashes of canonical local
  observations, but the proposal identifier is unique.
- Empty registered source-IP arrays and `execution_enabled: false` are contract
  constants. A consumer cannot reinterpret the object as authority.
- Discovery creates no audit event because no authorization-bearing state changes.
  The later confirmation/activation slice must persist and audit every human choice.

## Compatibility and rollback

This is an additive authenticated endpoint and a new v1 contract. There is no schema
migration and no persisted data to roll back. Older clients can ignore the endpoint.
Rollback removes the endpoint and UI card without changing existing policy,
attestation, or runtime records.

## Deferred work

Durable profile persistence, explicit confirmation, resolver-mode configuration,
registered source-IP validation, observer designation, activation, revocation, and
audit linkage remain deferred. Target-facing execution remains prohibited.
