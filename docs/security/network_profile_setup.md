# Supervised network profile setup

## Outcome

PentAI can inspect the host's current default interface, gateway, and resolver
addresses and present them as a short-lived `Network Profile Proposal v1`. This reduces
manual transcription while preserving the human authorization boundary.

The proposal is not a profile, approval, attestation, or grant. It is persisted only
as immutable, expiring review input and cannot enable execution. The authenticated
local API and UI leave route confirmation, resolver-mode selection, and registered
public source-IP entry unresolved. Discovery does not call public-IP observers or any
target.

After explicit human confirmation, PentAI creates one durable `Network Profile v1`.
The profile remains non-executing, is immutable except for an active-to-revoked
transition, and is linked to the exact stored proposal and hash-chained audit event.
An active profile must be explicitly revoked before another can be activated.

## Failure and authority boundaries

- Missing, malformed, oversized, ambiguous, or unsupported observations
  return the fixed `NETWORK_PROFILE_DISCOVERY_FAILED` diagnostic.
- Identical resolver entries emitted by the OS are canonicalized to one value.
- Raw command output and exception details are not returned to the UI.
- Proposal lifetime is bounded to ten minutes; the default is five minutes.
- Expired pending proposals are closed before new storage, and no more than 64
  proposals may await confirmation.
- Route and resolver identifiers are deterministic hashes of canonical local
  observations, but the proposal identifier is unique.
- Empty registered source-IP arrays and `execution_enabled: false` are contract
  constants. A consumer cannot reinterpret the object as authority.
- Proposal creation creates no audit event because no authorization-bearing choice is
  made. Activation and revocation are human-only authenticated operations and append
  privacy-minimized audit events without raw registered source addresses.
- Activation rejects missing confirmation, stale/unknown/replayed proposals,
  malformed or non-public source addresses, resolver/IPv6 conflicts, and an existing
  active profile.

## Compatibility and rollback

Migration `0012_network_profiles.sql` adds proposal and profile tables, immutable
history triggers, and the one-active-profile constraint without transforming existing
rows. The API and v1 contract are additive, so older clients remain compatible.
Rollback disables the endpoints and UI while retaining inert history; dropping the
tables is intentionally not automated because it would destroy security audit linkage.

## Deferred work

Profile-to-policy binding now requires exact route identity, registered source arrays,
IPv6 mode, and resolver mode before an attestor can be composed. Observer designation
and availability proof, live source-IP observation, controlled resolver provisioning
from the profile, and cross-platform live evidence remain deferred. A confirmed
profile is configuration, not a network attestation or execution authority.
Target-facing execution remains prohibited.
