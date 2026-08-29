# AI provider registry snapshot v1

## Outcome and boundary

The registry snapshot and receipt v1 contracts reserve an exact durable digest-bound
representation of one validated provider-registry revision. The snapshot retains the
closed provider/model allowlist, safe input classifications, integer budget ceilings,
remote-provider flag, and validity window needed by later configuration-snapshot and
meter boundaries.

Migration 0081 adds an immutable metadata ledger whose producer remains deny-all. No
snapshot or receipt can currently be created. Every record is fixed to `inactive`, with
activation, revocation, authority, and execution disabled.

The additive production-command v1 and receipt v2 prerequisite binds a future producer
to a server-derived local desktop principal and authenticated per-process session.
Migration 0082 remains producer-denied, so this added identity shape does not create a
snapshot or change receipt v1 behavior.

## Dependency and trust model

The existing registry compiler remains a pure validator. A future authenticated
producer must compile the current registry, derive canonical registry and provider-list
digests, and store the snapshot atomically. Later activation and revocation must bind
that immutable snapshot through separately reviewed versioned records; neither state is
inferred from the presence of a snapshot.

A provider-configuration snapshot cannot safely become durable from a transient caller
registry alone. It must eventually reference an exact current registry snapshot and
activation state. Runtime-meter identity, adapter execution, measurement production,
pricing, reconciliation, and finalization remain downstream.

## Privacy and default denial

Registry snapshots exclude credentials, secret references, prompts, contexts, provider
responses, evidence, targets, diagnostics, pricing, tokenizer rules, commands, paths,
URLs, signatures supplied as authority, and arbitrary payloads. Secret and restricted
raw-evidence classifications are not representable in the normalized provider list.

Unknown fields, unsafe classifications, malformed identities or digests, invalid
integer ceilings, activation or revocation claims, and authority or execution
enablement deny at the contract boundary. Direct insertion, update, and deletion deny
at storage.

## Compatibility, migration, and rollback

Provider registry v1 remains unchanged and pure. Provider-configuration snapshot v1,
provider-usage measurement v1, and all earlier orchestration records remain inert and
compatible. Migration 0081 is additive and empty on upgrade. Application rollback
leaves an unused empty table; destructive downgrade is unsupported.

## Deferred work

Authenticated snapshot production service composition, canonical normalization,
signature/source governance, durable activation
and revocation, rollback protection, configuration-snapshot production, meter identity,
adapter receipts, provider execution, usage measurement, accounting, dispatch, UI, and
Phase 2 demonstrations remain deferred.
