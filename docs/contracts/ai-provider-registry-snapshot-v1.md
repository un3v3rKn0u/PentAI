# AI provider registry snapshot v1

## Outcome and boundary

The registry snapshot and receipt v1 contracts reserve an exact durable digest-bound
representation of one validated provider-registry revision. The snapshot retains the
closed provider/model allowlist, safe input classifications, integer budget ceilings,
remote-provider flag, and validity window needed by later configuration-snapshot and
meter boundaries.

Migration 0081 adds the immutable metadata ledger. Migration 0083 enables only the
authenticated trusted-core producer: one exact source-bound production record must be
inserted in the same transaction before its matching snapshot. Every record remains
fixed to `inactive`, with activation, revocation, authority, and execution disabled.

The additive production-command v1 and receipt v2 prerequisite binds a future producer
to a server-derived local desktop principal and authenticated per-process session.
Migration 0082 remains producer-denied, so this added identity shape does not create a
snapshot or change receipt v1 behavior.

## Dependency and trust model

The existing registry compiler remains a pure validator. The authenticated producer
compiles the current registry, derives canonical registry and provider-list digests,
and stores one snapshot atomically under monotonic per-registry revision fencing. Later
activation and revocation must bind
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
enablement deny at the contract boundary. A snapshot insert without the exact
authenticated production record denies at storage. Update and deletion always deny.

## Compatibility, migration, and rollback

Provider registry v1 remains unchanged and pure. Provider-configuration snapshot v1,
provider-usage measurement v1, and all earlier orchestration records remain inert and
compatible. Migration 0083 is additive and preserves existing empty or immutable rows;
it replaces only the two producer-denial triggers with cross-ledger predicates.
Application rollback can read but cannot create the new records. Destructive downgrade
is unsupported.

## Deferred work

Durable activation and revocation, signature governance beyond the authenticated local
desktop source, configuration-snapshot production, meter identity,
adapter receipts, provider execution, usage measurement, accounting, dispatch, UI, and
Phase 2 demonstrations remain deferred.
