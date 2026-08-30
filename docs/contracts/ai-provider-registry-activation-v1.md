# AI provider registry activation prerequisite v1

## Outcome and boundary

The activation command and receipt v1 contracts reserve the exact authenticated,
digest-bound lifecycle record required before an inactive provider-registry snapshot
can become current. Migration 0084 adds immutable storage whose producer is deny-all,
so no activation receipt can currently be created and no snapshot becomes active.

The future receipt represents lifecycle coordination only. It keeps configuration-
snapshot production and revocation disabled and remains fixed to `authority: none` and
`execution_enabled: false`. It cannot enable a provider, resolve a secret, attest a
meter, invoke a provider, measure usage, dispatch work, or perform an external effect.

## Exact lineage and default denial

The command binds one exact authenticated snapshot-production result: snapshot and
receipt digests, registry identity and revision, canonical registry and provider-list
digests, server-derived local principal, per-process session, purpose, and bounded
validity. The later producer must revalidate the immutable snapshot, its production
receipt, registry expiry, current safety state, lifecycle concurrency, and recovery
state in one transaction.

Mixed versions, missing or changed digests, stale or expired snapshots, cross-registry
substitution, caller-selected identity or authority, competing activation, and direct
storage writes must deny. Snapshot presence and an activation-shaped command are not
activation evidence.

## Compatibility, migration, and rollback

Provider registry v1, snapshot v1, production command v1, and production receipt v2
remain unchanged. Migration 0084 is additive and empty on upgrade. Application rollback
leaves an unused deny-all table; destructive downgrade is unsupported.

## Deferred work

Authenticated activation production, one-current-active enforcement, supersession,
revocation, expiry recovery, configuration-snapshot production, meter identity,
provider execution, measurement, accounting, dispatch, UI, and Phase 2 demonstrations
remain separately reviewed work.
