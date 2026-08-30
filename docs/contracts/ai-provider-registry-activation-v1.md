# AI provider registry activation prerequisite v1

## Outcome and boundary

The activation command and receipt v1 contracts define the exact authenticated,
digest-bound lifecycle record required before an inactive provider-registry snapshot
can become current. Migration 0084 adds immutable storage and migration 0085 enables
only the authenticated trusted-core producer under an exact snapshot-production
predicate.

The receipt represents lifecycle coordination only. It keeps configuration-
snapshot production and revocation disabled and remains fixed to `authority: none` and
`execution_enabled: false`. It cannot enable a provider, resolve a secret, attest a
meter, invoke a provider, measure usage, dispatch work, or perform an external effect.

## Exact lineage and default denial

The command binds one exact authenticated snapshot-production result: snapshot and
receipt digests, registry identity and revision, canonical registry and provider-list
digests, server-derived local principal, per-process session, purpose, and bounded
validity. The producer revalidates the immutable snapshot, its production receipt,
registry expiry, latest per-registry revision, current safety state, and lifecycle
concurrency in one immediate transaction. While any activation remains unexpired, a
competing activation denies; replacement and explicit revocation remain separate work.

Mixed versions, missing or changed digests, stale or expired snapshots, cross-registry
substitution, caller-selected identity or authority, competing activation, and direct
storage writes deny. Byte-equivalent replay requires the same authenticated session and
current immutable receipt. Snapshot presence and an activation-shaped command are not
activation evidence.

## Compatibility, migration, and rollback

Provider registry v1, snapshot v1, production command v1, and production receipt v2
remain unchanged. Migration 0085 preserves the table and existing rows while replacing
only the deny-all producer trigger. Application rollback preserves immutable activation
rows but cannot create new ones; destructive downgrade is unsupported.

## Deferred work

Supersession before expiry, explicit revocation, expiry recovery, configuration-snapshot
production, meter identity, provider execution, measurement, accounting, dispatch, UI,
and Phase 2 demonstrations remain separately reviewed work.
