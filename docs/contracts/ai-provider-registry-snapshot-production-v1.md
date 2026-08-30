# AI provider registry snapshot production prerequisite v1

## Outcome and boundary

The snapshot-production command v1 and receipt v2 reserve the authenticated local-core
identity needed by a future provider-registry snapshot producer. They bind one exact
snapshot, registry revision, canonical registry digest, normalized provider-list digest,
server-derived local desktop principal, and per-process authenticated session.

Migration 0082 adds the immutable production ledger. Migration 0083 enables its sole
authenticated trusted-core producer while the command and receipt remain fixed to
`production_enabled: false`, `authority: none`, and `execution_enabled: false`.

## Authentication and trust model

The future trusted producer must derive the requester from the authenticated local-core
transport. A caller cannot choose a principal, session, role, delegation, proxy, signer,
or production privilege. The existing Ed25519 policy signer is not widened: ADR 0003
limits it to policy and approval material, and current provider-registry documents are
contract-valid but unsigned.

The trusted core compiles the registry,
sorts provider, model, and input-classification arrays into documented ASCII lexical
order, and derives separate canonical JSON SHA-256 digests for the complete registry and
normalized provider list. The authenticated local endpoint supplies only the registry,
command identity, and bounded validity; requester identity and session come exclusively
from middleware. One immediate transaction enforces monotonic revision, stores the
source-bound production receipt, then stores the matching inactive snapshot under
deferred foreign-key verification.

Byte-equivalent replay requires the same command, authenticated session, current
registry validity, and intact immutable hashes. Changed replay, competing equal or lower
revisions, forks, rollback, global safety pause, stale validity, and corrupted history
deny with stable codes.

## Privacy and default denial

The contracts and table accept only bounded identifiers, digests, revisions, principal
and session identity, closed purpose and authentication values, and timestamps. They
exclude registry documents, credentials, secret references, private keys, signatures,
prompts, contexts, provider responses, evidence, targets, diagnostics, commands, paths,
URLs, and arbitrary payloads.

Direct snapshot insertion without its exact production record remains storage-denied;
orphan production cannot commit because of the foreign key. Update and deletion remain
denied. Activation, revocation, configuration-snapshot production, meter registration,
provider execution, usage measurement, accounting, authority, and external effects
remain disabled.

## Compatibility, migration, and rollback

Provider registry v1 and provider-registry snapshot/receipt v1 remain unchanged. Receipt
v2 is additive and cannot be substituted for receipt v1 or used to create a snapshot.
Migration 0083 preserves existing rows and constraints while replacing only deny-all
producer triggers with exact predicates. Application rollback leaves immutable inactive
records that older code cannot produce or activate; destructive downgrade is unsupported.

## Deferred work

Source signing or governance beyond the existing authenticated local source, snapshot
activation and revocation, configuration-snapshot production, meter identity, adapter
receipts, provider execution, measurement, reconciliation, finalization, dispatch, UI,
and Phase 2 demonstrations remain deferred.
