# AI provider registry snapshot production prerequisite v1

## Outcome and boundary

The snapshot-production command v1 and receipt v2 reserve the authenticated local-core
identity needed by a future provider-registry snapshot producer. They bind one exact
snapshot, registry revision, canonical registry digest, normalized provider-list digest,
server-derived local desktop principal, and per-process authenticated session.

Migration 0082 adds an immutable production ledger whose producer remains deny-all.
The command and receipt are intentionally fixed to `production_enabled: false`,
`authority: none`, and `execution_enabled: false`; no command can currently be consumed
and no receipt can currently be created.

## Authentication and trust model

The future trusted producer must derive the requester from the authenticated local-core
transport. A caller cannot choose a principal, session, role, delegation, proxy, signer,
or production privilege. The existing Ed25519 policy signer is not widened: ADR 0003
limits it to policy and approval material, and current provider-registry documents are
contract-valid but unsigned.

The future producer must compile the registry with the existing deterministic validator,
normalize provider, model, and input-classification arrays into documented lexical order,
and derive canonical JSON SHA-256 digests in trusted core. This prerequisite stores no
registry document and implements none of those producer semantics.

## Privacy and default denial

The contracts and table accept only bounded identifiers, digests, revisions, principal
and session identity, closed purpose and authentication values, and timestamps. They
exclude registry documents, credentials, secret references, private keys, signatures,
prompts, contexts, provider responses, evidence, targets, diagnostics, commands, paths,
URLs, and arbitrary payloads.

Direct insertion, update, and deletion remain storage-denied. Snapshot production,
activation, revocation, configuration-snapshot production, meter registration, provider
execution, usage measurement, accounting, authority, and external effects remain
disabled.

## Compatibility, migration, and rollback

Provider registry v1 and provider-registry snapshot/receipt v1 remain unchanged. Receipt
v2 is additive and cannot be substituted for receipt v1 or used to create a snapshot.
Migration 0082 is additive and empty on upgrade. Application rollback leaves an unused
empty table; destructive downgrade is unsupported.

## Deferred work

Authenticated production service composition, canonical normalization implementation,
monotonic revision and rollback enforcement, source signing or governance, snapshot
activation and revocation, configuration-snapshot production, meter identity, adapter
receipts, provider execution, measurement, reconciliation, finalization, dispatch, UI,
and Phase 2 demonstrations remain deferred.
