# Local-model policy representation v1

## Scope

Engagement Manifest v3 and Policy IR v2 add exactly one non-network capability:
`ai.local.generate`. The existing manifest validator and Policy IR compiler remain
available for v2/v1 HTTP policy. The new entry points validate v3 and deterministically
compile v2 without evaluating an ActionIntent, activating a policy, minting a grant,
or executing a model. The authorization service now persists validated Manifest v3
and signs the resulting Policy IR v2 under the distinct `pentai-policy-v2` domain.

The engagement manifest supplies only the reviewed allow, deny, or conditional effect
and existing source provenance. It cannot select a runtime, model, artifact, path,
command, provider behavior, usage meaning, or execution authority. Those identities
remain bound by the local-model ActionIntent boundary.

## Default-deny and compatibility

Unknown capabilities, duplicate or contradictory effects, mixed versions, malformed
documents, and local capability input bearing runtime-specific fields deny. HTTP
capabilities retain their exact method requirements; local generation has no invented
HTTP method or target rule. Compilation rechecks the closed capability set and validates
the resulting Policy IR v2 contract.

Both versions are additive. Existing Engagement Manifest v2 validation, Policy IR v1
compilation, signing, approval, activation, and HTTP evaluation remain unchanged.
Migration 0093 makes Policy IR v2 rows immutable, retained, and storage-enforced
inactive. Byte-equivalent compilation reuses the same deterministic bundle; changed
manifests produce distinct history. Application rollback must first verify that no v2
rows exist, or retain the migration guards while older code ignores those rows.
Migration 0095 preserves content immutability and retention while permitting only the
exact Approval v2-backed activation edge and later revocation.

Policy Activation Approval v2 records an authenticated human approve or reject decision
for one exact current Manifest v3 and inactive Policy IR v2 tuple. Its signature uses
the `pentai-policy-activation-approval-v2` domain. Migration 0094 storage-checks its
closed version, identity, hash, decision, actor, timestamp, and no-authority bindings
against the durable policy and manifest rows. Approval is immutable chronology only.
Trusted core may consume an exact current approved record to activate the corresponding
Policy IR v2, but neither approval nor activation authorizes evaluation, grants, or
execution.

## Deferred work

PolicyDecision v2 evaluation is now available as non-authorizing metadata. Local-model
approval consumption, ActionGrant v2, runtime/model artifact verification, supervised
adapter execution, authenticated execution receipts, usage measurement, accounting,
and recovery demonstrations remain deferred.
