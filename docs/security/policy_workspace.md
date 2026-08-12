# Supervised Policy lifecycle workspace

The Policy workspace presents the existing manifest and signed-policy lifecycle without
changing policy semantics. Validation saves one immutable canonical manifest version and
shows contract issues, history, and the semantic diff from its predecessor. Compilation
uses the core signer and displays the exact compiled policy and full content digest.

Approval and activation are separate actions. A human chooses approved or rejected,
supplies a mandatory bounded reason and a valid future expiry, and records that typed
decision first. The UI accepts the response only when its exact policy identity, digest,
and decision match the displayed request. Activation becomes available only after a
confirmed approval in the current component instance, and its response must repeat the
exact policy identity and active status. Changing engagement, policy, manifest content,
decision, expiry, or reason clears the local approval gate.

Revocation requires a new bounded reason and validates the exact revoked response. The
core remains authoritative for signature verification, manifest/policy hashes, approval
expiry and validity, engagement state, replacement, revocation, and all audit events.
The UI cannot activate a rejected decision, mint a grant, or execute an action.

No endpoint, contract, schema, migration, signing, or persistence behavior changes.
Rollback restores the earlier combined presentation without changing immutable records.
