# Local-model policy representation v1

## Scope

Engagement Manifest v3 and Policy IR v2 add exactly one non-network capability:
`ai.local.generate`. The existing manifest validator and Policy IR compiler remain
available for v2/v1 HTTP policy. The new entry points validate v3 and deterministically
compile v2 without evaluating an ActionIntent, signing or activating a policy, minting
a grant, or executing a model.

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

Both versions are additive. Existing Engagement Manifest v2 validation and Policy IR
v1 compilation remain unchanged. No persistence changes, so rollback consists of
removing the new producer entry points; older consumers reject versions they do not
support.

## Deferred work

Policy signing and activation for the new versions, ActionIntent v2 evaluation,
PolicyDecision and ActionGrant versions, runtime/model artifact verification,
supervised adapter execution, authenticated execution receipts, usage measurement,
accounting, and recovery demonstrations remain deferred.
