# Phase 1 supervised Authorization workspace

**Status:** Implemented; sole-maintainer security review recorded

The Authorization workspace presents the existing non-executing authorization chain as
three separate supervised steps: create and evaluate an `ActionIntent`, mint a single-use
grant only from an exact allow decision, and verify/consume that grant locally.

Every response is checked against the displayed intent, assessment, policy hash, decision,
audience, capability, parameters digest, single-use requirement, and consumption receipt.
A denied or approval-required decision cannot unlock grant issuance. Policy or safety
state changes clear displayed authority. Editing the target clears the whole local chain.

Evaluation is deterministic local policy work and explicitly makes no target connection.
Grant consumption records authorization use but launches no gateway, worker, socket, or
external effect. This slice changes no schema, migration, policy semantics, grant service,
or execution behavior. Rollback restores the inline simulator without changing records.
