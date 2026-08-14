# Phase 1 fixture cleanup ownership verification

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

Fixture launches now carry three immutable recovery bindings: PentAI-managed ownership,
the fixed gateway-fixture role, and the durable one-use execution-claim ID. Startup cleanup
uses the claim-derived name only for discovery, then performs a bounded OCI inspection and
requires every label to match before force-removal.

A matching name with absent, malformed, or different labels is never removed. Recovery
pauses global safety and prevents gateway readiness instead.

## Safety and compatibility

Labels are fixed arguments produced by the trusted host adapter; callers cannot select or
override them. Additional runtime labels are tolerated, while all required PentAI bindings
must match exactly. Post-removal absence verification remains mandatory.

This is defense in depth for the owned TEST-NET fixture. General transports must bind
cleanup to independently verified durable identity and runtime ownership before activation.

The follow-on cleanup runtime-binding slice now additionally requires the durable runtime
ID, pinned image digest, and managed network to match labels on the cleanup target.
