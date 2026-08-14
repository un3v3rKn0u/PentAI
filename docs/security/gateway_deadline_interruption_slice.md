# Phase 1 gateway deadline interruption

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

The host adapter now derives the OCI command timeout from the same durable absolute
deadline passed to the isolated Rust client. The inner client stops socket activity using
one monotonic deadline, while the bounded host executor independently kills a command that
does not return by that boundary.

Timeout is translated into a fixed `HTTP_FIXTURE_DEADLINE` denial. Even when the executor
returns success, completion observed at or after the effective boundary is reclassified
as `deadline_exceeded` before durable finalization.

## Safety and compatibility

The effective deadline remains the earlier of the committed request deadline and the
fixture's five-second ceiling. Clock observations must be timezone-aware. No caller can
extend the timeout independently from the signed and committed authority.

This applies only to the fixed TEST-NET fixture transport. General HTTP(S), redirect,
worker, and external-target transports remain disabled and must adopt the same dual-layer
deadline pattern before they can be enabled.
