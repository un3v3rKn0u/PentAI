# Phase 1 worker gateway attachment topology

**Status:** Implemented as a non-mutating post-attachment inspection boundary

## Outcome

PentAI can now inspect the intended post-attachment worker network shape without changing
runtime state. The bounded Docker/Podman adapter requires the exact internal, IPv6-disabled
network identity and exactly two immutable peers: the configured gateway container and the
expected worker container. Missing, additional, malformed, renamed, duplicated, or swapped
identities deny with fixed errors.

Pre-attachment inspection continues to require the gateway as the sole peer. Both states use
one bounded network-inspection parser, so runtime-specific JSON handling, output ceilings,
timeouts, and isolation checks cannot drift between lifecycle stages.

This slice issues no OCI network-connect command, changes no durable worker state, and enables
no worker workload or target-facing execution.

## Compatibility and rollback

No schema, migration, configuration, or public API change is required. Existing sole-gateway
inspection behavior remains unchanged. Rollback removes only the additive attached-topology
adapter.

An attachment coordinator, durable attachment state, fresh pre-effect re-attestation,
post-attachment monitoring, and hosted rootless bypass evidence remain required before the
gateway-only worker channel can be enabled.
