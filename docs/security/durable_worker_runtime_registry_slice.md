# Phase 1 durable worker-runtime registry

**Status:** Implemented as non-executing durable composition

## Outcome

PentAI now records a worker launch intent before any container identity can be associated
with it. The record binds one worker to the exact fresh v2 containment attestation, OCI
runtime instance, worker-gateway network, and digest-pinned image. A successful later
container binding is a version-fenced transition and exposes the exact durable binding to
the containment watchdog.

Duplicate active containment identities, malformed or stale evidence, mutable identities,
container rebinding, invalid transitions, deletion, and any attempt to enable execution fail
closed. Startup recovery can enumerate both pre-effect launch intents and active or failed
records without guessing which runtimes belong to PentAI.

This slice persists identities only. It does not launch, attach, terminate, or execute a
worker.

## Compatibility and rollback

Migration `0030_worker_runtime_registry.sql` is additive and does not change existing
tables or contracts. Existing deployments may apply it without backfill. Older binaries
ignore the new table, and rollback disables registry composition while leaving its protected
history intact and worker execution disabled.

Bounded OCI termination and recovery are documented separately. Actual worker attachment and
execution, and hosted rootless bypass evidence remain required for the Phase 1 exit gate.
