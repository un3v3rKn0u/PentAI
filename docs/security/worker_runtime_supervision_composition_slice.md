# Phase 1 worker-runtime supervision composition

**Status:** Implemented as a non-executing startup and watchdog boundary

## Outcome

PentAI core now owns worker recovery and continuous containment supervision behind an
explicit, complete configuration opt-in. Startup processes durable unfinished worker records
before the first containment check and before core readiness can succeed. The watchdog then
reloads active bindings from the durable registry and constructs fresh v2 attestations from
the configured rootless runtime, internal worker network, and exact gateway-container
identity.

Disabled composition remains safe when the registry is empty, but unfinished records with no
configured cleanup path pause global safety and degrade readiness. Missing, partial, relative,
unsupported, or ambiguous runtime/network configuration denies startup or degrades with fixed
diagnostics.
Worker status is available through the authenticated core API and participates in health,
readiness, and bounded shutdown.

This slice performs no worker launch, network attachment, or workload execution.

## Compatibility and rollback

No schema, contract, or migration changes are required. Worker supervision is disabled by
default, so existing deployments retain prior behavior when no unfinished worker records
exist. Rollback removes the composition and API status route while leaving durable worker
history and execution-disabled state intact. Any unfinished record must continue to block
readiness until an approved cleanup path resolves it.

Actual worker attachment and execution, plus hosted rootless bypass evidence, remain required
for the Phase 1 exit gate.
