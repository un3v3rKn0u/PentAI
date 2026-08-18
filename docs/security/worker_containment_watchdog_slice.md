# Phase 1 worker containment watchdog

**Status:** Implemented as a non-executing supervision boundary

## Outcome

PentAI can now re-attest every registered worker containment binding before supervision
becomes ready and at a bounded interval afterward. Each fresh v2 attestation must retain the
exact expected OCI runtime and worker-gateway network identities. Duplicate or malformed
bindings, failed inspection, stale attestation, and identity or containment drift fail closed.

Any startup or watchdog failure latches degraded state, pauses new safety authority, and
requests worker termination in that order. A failed pause does not prevent the termination
request, and either control failure is reported through a fixed reason code without exposing
runtime diagnostics. Watchdog shutdown is bounded and a join timeout triggers the same
fail-closed response.

The supervisor reports `execution_enabled: false`. This slice does not register, attach, or
launch a worker, and it does not implement the termination adapter itself.

## Compatibility and rollback

No contract or database migration changes. Existing network and gateway supervisors are
unchanged. The worker monitor is inert when its trusted binding registry is empty. Rollback
removes the supervisor while leaving worker execution disabled.

The durable registry composition is documented separately. Bounded OCI termination/recovery,
actual attachment and execution, and hosted rootless bypass evidence remain required.
