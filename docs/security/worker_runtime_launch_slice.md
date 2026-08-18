# Phase 1 durable worker-runtime launch

**Status:** Implemented as a non-executing isolated-sentinel lifecycle

## Outcome

PentAI can now turn one fresh worker-role containment measurement into a durable isolated
worker sentinel. The coordinator persists the exact runtime, network, attestation, and pinned
image identity before invoking OCI, launches with the existing no-network controller, verifies
the immutable container identity and every least-privilege control, and only then exposes the
record to continuous supervision as `running`.

Any launch, inspection, or final binding failure invokes exact-worker recovery. Crash-gap
discovery uses the pre-effect ownership labels, and cleanup verifies ownership before bounded
removal. Targeted cleanup cannot sweep unrelated active workers. If cleanup itself fails, the
durable record remains retryable and the caller receives a fixed diagnostic without OCI detail.

This slice creates only the inert sentinel. It does not attach the worker to the gateway
network, execute a workload, or add target-facing authority.

## Compatibility and rollback

No schema, migration, or public API changes are required. Existing runtime, registry,
recovery, and supervision callers remain compatible. Rollback removes the launch coordinator;
all durable unfinished records must still be processed by startup recovery before readiness.

Gateway-only attachment, post-attachment containment monitoring, workload execution, and
hosted rootless bypass evidence remain required for the Phase 1 exit gate.
