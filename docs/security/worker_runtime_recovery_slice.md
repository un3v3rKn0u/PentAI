# Phase 1 bounded worker-runtime recovery

**Status:** Implemented as a non-executing termination and startup boundary

## Outcome

PentAI can now terminate every unfinished durable worker record before startup continues and
can provide the same adapter to the containment watchdog. Records with a persisted container
identity are never removed until a bounded OCI inspection proves the exact container ID and
all PentAI ownership labels. A launch intent interrupted after container creation but before
identity persistence uses a fixed, bounded, exact-label query; zero results finalize without
an OCI effect, exactly one result is durably bound and verified, and ambiguous results deny.

The registry records `termination_requested` before removal. Successful removal finalizes the
record, while inspection or removal failure persists `failed` for a later retry. Recovery
attempts every candidate and returns only a fixed incomplete-recovery error after processing
the set, so one bad runtime cannot hide another unfinished worker or leak OCI diagnostics.

This slice does not attach a worker to a network or enable worker execution.

## Compatibility and rollback

No schema, contract, or migration changes are required. The coordinator consumes migration
`0030` lifecycle states and the existing Docker/Podman controller. Older callers remain
compatible. Rollback removes recovery composition while leaving unfinished durable records
and execution-disabled state intact; startup must remain blocked until an approved cleanup
path resolves those records.

Actual worker attachment and execution, plus hosted rootless bypass evidence, remain required
for the Phase 1 exit gate.
