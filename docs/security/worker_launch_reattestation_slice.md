# Phase 1 worker launch re-attestation

**Status:** Implemented as a non-executing launch-planning boundary

## Outcome

Worker launch planning can now obtain its v2 containment attestation directly from the
trusted attestor at the boundary instead of accepting a caller-supplied document. The
fresh measurement is validated and its attestation and worker-gateway network identities
are bound into the existing locked-down launch specification in one synchronous operation.

Production v2 measurements are timestamped only after all live runtime, network, and peer
inspections complete. Inspection time therefore cannot silently consume the attestation's
freshness window before it is issued. A deterministic timestamp remains injectable for
tests.

Missing, malformed, stale, unsafe, or failed measurement denies before a launch
specification is returned. The resulting specification remains `execution_enabled: false`;
this slice does not start or attach a container, open a socket, or enable a gateway session.

## Compatibility and rollback

The existing explicit-attestation planning function remains available to current internal
tests and consumers. Historical v1 fixture behavior and both existing schemas are unchanged,
and no database migration is required. Rollback removes the attestor-owned planner and leaves
worker execution disabled.

Immediate measurement is now available at planning, but an executing attachment boundary,
continuous peer-drift response, recovery, and hosted rootless bypass evidence remain
required.
