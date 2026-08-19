# Phase 1 worker attachment recovery

**Status:** Implemented as a non-executing crash-recovery boundary

## Outcome

PentAI can now recover every unresolved prepared, attached, or failed worker-network
attachment after interruption. Recovery first converts any uncertain non-failed attachment to
durable failure, then requires ownership-verified exact-worker termination before appending an
immutable recovery receipt. If earlier cleanup already terminated the worker, recovery records
the receipt without repeating the OCI removal effect.

The coordinator attempts every unresolved attachment before returning one fixed aggregate
error. Failed termination remains durable and retryable, one bad worker cannot hide later
records, and resolved attachments no longer re-enter the queue. Recovery receipts bind the
exact attachment version and remain immutable, undeletable, and execution-disabled.

## Compatibility and rollback

Migration `0032_worker_attachment_recoveries.sql` adds one independent receipt table and does
not alter existing attachment or worker-runtime records. No backfill is required. Older
binaries ignore the receipts but may conservatively revisit already resolved attachment rows;
therefore rollback must keep execution blocked until worker-runtime state proves termination.

Production startup composition, continuous attached-topology supervision, hosted rootless
bypass evidence, and actual HTTP/browser worker execution remain required.
