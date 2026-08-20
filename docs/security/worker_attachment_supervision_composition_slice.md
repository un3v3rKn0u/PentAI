# Phase 1 worker attachment supervision composition

**Status:** Implemented as a fail-closed production startup and monitoring boundary

## Outcome

Strict worker supervision now recovers every unfinished network attachment before it
recovers residual worker runtimes or performs the first readiness measurement. A worker can
therefore never become ready while an uncertain prepared, attached, or failed attachment is
still unresolved.

The continuous watchdog selects verification from durable state. Unattached workers must
retain the exact no-network isolation controls and fresh gateway-only containment. Attached
workers must retain the exact image, ownership labels, resource and privilege controls, one
expected internal network, and the exact gateway/worker two-peer topology. Prepared, failed,
malformed, duplicated, or ambiguous state degrades readiness, pauses new authority, and
requests exact-worker termination.

## Compatibility and rollback

No schema or migration changes are required. The existing runtime and attachment registries
are joined read-only for supervision. Rolling back removes attachment-aware readiness, so
execution must remain disabled until the newer supervisor is restored and completes recovery.

Hosted worker-to-gateway execution and its rootless bypass matrix remain required before the
Phase 1 worker item or exit gate can be completed.
