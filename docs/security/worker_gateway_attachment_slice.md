# Phase 1 bounded worker gateway attachment

**Status:** Implemented as a non-executing gateway-only attachment boundary

## Outcome

PentAI can now attach one verified isolated worker sentinel to its exact internal gateway
network. The coordinator obtains fresh v2 containment evidence, persists the exact
version-fenced worker, container, network, gateway, and attestation identities before the
effect, invokes one fixed and bounded OCI `network connect`, and requires the exact two-peer
gateway/worker topology before recording `attached`.

Any connect, topology, or final-state failure records a durable failed attachment and invokes
ownership-verified exact-worker termination. Cleanup attempts both state failure and runtime
termination even if either control fails, and exposes only fixed diagnostics. Attached records
remain explicitly `execution_enabled: false`; the sentinel workload stays inert.

## Compatibility and rollback

No schema, migration, configuration, or public API change is required. The coordinator
consumes migration `0031`, the existing fresh v2 attestor, exact topology inspector, durable
worker recovery, and bounded command executor. Existing callers remain compatible.

Rollback removes the coordinator and connector. Any durable prepared, attached, or failed
record must still block execution and its exact worker must be recovered before readiness.
Production composition, startup attachment recovery, continuous attached-topology monitoring,
hosted rootless bypass evidence, and actual worker HTTP/browser execution remain required.
