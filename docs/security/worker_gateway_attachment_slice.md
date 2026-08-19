# Phase 1 bounded worker gateway attachment

**Status:** Implemented as a non-executing gateway-only attachment boundary

## Outcome

PentAI can now attach one verified isolated worker sentinel to its exact internal gateway
network. The coordinator obtains fresh v2 containment evidence, persists the exact
version-fenced worker, container, network, gateway, attachment strategy, and attestation
identities before the effect. Docker invokes one fixed and bounded OCI `network connect`.
Rootless Podman, which cannot connect a container launched with network mode `none`, launches
directly on the already attested internal network. Both strategies require exact worker-control
and two-peer gateway/worker inspection before recording `attached`.

Any connect, topology, or final-state failure records a durable failed attachment and invokes
ownership-verified exact-worker termination. Cleanup attempts both state failure and runtime
termination even if either control fails, and exposes only fixed diagnostics. Attached records
remain explicitly `execution_enabled: false`; the sentinel workload stays inert.

## Compatibility and rollback

Migration `0034` adds immutable, default-deferred attachment strategy and gateway identity
columns to the worker runtime intent. Existing records and Docker callers remain compatible.
Podman's unsupported post-launch connection is rejected before an OCI effect.

Rollback removes the coordinator and connector. Any durable prepared, attached, or failed
record must still block execution and its exact worker must be recovered before readiness.
Production composition, startup attachment recovery, continuous attached-topology monitoring,
hosted rootless bypass evidence, and actual worker HTTP/browser execution remain required.
