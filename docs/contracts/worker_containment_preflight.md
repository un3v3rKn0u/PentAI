# Worker Containment Preflight v1

## Outcome

The core can turn a prepared, explicitly non-executing gateway session and a fresh
runtime containment attestation into a digest-pinned worker launch specification. The
specification remains non-executing. This slice does not start a process or container.

## Authority boundary

Neither contract grants authority. A gateway session must already be bound to the
deterministic authorization chain, and a future execution broker must independently
load and verify that durable state immediately before launch. AI, UI, plugins, and
workers must not produce trusted containment attestations.

The attestation is valid for at most 60 seconds and fails closed if it is malformed,
future-dated, expired, or reports any missing control. Required measurements include:

- rootless runtime operation;
- a read-only root filesystem, all capabilities dropped, and no-new-privileges;
- no host PID, IPC, host network, or container-runtime socket;
- enforceable CPU, memory, and process limits and temporary-only mounts;
- a gateway-only internal network with direct egress, external DNS, and IPv6 disabled.

`RuntimeContainmentAttestor` is the trusted producer boundary. It accepts only typed
snapshots from an injected `RuntimeInspector`, requires every runtime and managed-network
control, converts successful measurements into the versioned contract, and validates
the result again before returning it. Inspection exceptions fail closed and diagnostics
do not include raw runtime output.

The inspector is an internal privileged adapter, not a worker or plugin extension
point. Production implementations must use fixed runtime operations, authenticate the
runtime instance and PentAI-managed network, bound all output, and must not accept
commands or flags from AI, UI, manifests, plugins, or workers.

`OciRuntimeSnapshotCollector` supplies this fixed-command boundary for Docker and
Podman. It verifies the expected runtime and managed-network identities, exact PentAI
ownership/control labels, rootless operation, resource-limit availability, internal
networking, and disabled IPv6 before emitting typed snapshots. See
`docs/security/runtime_snapshot_collector.md` for its assurance limits.

Launch plans require an immutable SHA-256 image digest, bounded argument vector, fixed
resource limits, and `execution_enabled: false`. Free-form shell evaluation is not a
consumer of this contract.

## Compatibility and rollback

Both schemas are v1 and reject unknown fields. Any relaxation or new required field
requires a new major version. Rollback consists of removing the producer and refusing
worker launch planning; existing authorization and gateway-session records are
unchanged. This slice adds no database migration or persisted runtime authority.

## Deferred verification

Cross-platform Docker/Podman output verification, container launch, gateway-network
construction, host firewall enforcement, runtime re-attestation,
worker termination, and platform-specific escape/bypass probes remain deferred. Until
those exist and pass, INV-NET-001, INV-NET-003, INV-NET-004, INV-ISO-001, and
INV-ISO-003 are not claimed verified and target-facing execution remains prohibited.
