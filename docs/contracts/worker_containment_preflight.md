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

Launch plans require an immutable SHA-256 image digest, bounded argument vector, fixed
resource limits, and `execution_enabled: false`. Free-form shell evaluation is not a
consumer of this contract.

## Compatibility and rollback

Both schemas are v1 and reject unknown fields. Any relaxation or new required field
requires a new major version. Rollback consists of removing the producer and refusing
worker launch planning; existing authorization and gateway-session records are
unchanged. This slice adds no database migration or persisted runtime authority.

## Deferred verification

Actual Docker/Podman discovery, trusted runtime measurement, container launch,
gateway-network construction, host firewall enforcement, runtime re-attestation,
worker termination, and platform-specific escape/bypass probes remain deferred. Until
those exist and pass, INV-NET-001, INV-NET-003, INV-NET-004, INV-ISO-001, and
INV-ISO-003 are not claimed verified and target-facing execution remains prohibited.
