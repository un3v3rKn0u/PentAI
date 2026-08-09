# Runtime Snapshot Collector

## Outcome

PentAI has a deterministic Docker/Podman inspection adapter for the worker-containment
preflight. The adapter executes only fixed, non-launching runtime information and
network-inspection commands, applies a five-second timeout and 256 KiB output limit,
parses a single JSON object, and converts accepted data into typed runtime and
gateway-network snapshots.

This slice does not create a network, launch a container, connect to a target, or enable
execution.

## Trust and ownership checks

The collector requires an absolute runtime executable, fixed Docker/Podman command
templates, bounded identifiers that cannot be interpreted as command options, an exact
runtime-instance identity, and an exact gateway-network identity. The network must carry
all PentAI management, role, deny-egress, deny-external-DNS, and application-instance
labels. Missing or mismatched labels deny the snapshot.

The local executor resolves the configured executable, rejects group/world-writable
binaries, does not invoke a shell, supplies a minimal environment, discards standard
error, bounds command arguments and runtime, and stops reading after the output limit.
Raw runtime output and errors are not returned in diagnostics.

Docker 24+ and Podman 4.6+ are the supported parser baselines. The collector requires
rootless mode, runtime resource-limit support, an internal network, and disabled IPv6.
All missing, malformed, oversized, ambiguous, or mismatched observations fail closed
before an attestation can be issued.

## Compatibility and rollback

No contract or database migration changes. The collector implements the existing
`RuntimeInspector` interface and produces the existing typed snapshots. Rollback removes
the adapter and leaves containment attestation and worker execution unavailable.

## Assurance boundary and deferred work

Management labels bind the observed network to expected local PentAI configuration;
they do not prove firewall behavior against a compromised runtime or local
administrator. Internal-network and label inspection also does not replace live direct
socket, alternate proxy, DNS, IPv4, IPv6, raw-route, runtime-socket, mount, IPC, and
resource-exhaustion tests.

Fixture parsers were tested for Docker and Podman, but no local daemon was invoked and
no cross-platform runtime output was verified in this slice. Platform collectors,
managed-network creation, continuous reinspection, live sandbox probes, worker launch,
and termination remain required. INV-NET-001, INV-NET-003, INV-NET-004, INV-ISO-001,
and INV-ISO-003 are not claimed verified.
