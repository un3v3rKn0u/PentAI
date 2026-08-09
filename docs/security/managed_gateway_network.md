# Managed Gateway Network and Conformance Gate

## Outcome

PentAI can idempotently provision a named Docker or Podman bridge network with fixed
internal-only configuration and PentAI ownership labels. A separate pinned local probe
must demonstrate that direct IPv4 egress, external DNS, and IPv6 are blocked before the
runtime snapshot collector can report a safe gateway network.

This slice does not launch a worker, attach a gateway, create an HTTP socket, contact a
target, or enable execution.

## Provisioning boundary

The provisioner uses fixed commands, bounded identifiers, timeouts, and output limits.
It refuses ambiguous names, pre-existing unowned networks, changed identifiers,
non-internal networks, enabled IPv6, failed creation, and creation races. Existing
networks are re-inspected before use. It never deletes or replaces a network.

Docker networks are created as internal bridges with IP masquerading disabled. Podman
networks additionally disable network DNS. Both carry exact management, role,
deny-egress, deny-external-DNS, and PentAI-instance labels. Labels identify intended
ownership and configuration; they are not enforcement evidence.

## Conformance gate

The probe command uses a locally available SHA-256-pinned fixture image, read-only root,
all capabilities dropped, no-new-privileges, and strict process, memory, CPU, runtime,
and output bounds. It uses only the documentation-only TEST-NET addresses `192.0.2.1`,
`192.0.2.53`, and `2001:db8::1`. It does not use a real target.

The probe output is strict JSON bound to the exact network ID. Missing, malformed,
oversized, mismatched, or negative results fail closed. The runtime snapshot collector
will not issue a safe network snapshot unless all three bypass probes succeed.

## Compatibility and rollback

No database migration or contract version changes. `OciRuntimeSnapshotCollector` now
requires a `NetworkConformanceVerifier`; callers that do not supply verified evidence
fail at construction rather than retaining the earlier metadata-only assumption.
Rollback disables the new collector integration and leaves worker execution denied.
Created networks are not automatically removed because deletion is destructive and
requires a separate explicit administrative operation.

## Local and cross-platform verification limits

The available local Docker daemon reported Docker 29.6.2 without rootless mode.
PentAI therefore did not create a network or launch the probe on this machine. This is
the required safe degradation and is not a live containment pass.

Commands and parsers are covered with synthetic Docker/Podman fixtures. A reviewed,
locally built and pinned probe image, live rootless Docker and Podman runs, gateway
attachment, host firewall rules, continuous re-probing, worker termination, and direct
socket/proxy/DoH/DoT/raw-route/platform bypass matrices remain required. INV-NET-001,
INV-NET-003, INV-NET-004, INV-ISO-001, and INV-ISO-003 are not claimed verified.
