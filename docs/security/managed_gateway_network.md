# Managed Gateway Network and Conformance Gate

## Outcome

PentAI can idempotently provision a named Docker or Podman bridge network with fixed
internal-only configuration and PentAI ownership labels. A separate pinned local probe
must demonstrate that direct IPv4 egress, external DNS, IPv6, runtime sockets, host
mounts, host PID namespaces, and resource-limit bypasses are blocked before the runtime
snapshot collector can report a safe gateway network.

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

The repository-owned probe is a dependency-free Rust binary packaged in a `scratch`
image as UID/GID 65532. The build has no base image or package-manager step. CI builds
the static binary locally, obtains the content-addressed image ID, and invokes the
runtime by that `sha256:` identity rather than by its temporary tag. The probe accepts
only the fixed TEST-NET destinations and an exact bounded network identifier.

The probe output is strict JSON bound to the exact network ID. Missing, malformed,
oversized, mismatched, legacy, or negative results fail closed. The runtime snapshot
collector will not issue a safe network snapshot unless every bypass probe succeeds.
The runtime command additionally uses a read-only root, dropped capabilities,
no-new-privileges, private default namespaces, and fixed CPU, memory, and PID limits.

The CI harness refuses to build an image or create a network until the selected runtime
reports rootless operation. It creates randomly named, run-scoped fixtures and removes
only those fixtures. Image construction uses `--pull=false` and `--network=none`; the
probe makes TCP connection attempts only to the three documented TEST-NET addresses.

## Compatibility and rollback

No database migration or public contract version changes. The internal conformance
result adds four mandatory booleans; legacy three-signal probe output is intentionally
incompatible and denied. Rollback removes the opt-in harness and probe fixture while
leaving worker execution denied. The general provisioner remains non-destructive. The
CI harness removes only its UUID-named run-scoped network and image.

## Local and cross-platform verification limits

The available local Docker daemon reported Docker 29.6.2 without rootless mode.
PentAI therefore did not create a network or launch the probe on this machine. This is
the required safe degradation and is not a live containment pass.

Commands and parsers are covered with synthetic Docker/Podman fixtures, and the probe
has dependency-free Rust argument tests. Hosted Linux rootless Podman execution is the
first live conformance target. Until that hosted job passes, no live containment claim
is made. Rootless Docker, macOS, Windows, gateway attachment, host firewall rules,
continuous re-probing, worker termination, and proxy/DoH/DoT/raw-route platform bypass
matrices remain required. INV-NET-001, INV-NET-003, INV-NET-004, INV-ISO-001, and
INV-ISO-003 are not claimed verified.
