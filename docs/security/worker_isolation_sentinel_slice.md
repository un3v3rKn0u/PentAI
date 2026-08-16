# Phase 1 worker isolation sentinel

**Status:** Implemented with hosted rootless proof required before evidence is claimed

## Outcome

The core now has a fixed OCI adapter that launches a digest-pinned worker sentinel with no
network attachment. It uses a read-only root, drops every capability, enables
no-new-privileges, isolates PID and IPC namespaces, applies fixed resource limits, and mounts
no host paths. Exact live inspection verifies the image, identity, ownership, empty network
set, and every launch restriction before accepting the container.

Docker must report an empty network map. Podman may omit that map, report it empty, or
report its inert `none` pseudo-network. Every accepted representation still requires all
address, gateway, interface, endpoint, alias, option, and published-port fields to be empty.
Podman's bounded namespace identifiers may be non-empty because they identify the isolated
namespace rather than an attachment. Unknown or additional connectivity state fails closed.

Malformed identities, mutable image references, runtime failures, any network attachment,
privilege drift, missing labels, or host binds fail closed. Termination accepts only a
canonical container identity.

## Safety and compatibility

This slice creates no persistence, schema, migration, socket, HTTP effect, grant consumption,
or product execution path. Rollback removes the unused adapter and tests.

The sentinel intentionally uses `network=none`; it cannot yet communicate with a gateway.
The rootless Podman conformance harness now launches the immutable sentinel, verifies its
live process capabilities and complete no-network OCI state, and terminates it by canonical
container ID. Changes to the adapter trigger that hosted job. A run is evidence only after
the corresponding protected workflow passes.

The next worker-network slice must introduce a distinct internal worker-to-gateway channel,
prove that the gateway is its only peer, re-attest after launch, and add hosted rootless
bypass evidence before any HTTP/browser worker can execute.
