# Phase 1 worker isolation sentinel

**Status:** Implemented with hosted rootless proof required before evidence is claimed

## Outcome

The core now has a fixed OCI adapter that launches a digest-pinned worker sentinel with no
network attachment. It uses a read-only root, drops every capability, enables
no-new-privileges, isolates PID and IPC namespaces, applies fixed resource limits, and mounts
no host paths. Exact live inspection verifies the image, identity, ownership, empty network
set, and every launch restriction before accepting the container.

Docker must report an empty network map. Podman may instead report its inert `none`
pseudo-network; that representation is accepted only when it is the sole entry and every
address, gateway, interface, endpoint, alias, option, and published-port field is empty.
Unknown or additional network state fails closed.

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
