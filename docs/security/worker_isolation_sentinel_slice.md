# Phase 1 worker isolation sentinel

**Status:** Implemented as a non-executing local boundary; hosted proof deferred

## Outcome

The core now has a fixed OCI adapter that launches a digest-pinned worker sentinel with no
network attachment. It uses a read-only root, drops every capability, enables
no-new-privileges, isolates PID and IPC namespaces, applies fixed resource limits, and mounts
no host paths. Exact live inspection verifies the image, identity, ownership, empty network
set, and every launch restriction before accepting the container.

Malformed identities, mutable image references, runtime failures, any network attachment,
privilege drift, missing labels, or host binds fail closed. Termination accepts only a
canonical container identity.

## Safety and compatibility

This slice creates no persistence, schema, migration, socket, HTTP effect, grant consumption,
or product execution path. Rollback removes the unused adapter and tests.

The sentinel intentionally uses `network=none`; it cannot yet communicate with a gateway.
The next worker-network slice must introduce a distinct internal worker-to-gateway channel,
prove that the gateway is its only peer, re-attest after launch, and add hosted rootless
bypass evidence before any HTTP/browser worker can execute.
