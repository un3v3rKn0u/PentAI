# Phase 1 worker gateway peer isolation

**Status:** Implemented as a non-executing OCI inspection boundary

## Outcome

PentAI can provision the existing fixed internal worker-to-gateway network and then
independently inspect its live OCI peer set. The inspection succeeds only when the exact
network identity remains internal with IPv6 disabled and the exact expected gateway
container is its sole peer. A missing gateway, an additional peer, a renamed gateway, or
network identity and isolation drift fails closed.

The result binds the verified network and gateway container identities for a later
containment-attestation producer. It does not attach or launch a worker, open a socket,
contact a resolver or target, or enable a prepared gateway session.

## Trust boundary

The inspector accepts only Docker or Podman, an absolute runtime executable, and bounded
identifiers. It issues one fixed network-inspection command with a five-second timeout and
a 64 KiB output ceiling. Docker and Podman output are parsed separately and must contain
exactly one expected document and peer mapping. Runtime values are never included in error
messages.

The expected gateway container identity must come from the trusted gateway lifecycle; UI,
AI, manifests, plugins, and workers are not trusted identity producers. Live inspection is
a point-in-time fact, not ongoing authority. A later slice must bind it into fresh worker
containment attestation, revalidate immediately before attachment, and monitor drift.

## Compatibility and rollback

No public contract or database migration changes. Existing fixture-network provisioning
and conformance probes are unchanged. Rollback removes the inspector and leaves worker
execution disabled. Hosted rootless peer and bypass evidence remains required before the
worker isolation item or target-facing execution can be considered complete.
