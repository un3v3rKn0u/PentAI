# Phase 1 worker containment attestor v2

**Status:** Implemented as a non-executing attestation boundary

## Outcome

PentAI can now combine the existing rootless runtime and network-conformance inspection
with the exact live sole-gateway peer verification to issue a short-lived v2 worker
containment attestation. The producer binds the expected worker-gateway network and gateway
container identities before emitting the worker-specific `worker_gateway` role.

Missing or unsafe runtime controls, network or gateway identity drift, an unsafe network
signal, failed inspection, malformed identity, and an invalid lifetime fail closed. The
attestation remains valid for no more than 60 seconds and is validated against the existing
v2 contract before it leaves the producer.

## Authority and compatibility

The attestor accepts only typed observations from trusted runtime and peer inspectors. UI,
AI, manifests, plugins, and workers cannot supply measurements. The gateway container
identity is an input to production and live comparison but is intentionally not embedded in
the v2 contract; the attestation binds the verified network identity and network role.

Historical v1 fixture attestation production and validation are unchanged. No contract
change or database migration is required. Rollback removes the v2 producer and leaves worker
launch planning unavailable because no fresh worker attestation can be issued.

## Deferred work

This slice does not attach or launch a worker, open a socket, enable a gateway session, or
monitor subsequent peer drift. Immediate re-attestation at attachment, continuous drift
response, recovery, and hosted rootless bypass evidence remain required.
