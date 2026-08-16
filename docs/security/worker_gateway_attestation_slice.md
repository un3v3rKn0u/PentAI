# Phase 1 worker gateway attestation contract

**Status:** Implemented as a non-executing contract boundary

## Outcome

Worker launch planning now requires a v2 containment attestation with the exact
`worker_gateway` network role and a distinct `worker_gateway_network_id`. The historical v1
attestation remains available only to existing gateway-to-owned-fixture consumers. A v1
fixture attestation, wrong role, additional legacy network identity, malformed document, or
stale measurement cannot produce a worker launch plan.

The resulting launch specification remains digest-pinned, locked down, and explicitly
non-executing. This slice does not create a network, launch a worker, contact a gateway, or
authorize an external destination.

## Safety and compatibility

The new required role and renamed network identity change authorization semantics, so the
worker attestation receives a new major version. Existing v1 gateway-fixture consumers are
unchanged. No database schema or migration is required because attestations and launch plans
remain transient validated documents.

Rollback removes the v2 schema and restores worker planning to v1, but that would reintroduce
network-role ambiguity and must not be used once a worker-gateway producer exists.

The next slice must construct and inspect a distinct internal worker-to-gateway network,
prove the gateway is its only peer, and keep worker execution disabled until hosted rootless
bypass evidence passes.
