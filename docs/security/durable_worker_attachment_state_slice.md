# Phase 1 durable worker attachment state

**Status:** Implemented as non-executing pre-effect attachment persistence

## Outcome

PentAI can now persist one exact worker-network attachment intent before a future OCI
network-connect effect. The record requires a fresh worker-role v2 containment attestation
and atomically matches its runtime and network identities to one exact version-fenced running
worker, immutable container ID, and trusted gateway container ID.

The additive lifecycle permits only `prepared → attached` or `prepared/attached → failed`.
Every transition is version fenced; identities, timestamps of origin, execution-disabled
state, and history cannot be rewritten or deleted. Prepared, attached, and failed records are
enumerable for future startup recovery, and duplicate attachment authority denies.

This slice does not invoke OCI, attach a network, change worker supervision, or enable a
workload or target-facing execution.

## Compatibility and rollback

Migration `0031_worker_network_attachments.sql` adds one independent table and does not alter
existing runtime records or contracts. Existing deployments require no backfill; older
binaries ignore the new table. Rollback removes registry composition while preserving the
protected records. Any prepared or attached record must continue to block execution until an
approved recovery path resolves it.

The attachment coordinator, network-connect adapter, exact post-effect topology verification,
startup recovery composition, continuous attached-topology monitoring, and hosted rootless
bypass evidence remain required.
