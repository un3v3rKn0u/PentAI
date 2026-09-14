# Local-model artifact registry activation prerequisite v1

## Outcome and boundary

The command and receipt contracts reserve the exact authenticated lifecycle record
required before local-model artifact manifest v1 can become current. Migration 0097
adds empty immutable storage with its producer disabled.

This prerequisite does not activate the registry. It performs no artifact discovery,
installation, file access, hashing, GGUF parsing, verification, receipt production,
approval consumption, grant issuance, model loading, process launch, or execution.

## Authoritative lineage and default denial

Both contracts pin the exact repository-owned manifest ID, revision, and canonical
digest. They reserve a server-authenticated local human principal and process session,
bounded command time, ADR 0008's 180-day review period, and no-authority lifecycle
flags. A future producer must derive those values from the built-in resolver,
authenticated middleware, trusted time, current safety state, and durable storage; a
caller document is never an authoritative source.

Missing, additional, mixed-version, substituted, payload-bearing, verifying,
revoking, granting, or executing fields deny. Storage independently binds both JSON
documents to typed columns, rejects direct production, and forbids update and delete.

## Replay, concurrency, expiry, and recovery

No producer exists, so replay, competing activation, expiry, revocation, cancellation,
fencing, and startup recovery cannot create or advance state. The future producer must
derive deterministic replay identity, serialize activation, enforce exact current
lineage and safety, calculate the expiry from its trusted activation instant, and make
startup read-only.

## Compatibility and rollback

This is additive v1 storage and two additive schemas. Existing APIs, data, manifests,
policy decisions, grants, and runtime behavior are unchanged. Upgrade creates an empty
table. Application rollback cannot produce rows; destructive database downgrade is
unsupported.

## Deferred work

Authenticated activation production, revocation, supersession, rollback, installation,
artifact verification and receipts, persistence reconciliation, ActionGrant v2, model
loading, supervision, metering, and execution remain unavailable.
