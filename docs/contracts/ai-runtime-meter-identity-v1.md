# AI runtime meter identity v1

## Outcome and boundary

The identity and receipt v1 contracts reserve the smallest durable provenance shape
needed before a runtime can be considered as a possible provider-usage measurement
source. One identity binds an implementation and version to one exact inactive provider-
configuration snapshot, provider/model, durable worker-runtime version, runtime instance,
containment attestation, image digest, closed set of supported measurement dimensions,
and bounded validity window.

The record is deliberately inert. Its state is `inactive`; attestation and measurement
remain disabled; authority is `none`; and execution is disabled. Migration 0088 adds an
immutable ledger whose producer is denied at storage. No identity or receipt can yet be
created, and the provider-usage producer from migration 0079 remains deny-all.

## Trust, privacy, and accounting

Identity metadata is not proof that a provider request occurred, that a meter is
accurate, or that reported usage is billable. The contracts do not define pricing,
tokenizers, cached-token treatment, streaming aggregation, provider-side retries,
batching, tool calls, partial requests, cancellation, timeouts, failures, or local-model
accounting. Unsupported behavior must deny in later boundaries rather than be estimated.

Credentials, opaque secret references, prompts, contexts, provider responses, evidence,
targets, commands, paths, URLs, diagnostics, usage amounts, prices, and arbitrary payloads
are excluded. Supported dimensions are closed names only; the identity carries no usage
values and grants no provider, worker, network, accounting, or execution authority.

## Compatibility, migration, and rollback

The contracts are additive and do not change provider configuration, configuration-
snapshot, worker-runtime, completion, reservation, or usage-measurement v1 semantics.
Migration 0088 creates one empty table and four default-deny triggers. Fresh migration,
upgrade from 0087, and rerun are idempotent through the migration ledger. Application
rollback leaves an empty table ignored by older code. Destructive downgrade is
unsupported.

## Default denial and deferred work

Unknown fields, mixed versions, malformed identities, unsupported dimensions, duplicate
dimensions, active state, measurement enablement, authority, execution, and provider or
diagnostic payloads deny at contract validation. Direct insertion, mutation, and deletion
deny at storage. Recovery has no producer and cannot invent, activate, renew, attest, or
measure from an identity.

Authenticated identity production, exact current configuration and worker revalidation,
meter attestation, configuration binding, execution receipts, provider invocation,
measurement production, reconciliation, budget finalization, dispatch, and runtime
composition remain deferred for independent review.
