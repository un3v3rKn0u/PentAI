# AI runtime meter implementation v1

## Outcome and boundary

The implementation capability and receipt v1 contracts reserve a closed, inert source
of implementation/version, provider-type, and supported-dimension metadata for a future
runtime-meter identity producer. They do not claim accuracy, liveness, containment,
provider execution, or billable usage.

Migration 0090 adds an immutable ledger whose producer remains denied at storage. No
capability or receipt can be created. Identity binding, attestation, measurement,
authority, and execution remain disabled.

## Trust, privacy, and accounting

Provider types and measurement dimensions are closed names only. The contracts do not
define values, prices, tokenizers, cache treatment, streaming aggregation, retries,
batching, tool calls, partial requests, cancellation, timeouts, failures, or local-model
accounting. A future trusted producer must authenticate the implementation source and
derive all security-critical capability meaning rather than trusting a caller.

Credentials, secret references, prompts, contexts, provider responses, evidence,
targets, commands, paths, URLs, diagnostics, usage values, prices, and arbitrary payloads
are excluded. Capability metadata grants no provider, network, worker, accounting, or
execution authority.

## Compatibility, migration, and rollback

The contracts and migration are additive. Existing registry, configuration, worker,
meter identity, completion, reservation, and usage-measurement versions remain unchanged.
Fresh migration, upgrade from 0089, and rerun are idempotent through the migration
ledger. Older applications ignore the empty table. Destructive downgrade after future
rows exist is unsupported.

## Default denial and deferred work

Unknown fields, mixed versions, malformed identities, empty, duplicate, or unsupported
provider types or dimensions, active state, identity binding, attestation, measurement,
authority, execution, and arbitrary payloads deny at contract validation. Direct insert,
update, and deletion deny at storage. Recovery cannot invent or activate a capability.

Authenticated capability production, meter identity production, attestation, provider
execution receipts, provider invocation, measurement, reconciliation, budget
finalization, dispatch, and runtime composition remain deferred for independent review.
