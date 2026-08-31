# AI runtime meter implementation v1

## Outcome and boundary

The implementation capability and receipt v1 contracts reserve a closed, inert source
of implementation/version, provider-type, and supported-dimension metadata for a future
runtime-meter identity producer. They do not claim accuracy, liveness, containment,
provider execution, or billable usage.

Migration 0090 adds an immutable ledger whose producer remains denied at storage. No
capability or receipt can be created. Identity binding, attestation, measurement,
authority, and execution remain disabled.

The additive production command v1 and source-bound receipt v2 reserve the exact
authenticated local principal/session, implementation/version, closed provider types,
closed dimensions, and validity needed by a future trusted producer. Migration 0091
adds a second immutable ledger whose producer also remains denied. These contracts do
not establish that an implementation truthfully supports a provider type or dimension.

The additive implementation-manifest v1 contract and deterministic compiler define the
canonical code-owned metadata that a later trusted producer must use instead of caller
claims. The manifest binds one implementation/version and artifact digest to closed
provider types and dimensions. Compilation validates and normalizes metadata only: no
manifest instance or registry is supplied, persisted, activated, or runtime-composed.

The trusted-core built-in registry is code-owned and deliberately empty. Its public
lookup accepts only an exact implementation ID, positive version, and SHA-256 artifact
digest as untrusted selectors. Malformed selectors deny distinctly; well-formed but
unregistered or artifact-mismatched selectors deny uniformly as unavailable. Internal
registry construction rejects duplicate implementation/version or manifest identities
and derives an order-independent registry digest. Caller documents cannot add entries.

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
Fresh migration, upgrades through 0089, 0090, and 0091, and rerun are idempotent through
the migration ledger. Older applications ignore the empty additive tables. Receipt v1
remains the immutable capability record; receipt v2 is only source-bound production
provenance. Destructive downgrade after future rows exist is unsupported.

## Default denial and deferred work

Unknown fields, mixed versions, malformed identities, empty, duplicate, or unsupported
provider types or dimensions, active state, identity binding, attestation, measurement,
authority, execution, and arbitrary payloads deny at contract validation. Direct insert,
update, and deletion deny at storage. Recovery cannot invent or activate a capability.

Both the capability and production-ledger producer guards remain deny-all. A later
trusted producer must authenticate the local source and derive the canonical capability
from an authoritative built-in implementation manifest or equivalent reviewed source;
the authenticated requester alone cannot establish implementation truth.

A reviewed code-owned manifest instance, capability production, meter identity
production, attestation, provider execution receipts, provider invocation, measurement,
reconciliation, budget finalization, dispatch, and runtime composition remain deferred
for independent review.
