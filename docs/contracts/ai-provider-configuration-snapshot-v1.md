# AI provider configuration snapshot v1

## Outcome and boundary

The snapshot and receipt v1 contracts reserve an exact durable provider/model
configuration identity for a future trusted runtime meter. They bind the existing
configuration hash to one registry revision, provider type and identity, model, privacy
zone, input classifications, integer ceilings, and validity window. Both shapes are
inert: `state` is `inactive`, `meter_binding_enabled` is false, `authority` is `none`,
and `execution_enabled` is false.

Migration 0080 adds an immutable metadata ledger. Its producer is deliberately denied
at storage, so no snapshot or receipt can currently be created. The slice does not
activate a registry entry, attest a meter, invoke a provider, resolve a secret, measure
usage, reconcile an account, or finalize a reservation.

The additive production command v1 and production receipt v2 now reserve the
authenticated source and exact active-registry lineage required by a future producer.
They bind one command identity, server-derived local principal and process session,
registry activation and receipt digest, registry snapshot and production receipt
digests, configuration identity/hash, provider/model identity, and only the digest of
an opaque remote secret reference. Migration 0086 stores no rows because its producer
remains deny-all. The original snapshot and receipt v1 contracts remain unchanged.

## Privacy, secrets, and accounting

Remote snapshots retain only a digest of the opaque provider-bound secret reference;
the reference and credential value are excluded. Local runtime snapshots require the
secret digest to be absent and the remote opt-in to be false. Raw prompts, contexts,
provider responses, evidence, targets, diagnostics, commands, paths, URLs, pricing,
tokenizer rules, and arbitrary payloads are not representable.

Budget fields are configuration ceilings, not measured or billable usage. Quantities
are bounded integers in explicit units. Retry capacity is not part of the snapshot.
The contracts define no price calculation, tokenizer, cache treatment, streaming
aggregation, provider retry, partial-request, cancellation, or failure semantics.

## Compatibility, migration, and rollback

The existing pure AI provider configuration and registry v1 contracts remain unchanged
and do not become durable or active through this slice. Migrations 0080 and 0086 are
additive and empty on upgrade; earlier provider, task, completion, reservation, and
measurement contracts and rows are unchanged. Application rollback leaves inert empty
tables. Destructive downgrade is unsupported.

## Default denial and deferred work

Unknown fields, mixed provider/privacy behavior, raw secret references, invalid
identifiers, non-integer or excessive ceilings, activation, meter binding, or authority
deny at the contract boundary. Direct insertion, update, and deletion deny at storage.

Authenticated registry-snapshot production and activation are now prerequisites in the
durable lineage. Authenticated configuration-snapshot production, runtime-meter identity
and attestation, adapter execution receipts, pricing and tokenizer policy, provider
execution, usage production, reconciliation, reservation closure, dispatch, and runtime
composition remain deferred and require independent default-deny boundaries.
