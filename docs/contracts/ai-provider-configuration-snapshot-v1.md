# AI provider configuration snapshot v1

## Outcome and boundary

The snapshot and receipt v1 contracts reserve an exact durable provider/model
configuration identity for a future trusted runtime meter. They bind the existing
configuration hash to one registry revision, provider type and identity, model, privacy
zone, input classifications, integer ceilings, and validity window. Both shapes are
inert: `state` is `inactive`, `meter_binding_enabled` is false, `authority` is `none`,
and `execution_enabled` is false.

Migration 0080 adds the immutable metadata ledger. Migration 0087 replaces its deny-all
producer with an exact trusted-core predicate: an authenticated local session may now
record one inactive snapshot only from the exact current registry activation and
immutable registry-production lineage. Production does not activate a registry entry,
attest a meter, invoke a provider, resolve a secret, measure usage, reconcile an account,
or finalize a reservation.

The additive production command v1 and production receipt v2 now reserve the
authenticated source and exact active-registry lineage required by a future producer.
They bind one command identity, server-derived local principal and process session,
registry activation and receipt digest, registry snapshot and production receipt
digests, configuration identity/hash, provider/model identity, and only the digest of
an opaque remote secret reference. The trusted service derives every digest and durable
field, revalidates the active registry, provider/model allowlist, privacy route, integer
ceilings, validity, safety state, and remote secret-reference metadata, then atomically
stores the production and snapshot records. The original snapshot and receipt v1
contracts remain unchanged.

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

The existing pure AI provider configuration and registry v1 contracts remain unchanged.
Migration 0087 is additive and changes only producer guards; earlier provider, task,
completion, reservation, and measurement contracts and rows are unchanged. Application
rollback leaves produced immutable metadata readable but an older application cannot
produce new snapshots. Destructive downgrade and deletion of future rows are unsupported.

## Default denial and deferred work

Unknown fields, mixed provider/privacy behavior, invalid identifiers, non-integer or
excessive ceilings, stale or corrupt lineage, changed or cross-session replay, safety
pause, meter binding, or authority deny. The opaque secret reference exists only in the
authenticated request long enough to validate its metadata; durable records contain
only its digest. Direct insertion without the exact production lineage, update, and
deletion deny at storage. Startup recovery never invents or resumes production.

Authenticated registry-snapshot production, activation, and configuration-snapshot
production now form the durable provenance lineage. Registry supersession/revocation,
runtime-meter identity and attestation, adapter execution receipts, secret resolution,
pricing and tokenizer policy, provider execution, usage production, reconciliation,
reservation closure, dispatch, and runtime composition remain deferred and require
independent default-deny boundaries.
