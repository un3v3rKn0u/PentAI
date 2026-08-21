# AI assessment retrieval v1

## Outcome and boundary

The retrieval-policy, request, and result v1 contracts provide deterministic,
assessment-scoped access-control filtering over validated `UntrustedContentEnvelope v1`
records. The slice returns metadata only: envelope identity, origin, classification,
provenance, content digest, validity, and instruction-like annotations. It never returns
content, constructs a model context, performs search, contacts a provider, or creates
execution authority.

`authority` and `execution_enabled` are fixed to `none` and `false` on policy, request,
result, and every result item. Retrieved metadata cannot represent policy activation,
approval, capability, tool arguments, secret access, network authority, `ActionIntent`,
or `ActionGrant`.

## Trusted policy and exact access control

A contract-valid current policy binds one assessment and revision to explicit subjects.
Each exact subject has an explicit purpose set, origin set, classification set, and
maximum result count. The compiler creates immutable permission snapshots and rejects
duplicate subjects. There is no parent, role, wildcard, group, worker, or agent
privilege inheritance.

Policy origin authentication and activation are not implemented here. The catalog
constructor is a trusted-core dependency-injection boundary; untrusted callers must not
supply or select policy documents. Durable authenticated policy activation is required
before exposing this component through an API or agent runtime.

Every request binds the exact assessment, subject, purpose, policy identity/version,
catalog version, query digest, requested origin/classification subsets, result limit,
and short validity window. Requested access must be a subset of the exact subject
permission. A request cannot extend policy through its filters.

## Envelope validation and deterministic selection

Every catalog envelope is revalidated at construction and on every retrieval. Exact
assessment, origin-specific provenance, content digest, recomputed instruction metadata,
classification, UTF-8 bound, and current lifetime remain mandatory. One invalid,
cross-assessment, expired, or tampered envelope denies the whole retrieval rather than
being silently skipped. Duplicate envelope identity or provenance makes the catalog
ambiguous and denies.

Selection is an exact origin/classification filter followed by deterministic ordering
over origin, classification, provenance reference, and envelope identity. The subject
and contract result limits are then applied. There is no relevance scoring, query
interpretation, semantic search, embedding, or content inspection. The query digest is
provenance metadata only in this slice.

## Replay, privacy, and prompt injection

Request identities are consumed atomically in process. Exact replay and conflicting
identity reuse deny, including concurrent duplicate delivery. Catalog and request state
are not durable; restart recovery and idempotent distributed delivery remain deferred.

Only the envelope-safe classifications `public`, `internal`, `confidential`, and
`restricted_redacted` are representable. `secret` and `restricted_raw_evidence` cannot
appear in policy, request, envelope, or result contracts. This metadata-only slice does
not resolve, inspect, log, or return content or secrets.

Instruction-like annotations pass through as inert metadata. Adversarial envelope text
cannot alter the policy, subject, purpose, filters, ordering, limits, authority, or
execution state, and the text itself is omitted from results. Detection is not an
authorization control.

## Compatibility, migration, rollback, and residual risk

The three contracts are additive v1 schemas with no earlier producers or consumers.
Required-field or semantic changes require a new major version. No database migration
or durable state is introduced. Rollback removes the schemas, component, tests, and
documentation without data conversion or authority recovery.

Synthetic tests cover policy immutability, deterministic bounded selection, metadata-
only output, exact subject/purpose ACLs, privilege expansion, malformed and forbidden
classification, policy/catalog/time fencing, cross-assessment and tampered envelopes,
expiry, duplicate identity/provenance, replay, conflicting reuse, concurrency, and
inert prompt-injection metadata.

Durable authenticated policy activation, indexing, acquisition, ACL persistence,
idempotent recovery, audit, deletion/retention integration, content retrieval, query
matching, embeddings, context construction, provider routing, and agents remain
deferred. The broader retrieval action therefore remains open.
