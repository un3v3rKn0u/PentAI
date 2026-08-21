# Untrusted content envelope v1

## Outcome and boundary

`UntrustedContentEnvelope v1` is an assessment-scoped, non-executing container for
bounded text from program pages, retrieved documents, target content, tool output,
evidence derivatives, plugin messages, and model output. It structurally labels the
content as data with `authority: none` and `execution_enabled: false`; it cannot carry
trusted instructions, policy, approval, capabilities, tool arguments, secret handles,
network authority, or executable operations.

The deterministic core builds and validates envelopes without contacting a source,
provider, plugin, model, tool, evidence store, target, or network. It does not construct
a prompt or model context. Any future requested effect must still become an
`ActionIntent` and traverse the Phase 1 `PolicyDecision → ActionGrant → supervised
execution` chain.

`PromptInjectionCorpus v1` separately constrains the synthetic regression fixture to
bounded identifiers, categories, and text. It contains no live source or target data.

## Scope, provenance, integrity, and lifetime

Every envelope binds one UUID assessment, an explicit origin, a permitted privacy
classification, an origin-specific opaque provenance reference, the exact UTF-8 content
digest, acquisition time, and expiry. The validator requires the caller's expected
assessment, maps each origin to its exact provenance namespace, recomputes the digest,
and permits at most 16,384 UTF-8 bytes and a 24-hour lifetime. Future, expired,
reversed, or overlong validity denies.

The process-local registry atomically rejects exact replay, conflicting envelope
identity, reused provenance, and concurrent duplicate registration. Stored and returned
documents are deep copies. Replay fencing is not durable and grants no authority.

## Prompt-injection metadata

A deterministic indicator pass annotates instruction-like text across direct,
indirect, encoded, obfuscated, delimiter-breaking, role-confusion, authority-claim,
secret-exfiltration, tool-call, policy-mutation, and data-poisoning categories. Metadata
is recomputed during validation so callers cannot clear or alter it.

Detection never changes authority, classification, execution state, policy, or parsing.
Undetected content is equally untrusted. The indicators are regression metadata, not a
security decision or a claim of comprehensive prompt-injection detection.

## Privacy and secret consequences

Only `public`, `internal`, `confidential`, and `restricted_redacted` are representable.
`secret` and `restricted_raw_evidence` classifications fail schema validation. The
envelope has no secret-reference or credential fields, performs no resolution, and
does not log or route content.

Content remains arbitrary untrusted text and could be misclassified or contain
sensitive material. This slice does not inspect secrets or prove classification. A
future context builder and provider adapter must authenticate classification and apply
data-routing policy before any model receives content.

## Default deny, compatibility, and rollback

Malformed, missing, unknown, unsupported, oversized, cross-assessment, origin/provenance
mismatched, digest-tampered, metadata-tampered, future, stale, expired, replayed,
identity-conflicting, or provenance-reused input denies with stable
`UNTRUSTED_CONTENT_*` codes. Unknown nested authority or instruction structures fail
the closed schema.

This additive v1 contract has no previous producer or consumer and requires no database
migration. Required-field or semantic changes require a new major contract. Rollback
removes the schema, core component, synthetic corpus, tests, and documentation without
data conversion or authority recovery.

## Verification and residual risk

Synthetic tests cover every supported origin and classification, exact UTF-8 byte and
time boundaries, forbidden privacy classes, unknown authority-bearing fields,
cross-assessment substitution, provenance mismatch/reuse, digest and metadata tampering,
replay, identity conflict, concurrency, and all eleven injection categories.

Durable provenance and replay state, live acquisition, retrieval ACLs, source
authentication, classification assurance, secret scanning, active-content stripping,
context construction, provider routing, canary traces, model evaluation, and agent
integration remain deferred. The broader action-plan item therefore remains open.
