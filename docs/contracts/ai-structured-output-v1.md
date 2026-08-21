# AI structured output v1

## Outcome and trust boundary

The candidate-observation, repair-request, and parse-result v1 contracts establish a
strict non-executing boundary for model-produced bytes. The only supported response
type is `candidate_observation`; it contains bounded descriptive candidate data and
cannot represent an operation, approval, policy, capability, tool call, `ActionIntent`,
or `ActionGrant`. Accepted output remains untrusted candidate data.

The parser performs no provider call, prompt construction, secret resolution, evidence
read, persistence, agent loop, network action, approval, or authorization operation.
Every result fixes `execution_enabled` to `false` and records direct acceptance,
acceptance after one repair, or denial.

## Strict parsing and default deny

The parser accepts exact `bytes`, enforces a 32,768-byte ceiling before decoding, and
uses strict UTF-8 and JSON decoding. Duplicate keys, trailing content, non-finite
numbers, non-object roots, unsupported versions or response types, operation fields,
unknown fields, missing fields, type coercion, more than 32 observations, strings over
their bounds, and nesting deeper than six levels deny with stable `AI_OUTPUT_*` codes.
SHA-256 digests identify the exact bytes without logging their contents.

Malformed JSON and schema-invalid candidate data may receive one repair pass. The
repair request is bound to the initial byte digest and failure code, fixes every
parser limit, expires within one minute, and is consumed atomically once. Modified,
mismatched, future, stale, replayed, unexpected, terminal-failure, or second repair
attempts deny. A failed repaired output produces `AI_OUTPUT_REPAIR_EXHAUSTED`; there is
no alternate-model or unbounded retry path in this slice.

## Security, privacy, and authorization consequences

This boundary supports `INV-AUTH-003`, `INV-AGENT-001` through `INV-AGENT-004`, and
`INV-DATA-001`. Neither an accepted payload nor a repair request conveys authority.
Future consumers must still convert any requested effect into a versioned
`ActionIntent` and pass the Phase 1 `PolicyDecision → ActionGrant → supervised
execution` chain.

The contracts have no dedicated prompt, evidence, assessment-content, credential,
secret-value, or secret-reference fields. Descriptive strings remain arbitrary untrusted
text and could contain sensitive or instruction-like material; the parser neither logs
nor classifies them. Future context, storage, logging, and display consumers must apply
the applicable data-routing and untrusted-content boundaries. This is not a context-
builder or provider-routing implementation and makes no claim about content sent to a
model.

## Compatibility, migration, rollback, and recovery

These additive v1 contracts have no prior producers or consumers. Required-field,
semantic, or limit changes require a new major contract version. No database migration
or durable state is introduced. Rollback removes the schemas, parser, tests, and this
documentation without data conversion or authority recovery.

Repair replay fencing is process-local. A restart forgets consumed repair identifiers,
but replay still cannot create an external effect because parsing is non-executing.
Durable orchestration must persist repair lifecycle before provider-mediated repair is
enabled.

## Verification and residual risk

Synthetic tests cover direct and repaired acceptance; exact byte ceilings; encoding,
empty, duplicate, trailing, malformed, non-finite, version, type, operation, unknown,
missing, coercion, collection, and depth denials; tampered binding and limits; stale
repair; exhaustion; exact replay; and concurrent one-use consumption.

An additive `UntrustedContentEnvelope v1` boundary now provides inert assessment scope,
provenance, classification, digest, lifetime, and prompt-injection metadata for bounded
text. Provider adapters, actual repair prompting, durable repair state and audit,
arbitrary response-type registration, context construction, live prompt-injection
evaluation, context privacy enforcement, and agent integration remain deferred. The
Phase 2 structured-output action remains open until those applicable integrations and
evidence exist.
