# Attempt-three provider usage v1 prerequisite

## Boundary

This additive prerequisite defines closed provider-usage measurement and receipt shapes
for the exact successful attempt-three completion lineage. Migration 0079 reserves an
immutable ledger for one completion, reservation, account version, worker, checkpoint,
fence, and recovery generation. Its producer is deliberately storage-denied.

No trusted runtime meter or provider adapter exists yet. Consequently no measurement
or receipt can be produced, and successful coordination must not be interpreted as
evidence of requests, tokens, runtime, or cost. A later separately reviewed producer
must derive every binding and integer amount from trusted runtime state; caller-supplied
usage is never acceptable.

## Units and lineage

The closed amount set is input tokens, output tokens, request count, integer micro-USD,
and runtime seconds. Values are bounded non-negative integers and at least one dimension
must be positive. Retry units are intentionally absent: both retry units permitted by
retry policy v2 remain permanently consumed and cannot be measured, refunded, or
reinterpreted as provider capacity.

The measurement binds the exact completion-v3 digest, succeeded task and plan revisions,
attempt-three identity, reservation-v4 request digest, authoritative assessment budget
account and version, provider configuration hash and registry revision, worker/runtime,
lease consumption, checkpoint head or explicit absence, fencing token, and recovery
generation. The receipt keeps reconciliation and budget finalization disabled.

## Compatibility, privacy, and rollback

The schemas and table are additive. Earlier completion, reservation, accounting, and AI
budget contracts remain unchanged and cannot satisfy this boundary. The in-memory AI
budget ledger's committed state retains a full reservation and is not an actual-usage
source. Existing cancellation, expiry, and recovery release behavior remains unchanged.

Only bounded identifiers, hashes, integer quantities, revisions, closed constants, and
timestamps are representable. Provider responses, prompts, assessment content, evidence,
artifacts, findings, diagnostics, targets, credentials, tokens, commands, paths, URLs,
prices supplied by callers, and arbitrary payloads are excluded. Application rollback
leaves the empty inert table unused; destructive migration reversal is unsupported.

Provider adapters, trusted runtime metering, production, reconciliation, debit or
settlement, partial-use semantics, reservation closure/release, provider execution,
dispatch, evidence/reporting, and Phase 2 demonstrations remain deferred.
