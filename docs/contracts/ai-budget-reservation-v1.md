# AI budget reservation v1

## Outcome and boundary

The request and reservation contracts provide a non-executing, deterministic budget
ledger for one validated `AIProviderConfiguration v1` and its exact trusted registry
revision. The ledger atomically reserves input tokens, output tokens, request count,
integer micro-USD cost, and runtime seconds. It never contacts a provider, resolves a
secret, accepts model content, or grants execution authority.

Every request carries an idempotency key, the expected ledger version, exact
configuration and registry provenance, a short validity window, and
`execution_enabled: false`. Successful receipts are immutable snapshots with a
monotonic ledger version and canonical request fingerprint.

## Default deny and lifecycle

Schema validation precedes semantic accounting. Missing, malformed, empty, stale,
overlong, authority-mismatched, version-stale, conflicting-replay, invalid-transition,
expired, tampered, or cumulative over-budget input denies with a stable
`AI_BUDGET_*` code. An exact idempotent replay returns its existing receipt without
charging twice. Lock-protected compare-and-reserve semantics prevent concurrent
oversubscription.

Reservations may be committed once or released once. Commit retains accounted usage;
release returns the reservation to the available ceiling. Expired reservations cannot
commit. Recovery validates every receipt, rejects duplicate or oversubscribed state,
preserves committed usage, and deterministically releases expired reservations before
accepting new work. Recovery does not restore provider or network authority.

## Compatibility, migration, privacy, secrets, and rollback

Both schemas are additive v1 contracts with no earlier producer. No database migration
is introduced: the ledger is deliberately in-memory until a durable orchestration
store is designed. Required-field or semantic changes require a new major version.
Rollback removes the schemas, ledger, tests, and documentation; no persisted data or
authority needs conversion.

The ledger processes counts and opaque provider/configuration identifiers only. It
does not accept prompts, evidence, assessment data, secret values, or secret-reference
descriptors, and it does not resolve the configuration's opaque secret reference.

## Verification and residual risk

Synthetic tests cover exact ceilings, malformed and empty requests, stale and
overlong windows, authority and version fencing, exact and conflicting replay,
concurrent reservations, state transitions, expiry, release, tampered and ambiguous
recovery, and cumulative oversubscription. JSON contract validation, full Python tests,
Ruff, and mypy are required.

Durable storage, crash-atomic database transactions, audit linkage, per-assessment and
per-task aggregation, provider-reported usage reconciliation, cancellation integration,
pricing/version provenance, runtime deadline enforcement, and provider execution remain
deferred. This slice therefore does not complete the broader Phase 2 budget item.
