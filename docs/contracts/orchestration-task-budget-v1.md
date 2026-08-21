# Orchestration task budget v1

## Boundary

This additive boundary persists a trusted assessment-level budget account derived from
one validated `AIProviderConfiguration v1` and exact provider-registry revision, then
atomically reserves bounded capacity for one current Validation Agent task. It is a
coordination ceiling only: `authority` is `none`, `execution_enabled` is false, and no
provider usage, ActionIntent evaluation, approval, grant, dispatch, or external effect
occurs.

The request binds the exact account version, assessment, active signed policy, plan and
task revisions, agent identity, immutable task-capability manifest, purpose, integer
amounts, and validity window. Supported units are input/output tokens, requests,
micro-USD cost, runtime seconds, and retries. Floating-point, unit-free, wildcard,
delegated, secret-bearing, or authority-shaped input is unrepresentable.

## Accounting, cancellation, and recovery

Migration 0038 stores immutable account identity/ceilings and reservation identity,
with a monotonic account version. An immediate SQLite transaction revalidates safety,
policy, plan/task state, manifest digest and scope, account expiry/version, current
reserved totals, and every ceiling before compare-and-reserve. Exact replay returns
the same receipt only while all security bindings remain current; changed reuse denies.
Concurrent contenders cannot oversubscribe or both consume one version.

Cancellation and terminal/recovered task state deny new reservations immediately.
Recovery validates every stored receipt and releases only expired or no-longer-current
reservations, increments the account version, and emits metadata-only hash-chained
audit/outbox events. Recovery never resumes work or converts released capacity into
authority. Reusing capacity requires a new fully validated reservation transaction.

## Compatibility, privacy, rollback, and residual risk

The schemas, service, and migration are additive. The existing in-memory AI budget
ledger, Phase 1 gateway budgets, ActionIntent contracts, and historical data remain
unchanged. Application rollback disables new account activation/reservation/recovery
while retaining immutable history; migration 0038 is not reversed.

Only identifiers, hashes, integer ceilings/amounts, timestamps, and states are stored.
Prompts, model content, evidence, target data, credentials, secret references, and
provider payloads are absent. Account activation is a trusted-core method but Master
Orchestrator transport authentication is deferred. Provider usage reconciliation,
committed usage/debit, per-action budget composition, human approval, leases,
checkpoints, dispatch, and execution remain required before the broader budget and
orchestration requirements can complete.
