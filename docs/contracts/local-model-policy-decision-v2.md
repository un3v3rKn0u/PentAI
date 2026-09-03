# Local-model PolicyDecision v2

## Scope

PolicyDecision v2 records deterministic policy evaluation for one already-persisted
ActionIntent v2 whose capability is exactly `ai.local.generate`. Trusted core accepts
only the intent identifier, then derives the complete intent, assessment, plan, task,
Policy IR v2, Manifest v3, capability-manifest, provider-configuration, active-registry,
and policy-epoch lineage from durable storage.

The only outcomes are `allow`, `deny`, and `approval_required`, derived from the one
compiled capability rule. A decision is fixed to `authority: none`,
`grant_enabled: false`, and `execution_enabled: false`. Even `allow` is policy metadata,
not an ActionGrant and not permission to load a model or start a process.

## Default deny and replay

Evaluation revalidates the exact current active signed Policy IR v2, latest valid
Manifest v3, active assessment and safety state, running validation task and exact
revisions, immutable local-model manifest, fixed `llama.cpp` and Qwen configuration,
active registry lineage, limits, classifications, and all covering expiry bounds in one
serialized transaction. Missing, malformed, mixed-version, substituted, stale,
expired, revoked, cancelled, superseded, or ambiguous state denies before persistence.

The decision identifier is deterministic for the intent and policy hash. One immutable
row may exist per intent. Replay returns the exact stored document only after all
current bindings are revalidated; changed or competing state cannot create a second
decision. Startup recovery has no evaluation producer and cannot invent or resume one.

## Compatibility and rollback

PolicyDecision v1, ActionIntent v1, ActionGrant v1, and HTTP authorization are
unchanged. PolicyDecision v2 uses a separate table and has no grant consumer. Migration
0096 is additive. Application rollback disables new v2 evaluation while retaining the
immutable history; automatic conversion or deletion is unsupported.

## Deferred work

Local-model approval consumption, ActionGrant v2, artifact and binary verification,
adapter supervision, prompt handling, execution, receipts, metering, accounting,
worker/runtime fencing, and recovery demonstrations remain separately reviewed work.
