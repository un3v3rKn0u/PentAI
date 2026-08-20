# AI provider configuration v1

## Outcome and boundary

`ai-provider-configuration-v1.schema.json` is the first Phase 2 provider-neutral
contract. It identifies one exact approved remote provider or local runtime and one
exact model, while keeping provider execution unconditionally disabled. Validation is
pure and performs no provider request, local-model load, secret resolution, evidence
read, persistence, agent loop, network action, approval, or authorization operation.

The deterministic core compiles `ProviderPolicy` from a contract-valid
`AIProviderRegistry v1`; configuration data cannot add providers, models, data classes,
or budget authority. Provider and model identifiers are exact and case-sensitive.
Remote use requires both configuration opt-in and trusted policy enablement. Local
runtimes must not carry a secret reference. Configuration expiry cannot exceed the
registry expiry, and an expired registry policy denies reuse.

## Privacy and secret handling

The provider trust zone is classified as `remote_third_party` or `local_device`.
Allowed input classes are explicit. `secret` and `restricted_raw_evidence` are never
routable in v1, even to a local runtime. A remote provider may receive only the subset
permitted for its exact trusted provider identity. This is configuration validation,
not a future context-builder guarantee; no content is accepted by this API.

Remote credentials are represented only by a provider-bound opaque reference of the
form `secretref://provider/<provider-id>/<uuid>`. Unknown properties, including common
raw-credential fields, fail schema validation. The validator never resolves or logs a
referenced value.

## Default-deny and abuse cases

Missing, malformed, future-dated, expired, overlong-lived, ambiguous, unsupported, or
unknown configuration denies. Provider-type mismatch, unknown model, cross-provider
secret reference, absent remote opt-in, disallowed privacy class, and any ceiling
exceedance deny with stable `AI_*` codes. Budget ceilings cover input tokens, output
tokens, requests, integer micro-USD cost, and runtime seconds. Exact ceilings pass;
one unit above denies.

The contract rejects `execution_enabled: true`. AI output remains untrusted candidate
data and cannot approve actions, activate policy, mint grants, contact targets, or
alter the Phase 1 `ActionIntent → PolicyDecision → ActionGrant → supervised execution`
chain.

## Compatibility, migration, and rollback

This additive v1 contract has no earlier producer or consumer. No database migration
is required because the slice persists no provider configuration. Removing the schema,
validator, tests, and this document fully rolls back the slice; no durable state or
authority requires conversion. Future compatible additions must remain optional and
default-denying. Required-field or semantic changes require a new major contract.

## Verification and residual risk

Synthetic tests cover valid remote/local configurations and malformed, missing,
future, stale, ambiguous, unknown-provider, unknown-model, raw-secret-property,
cross-provider-reference, privacy, opt-in, execution-enable, registry expiry, and every
budget-boundary case. Contract validation, Python tests, Ruff, and mypy are required.

Deferred risks include actual secret brokerage, provider adapters, context construction,
content classification, prompt-injection defenses, structured-output parsing, budget
reservation/accounting, persistence, audit events, UI configuration, and model/provider
availability. No claim is made that this slice completes the Phase 2 AI-foundation
checkboxes.
