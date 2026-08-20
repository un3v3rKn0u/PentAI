# AI secret reference v1

## Outcome and trust boundary

`ai-secret-reference-v1.schema.json` describes only opaque metadata for a future
provider credential. It binds one provider-scoped reference to one exact remote
provider configuration, provider identity, fixed authentication purpose, lifecycle
state, and validity window. `resolution_enabled` is fixed to `false`.

Validation composes the current trusted provider registry and provider configuration
checks before accepting the descriptor. It performs no keychain or credential-store
access, secret resolution, persistence, provider request, model load, evidence access,
logging, agent action, approval, grant, or network operation.

## Default-deny behavior

Missing, malformed, unknown, or extra fields deny. Raw-secret-shaped properties cannot
be represented. The opaque reference URI must embed the same exact provider identity
as the descriptor and configuration. A descriptor is also bound to the exact
configuration UUID, preventing reuse with another configuration.

Future-dated, expired, reversed, or longer-than-30-day reference windows deny. The
reference must exist no later than configuration creation and remain current for the
entire configuration lifetime. Revoked references deny. Local runtimes cannot accept a
provider secret descriptor. Attempted resolution enablement fails schema validation.

Stable `AI_SECRET_*` codes distinguish malformed, clock, binding, stale, lifetime,
revocation, and unsupported-runtime failures. Invalid underlying provider configuration
or registry authority continues to deny through its existing stable code rather than
being reinterpreted as secret authority.

## Privacy and secrets

The contract contains identifiers and lifecycle metadata only. It has no field for a
credential, token, private key, secret bytes, locator details for an OS store, or model
context content. Validation never returns secret material. Synthetic tests add unknown
raw-secret-shaped properties only to prove schema rejection and use random UUID text,
not a credential fixture.

## Compatibility, migration, and rollback

This additive v1 contract composes with `AIProviderConfiguration v1` and
`AIProviderRegistry v1` without changing either JSON schema. No database migration is
required because no descriptor is persisted. Rollback removes the schema, validator,
tests, and documentation; the provider configuration continues to carry its opaque
reference string under the prior boundary.

Required fields, changed binding/lifecycle semantics, or new resolution behavior
require a new major contract. Resolution must not be added as an optional v1 field or
enabled through a compatible minor change.

## Verification and deferred work

Synthetic tests cover valid non-resolution, missing/malformed/raw-secret-shaped input,
configuration replay, provider/reference mismatch, cross-provider ambiguity, future,
expiry, reversed/overlong windows, incomplete lifetime coverage, revocation, local
runtime rejection, and attempted resolution enablement.

OS credential-store integration, authenticated broker resolution, just-in-time access,
single-use leases, rotation, durable state, revocation propagation, audit events,
redaction scans, crash recovery, and UI remain deferred. Provider execution stays
disabled, and this slice does not complete the broader Phase 2 secret/budget item.
