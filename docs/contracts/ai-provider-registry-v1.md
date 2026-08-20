# AI provider registry v1

## Outcome and trust boundary

`ai-provider-registry-v1.schema.json` is the trusted, non-executing source for exact
provider/model allowlists. A pure compiler accepts a contract-valid current registry
and creates an immutable `ProviderPolicy` carrying the registry identity, revision,
and expiry. Provider configuration cannot create its own allowlist authority.

Registry compilation performs no persistence, network request, model load, secret
resolution, evidence access, agent action, approval, grant, or provider execution.
`execution_enabled` must be exactly `false`.

## Default-deny behavior

Missing fields, unknown fields, invalid identifiers, duplicate models, invalid budget
ceilings, and attempted execution enablement fail schema validation. Future-dated,
expired, reversed, or longer-than-30-day validity denies. Duplicate provider identities
deny even when one entry is disabled, preventing order-dependent interpretation. A
registry with no enabled provider denies instead of producing an empty or degraded
policy.

Disabled providers are excluded from the compiled maps. Exact, case-sensitive model
identifiers and explicit provider types are retained. Configuration validation rejects
a disabled/unknown provider, unlisted model, type mismatch, policy reuse after registry
expiry, or configuration that outlives the registry.

## Privacy and secrets

Every registry provider declares an explicit allowed-input classification set. `secret`
and `restricted_raw_evidence` are forbidden in all entries, including disabled entries,
so later enablement cannot expose dormant unsafe routing. The registry contains no
secret reference or secret value. Provider configuration retains the separate opaque
provider-bound reference rule.

## Compatibility, migration, and rollback

This is a new additive v1 contract. `AIProviderConfiguration v1` remains compatible;
its trusted policy now carries registry provenance and expiry. No database migration is
required because registry state is not persisted or activated in this slice. Rollback
removes the registry schema/compiler/tests and returns the configuration validator to
its previous trusted-policy injection boundary; no durable records require conversion.

Required fields, changed identity/routing semantics, or removed values require a new
major version. Optional additive metadata may use a compatible minor version only when
older consumers remain safely default-denying.

## Verification and deferred work

Synthetic tests cover valid remote/local compilation and configuration composition,
immutable snapshot behavior, malformed and missing data, time boundaries, duplicate
providers and models, all-disabled state, forbidden classifications, disabled provider,
unlisted model, budget schema boundaries, configuration overrun, and expired-policy
reuse.

Durable registry storage, human activation and revocation, rollback protection,
signature/digest verification, audit events, provider adapters, secret brokerage,
runtime budget accounting, model contexts, and UI remain deferred. This slice does not
complete the Phase 2 allowlist/budget action-plan item or enable provider execution.
