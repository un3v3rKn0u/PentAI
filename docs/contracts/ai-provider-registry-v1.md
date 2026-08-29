# AI provider registry v1

## Outcome and trust boundary

`ai-provider-registry-v1.schema.json` is the trusted, non-executing source for exact
provider/model allowlists. A pure compiler accepts a contract-valid current registry
and creates an immutable `ProviderPolicy` carrying the registry identity, revision,
and expiry. Provider configuration cannot create its own allowlist authority.

Registry compilation performs no persistence, network request, model load, secret
resolution, evidence access, agent action, approval, grant, or provider execution.
`execution_enabled` must be exactly `false`.

The additive normalization helper validates through this same compiler, deep-copies the
document, sorts providers by ASCII `provider_id`, and sorts each provider's ASCII model
identifiers and input classifications lexically. The complete normalized registry and
its normalized provider array are hashed separately with the repository canonical JSON
and SHA-256 primitives. Array ordering cannot fork provenance, while ceilings, validity,
remote-provider policy, provider/model metadata, or any other semantic change alters the
applicable digest.

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

This is an additive v1 validation contract. `AIProviderConfiguration v1` remains
compatible; its trusted policy carries registry provenance and expiry. The separate
registry-snapshot v1 contracts and migration 0081 reserve an inert durable normalized
copy without changing this compiler or activating a registry. Their producer remains
storage-denied, so no runtime registry state exists yet.

Required fields, changed identity/routing semantics, or removed values require a new
major version. Optional additive metadata may use a compatible minor version only when
older consumers remain safely default-denying.

## Verification and deferred work

Synthetic tests cover valid remote/local compilation and configuration composition,
immutable snapshot behavior, malformed and missing data, time boundaries, duplicate
providers and models, all-disabled state, forbidden classifications, disabled provider,
unlisted model, budget schema boundaries, configuration overrun, expired-policy reuse,
order-independent normalization, semantic digest substitution, and caller mutation
isolation.

Authenticated registry-snapshot production, monotonic revision and rollback protection,
human activation and revocation, signature/source governance, audit events, provider
adapters, secret brokerage, runtime budget accounting, model contexts, and UI remain
deferred. This slice does not complete the Phase 2 allowlist/budget action-plan item or
enable provider execution.
