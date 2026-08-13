# Phase 1 structured scope-boundary review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The supervised Intake normalization checkpoint now requires explicit third-party-service
and shared-hosting/CDN decisions alongside a bounded scope-expansion process. Both
external-infrastructure decisions default to `deny`; the only alternative is the
manifest contract's `allow_if_explicit`, which does not add an asset by itself.

The reviewed values map directly to existing manifest v2 scope fields. The authenticated
core remains authoritative for schema and semantic validation, policy compilation,
approval, and activation.

## Safety and failure states

Unknown boundary values, a missing or whitespace-only expansion process, and processes
longer than 500 characters deny draft construction. Discovered assets still default to
deny and redirects outside scope still stop. Choosing `allow_if_explicit` cannot infer
authority for third-party or shared infrastructure; a separately reviewed exact allow
asset remains required.

This slice adds no source interpretation, discovery, DNS, network access, policy
authority, grant, or execution behavior.

## Compatibility and rollback

Manifest v2 already defines `third_party_services`, `shared_hosting_and_cdn`, and
`scope_expansion_process`, so no schema or migration change is required. Existing builder
callers without a boundary review continue to emit conservative deny defaults. Rolling
back the UI does not alter persisted source, manifest, or policy history.
