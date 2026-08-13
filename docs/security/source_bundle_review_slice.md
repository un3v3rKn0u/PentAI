# Phase 1 supervised source-bundle review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The Intake workspace can assemble more than one exact immutable source into a manifest
draft. Every selected source identifier and digest is revalidated against the current
program history, ordered using the documented contract → program staff → program page →
platform rule → internal note precedence, and retained in the manifest source list and
every top-level field-provenance link.

Sources sharing a reference but carrying different hashes are treated as conflicting
immutable versions. The operator must record a bounded restrictive-review note before a
draft can be produced. The draft retains both versions, adds a normalization warning and
an unresolved question, and keeps approval pending. The UI does not infer which statement
is permitted and does not remove the core's completeness, contradiction, or activation
checks.

## Safety and failure states

Empty, duplicated, missing, malformed, or ambiguous selections deny locally before they
can alter the draft. Conflict notes are required only for detected version conflicts and
are limited to 500 characters. Changing the reviewed bundle clears validated manifest,
policy, and semantic-diff state before rebuilding a draft.

This slice adds no source mutation, extraction, network access, approval, policy
activation, grant, or execution capability. The authenticated core remains authoritative
for provenance integrity and manifest validation.

## Compatibility and rollback

The existing manifest v2 contract already permits multiple sources, multiple provenance
links, normalization warnings, and unresolved questions. No schema or migration changes
are needed. Rolling back the UI leaves all immutable source and manifest history intact.
