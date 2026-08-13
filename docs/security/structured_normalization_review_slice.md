# Phase 1 structured normalization review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

Source import and source-bundle selection no longer silently create a draft from fixed
scope and limit defaults. The Intake workspace requires an explicit human review of the
exact domain, allowed and denied paths, allowed ports, capabilities, request rate,
total-request ceiling, response ceiling, and a bounded transcription rationale.

The UI performs narrow syntactic checks, normalizes the reviewed domain and comma-separated
values, and copies the result into a provenance-linked pending manifest draft. The
authenticated core remains authoritative for canonicalization, contradictions,
completeness, policy compilation, and activation.

## Safety and failure states

Blank or malformed domains, non-absolute paths, invalid ports, malformed or absent
capabilities, non-positive rates and ceilings, and missing or oversized rationale deny
draft construction. Wildcard syntax is not inferred by this domain-only slice. Importing
a new source clears the previous normalization review and leaves the draft empty until
the operator reviews the source bundle again.

Every constructed draft records the human normalization rationale as a warning, retains
pending approval, and preserves all reviewed source digests in field provenance. This
slice adds no extraction, policy authority, grant, network, or execution capability.

## Compatibility and rollback

Manifest v2 already supports the reviewed fields and normalization warnings, so no schema
or migration changes are required. Existing persisted manifests remain readable. Rolling
back this UI slice does not mutate source, manifest, or policy history.
