# Phase 1 structured technique review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The supervised Intake normalization checkpoint now reviews allowed and denied capability
lists, explicit GET/HEAD/OPTIONS method authority, and one optional conditional capability
with an approval type and bounded conditions. The reviewed values map directly to the
existing manifest v2 technique fields.

The authenticated core remains authoritative for supported-capability validation,
contradiction detection, policy compilation, approval evaluation, and activation.

## Safety and failure states

At least one directly allowed capability and one HTTP method are required. Malformed
capability names, overlapping allow/deny/conditional classification, incomplete
conditional approval data, and a directly allowed built-in HTTP capability without its
required method deny draft construction. A conditional capability does not become a
direct allow and retains its approval requirement.

This slice adds no technique execution, network access, approval issuance, grant, or
policy activation behavior.

## Compatibility and rollback

Manifest v2 already defines allowed, denied, and conditional capabilities and allowed
HTTP methods, so no schema or migration change is required. Existing builder callers
without structured technique review retain the previous allow-only GET representation.
Rolling back the UI does not alter persisted source, manifest, or policy history.
