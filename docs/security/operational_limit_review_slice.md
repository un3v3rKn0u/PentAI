# Phase 1 operational-limit review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The supervised Intake normalization checkpoint now reviews global and per-host request
rates, burst size, concurrent connections, maximum runtime, total requests, request-body
and response-size bounds, and explicit stop conditions. The values map directly to the
existing manifest v2 operational-limit fields.

The authenticated core and gateway remain authoritative for validation, reservation,
accounting, stop enforcement, policy activation, and execution.

## Safety and failure states

Every positive limit must be finite and greater than zero; integer-only ceilings must be
whole numbers. Request-body bytes may be zero but not negative. Per-host rate cannot
exceed the global rate. At least one non-empty, bounded stop condition is mandatory.
Malformed or inconsistent input denies draft construction.

This slice changes reviewed draft construction only. It adds no scheduler, request,
network, grant, enforcement, or execution behavior.

## Compatibility and rollback

Manifest v2 already defines these operational fields, so no schema or migration change
is required. Existing builder callers without a complete operational review retain the
previous conservative defaults. Rolling back the UI does not alter persisted source,
manifest, policy, reservation, or accounting history.
