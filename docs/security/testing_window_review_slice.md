# Phase 1 testing-window review

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

Supervised Intake now requires an explicit weekday set, start and end time, and IANA
timezone before constructing a manifest. An optional blackout interval requires both
timezone-aware endpoints and a bounded reason. Reviewed values map to structured
`allowed_testing_windows` and `blackout_periods` entries in manifest v2.

## Safety and compatibility

Unknown weekdays or timezones, malformed or non-increasing windows, and partial or
non-increasing blackout intervals deny draft construction. The manifest contract no
longer accepts arbitrary objects for these fields, and the policy boundary independently
checks timezone identity and ordering. Existing manifests that omit the optional fields
remain valid.

This slice creates no scheduler, clock-trust claim, request, grant, network effect, or
execution authority. Runtime window enforcement and account-reference review remain
separate gates. Rollback affects draft construction only and does not alter persisted
source, manifest, policy, or execution history.
