# Phase 1 testing-window enforcement

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

Policy compiler `1.2.0` preserves reviewed allowed windows and blackout periods in signed
Policy IR. The deterministic evaluator converts its current UTC instant into each
window's IANA timezone, requires an allowed weekday and half-open local interval, and
gives active blackout periods precedence.

## Safety and compatibility

Closed weekdays, times before the start or at/after the end, active blackout intervals,
and malformed schedule data deny with `TESTING_WINDOW_CLOSED`. Policy validity and intent
expiry remain independent outer bounds. Existing Policy IR without a schedule remains
readable for compatibility; every new supervised Intake manifest carries a schedule.

This slice authorizes no new capability or destination. It strengthens decision-time
authorization only. The existing short-lived grant, gateway deadline, clock rollback
checks, safety controls, and request-start revalidation remain mandatory. Continuous
wall-clock health attestation and active-session termination at a schedule boundary
remain part of the broader execution exit gate.
