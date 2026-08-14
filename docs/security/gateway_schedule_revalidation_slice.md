# Phase 1 gateway schedule revalidation

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The gateway's final request-start transaction now reloads the immutable signed Policy IR
and revalidates its testing schedule against the exact commit instant. A session prepared
during allowed time cannot consume its grant or commit request/rate capacity after the
window closes or a blackout becomes active.

## Safety and compatibility

Closed or malformed schedules deny as inactive runtime authority before any grant or
reservation mutation. The check runs in the same immediate database transaction as all
other final authority checks. Policies without schedules retain legacy compatibility.

The follow-on gateway schedule-deadline slice now caps each committed request at the
active window union's end or the next blackout boundary. Continuous clock health and
active interruption at that durable deadline remain separate Phase 1 exit-gate controls.
