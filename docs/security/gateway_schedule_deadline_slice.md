# Phase 1 gateway schedule deadline

**Status:** Implemented; sole-maintainer security review recorded

## Outcome

The gateway's atomic request-start transaction now derives a single schedule deadline
from the immutable signed Policy IR and persists the earliest of that boundary, the grant
timeout, grant expiry, engagement expiry, and network-attestation expiry. A request that
starts during reviewed time cannot be finalized after its active testing-window union
ends or the next blackout begins.

## Safety and compatibility

Overlapping allowed windows form a union, so the latest matching window end applies.
The earliest upcoming blackout always takes precedence. Active blackouts, closed windows,
unknown timezones, malformed schedules, and invalid local-time boundaries fail closed.
Policies without schedules retain their existing deadline behavior.

The policy package owns schedule matching and boundary calculation, preventing decision
and gateway paths from drifting apart. The follow-on clock-health slice now continuously
compares wall and monotonic progress and pauses global safety on uncertainty. This slice
adds no socket, worker, destination, or external effect. Active interruption when a
committed deadline arrives remains a separate Phase 1 exit-gate control.
