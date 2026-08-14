# Phase 1 gateway cleanup safety latch

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

The fixture transport now requires a safety-pause dependency at construction. If bounded
timeout cleanup raises, times out, or returns failure, the adapter pauses global safety
with the fixed `GATEWAY_FIXTURE_CLEANUP_FAILED` reason before surfacing the transport error.

If the safety operation itself fails, the adapter returns the distinct fixed
`HTTP_FIXTURE_SAFETY_PAUSE_FAILED` code without exposing exception details. No further
fixture execution can rely on cleanup having succeeded silently.

## Composition and compatibility

The hosted containment proof connects this dependency to the authenticated core's global
safety control with the fixed `gateway-http-fixture` actor. Tests must provide an explicit
fixture callback, preventing new compositions from accidentally omitting the latch.

This remains limited to the owned TEST-NET proof path. Any future general transport must
use a durable safety latch and recovery workflow rather than an optional callback.
