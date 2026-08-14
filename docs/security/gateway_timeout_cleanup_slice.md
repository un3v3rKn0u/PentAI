# Phase 1 gateway timeout cleanup

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

Every isolated fixture launch now has a unique OCI container name derived from its
immutable one-use execution claim. When the host-side deadline interrupts the attached
command, the adapter force-removes that exact container through a second bounded command
before returning the deadline denial.

Cleanup must complete successfully within two seconds. Executor failure, cleanup timeout,
or a nonzero runtime result becomes the fixed `HTTP_FIXTURE_CLEANUP_FAILED` error rather
than assuming that `--rm` removed the container.

## Safety and compatibility

The container identity is not caller-selected and cannot collide across execution claims.
Normal successful execution retains `--rm`; explicit removal is only the timeout recovery
path. Both launch and cleanup remain constrained by the same trusted OCI executable and
bounded-output executor.

This remains limited to the owned TEST-NET fixture. General transports remain disabled
and must define equivalent identity, interruption, cleanup, and safety-pause behavior.

The follow-on cleanup safety-latch slice now requires every transport composition to
provide a global safety callback and invokes it before returning any cleanup failure.
