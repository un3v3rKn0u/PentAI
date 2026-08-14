# Phase 1 durable fixture cleanup recovery

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

Gateway supervisor recovery now uses the durable execution-claim ledger as its cleanup
queue. Before runtime sentinel recovery or containment re-attestation, it enumerates every
claim still in `claimed` state and derives the exact fixture container name.

Each name is queried through a bounded, exact-name OCI filter. Present containers are
force-removed and queried again; already-absent containers are idempotent success. Runtime
errors, unexpected names, removal failure, or a container that remains visible pause global
safety and prevent supervisor readiness.

## Safety and compatibility

Recovery uses the configured trusted OCI executable and the existing bounded command
executor. It does not delete or mutate immutable claim history; the authorization startup
transaction remains responsible for abandoning claims and cancelling committed starts.
Running cleanup first preserves the identity needed to remove crash leftovers.

This remains limited to the owned TEST-NET fixture. Future general transports require a
durable effect identity and equivalent reconcile-before-ready behavior.
