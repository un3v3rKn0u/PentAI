# Gateway Runtime Supervisor

## Outcome

The local core owns the lifetime of an injected gateway runtime lifecycle. Before the
application reports readiness, the supervisor terminates every durable launching,
running, or cleanup-retryable sentinel. It then runs bounded repeat checks until
shutdown. Neither recovery nor monitoring enables execution or resumes an assessment.

When no OCI supervisor is configured, startup queries the durable runtime ledger. An
empty ledger is reported as `disabled`; any record that may still own a container is
reported as `degraded`, global safety remains paused, readiness returns HTTP 503, and
`execution_enabled` remains false.

## Failure and shutdown behavior

Recovery failure, an unexpected watchdog failure, a watchdog join timeout, or shutdown
cleanup failure moves supervision to a stable degraded state and invokes the global
safety pause directly. Diagnostics expose only a fixed reason code, counts, watchdog
state, and the constant non-executing flag. They do not expose runtime output,
container identities, network identities, or local paths.

The authenticated shutdown path stops the watchdog, waits for a bounded interval, and
re-runs durable termination recovery. Framework shutdown invokes the same idempotent
operation. Startup and shutdown cleanup are safe to repeat after success.

## Compatibility and rollback

This slice adds no schema, migration, or target-facing API. Existing application
callers remain compatible. A custom supervisor is injected at composition time; the
default core remains ready only when the durable runtime ledger has no possibly live
container. Before rolling back, operators must terminate all recorded sentinels because
the older core cannot continuously supervise them.

## Deferred authority

Production OCI configuration and construction, route/source-IP attestation, controlled
DNS, outbound gateway networking, HTTP requests, redirects, response handling, worker
attachment, and automatic assessment resumption remain absent.
