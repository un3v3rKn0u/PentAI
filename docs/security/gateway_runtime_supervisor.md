# Gateway Runtime Supervisor

## Outcome

The local core owns the lifetime of a configured gateway runtime lifecycle. Before the
application reports readiness, the supervisor terminates every durable launching,
running, or cleanup-retryable sentinel and revalidates the configured rootless runtime,
managed internal network, and pinned conformance-probe image. It then runs bounded
repeat checks until shutdown. Neither recovery nor monitoring enables execution or
resumes an assessment.

Before sentinel recovery, the configured supervisor also enumerates unfinished durable
fixture claims and verifies that each claim-derived container name is absent, force-removing
an exact match when necessary. Ambiguous runtime output or failed cleanup pauses global
safety and prevents readiness.

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

Startup and every watchdog cycle also compare UTC wall-clock progress with monotonic
elapsed time before lifecycle work. Invalid observations, rollback, or drift beyond one
second degrade the supervisor and pause global safety.

The authenticated shutdown path stops the watchdog, waits for a bounded interval, and
re-runs durable termination recovery. Framework shutdown invokes the same idempotent
operation. Startup and shutdown cleanup are safe to repeat after success.

## Compatibility and rollback

This slice adds no schema, migration, or target-facing API. Existing application
callers remain compatible. Runtime composition is disabled by default. Enabling it
requires all of the following explicit settings; partial, malformed, mutable, relative,
or unverifiable configuration denies readiness:

- `PENTAI_GATEWAY_RUNTIME_ENABLED=1`
- `PENTAI_GATEWAY_RUNTIME` (`docker` or `podman`)
- `PENTAI_GATEWAY_RUNTIME_EXECUTABLE` (absolute trusted executable path)
- `PENTAI_GATEWAY_RUNTIME_INSTANCE_ID`
- `PENTAI_GATEWAY_NETWORK_ID`
- `PENTAI_GATEWAY_PROBE_IMAGE_DIGEST` (`sha256:<64 lowercase hex>`)
- `PENTAI_GATEWAY_INSTANCE_ID`
- optional `PENTAI_GATEWAY_WATCHDOG_INTERVAL_SECONDS` from 0.1 through 10

The default core remains ready only when the durable runtime ledger has no possibly live
container. Before rollback, disable new runtime composition and terminate every recorded
sentinel because an older core cannot continuously supervise it.

## Deferred authority

Network provisioning and image construction remain separate explicit operator steps.
Route/source-IP attestation, controlled DNS, outbound gateway networking, HTTP requests,
redirects, response handling, worker attachment, and automatic assessment resumption
remain absent.
