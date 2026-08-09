# Gateway Runtime Lifecycle

## Outcome

PentAI can durably launch and monitor a non-target-facing gateway sentinel under a
verified rootless OCI runtime. The sentinel is attached only to the exact managed
internal network, performs no DNS or HTTP work, and keeps `execution_enabled: false`.

Each runtime is bound to one prepared gateway session, one short-lived containment
attestation, one runtime instance, one managed network, and one SHA-256 image identity.
Podman runtime identity uses its machine ID when exposed and otherwise its validated
host name; the selected value is re-observed on every containment measurement.
The database records `launching` before the external effect, records the container ID
before verification, and retains immutable terminal history. Launching, running, and
terminal transitions are appended transactionally to the existing hash-chained audit
ledger with the runtime as the subject.

## Enforcement and recovery

The fixed launch drops every capability, enables no-new-privileges, uses a read-only
root, a non-root image user, private default PID/IPC namespaces, no host mounts or
runtime socket, and fixed CPU, memory, and PID limits. Post-launch and watchdog checks
re-inspect ownership labels, container identity, running state, network, user,
privileges, namespaces, mounts, and limits, and refresh the full containment attestation.

Any missing, stale, changed, malformed, or unverifiable observation terminates the
container and invokes the durable assessment safety transition. Termination failure is
recorded as `failed`, still pauses/revokes authority, and remains eligible for startup
recovery retry. Startup recovery terminates every launching, running, or failed-owned
container and is idempotent after success.

## Compatibility and rollback

Migration `0011` and GatewayRuntimeInstance v1 are additive. Existing prepared sessions
do not acquire runtimes automatically. Rolling back the coordinator cannot delete or
reactivate runtime history; startup recovery must first terminate any recorded live or
failed instance. This slice does not change GatewaySession v1.

## Deferred authority

This is a sentinel lifecycle, not an HTTP gateway. It has no outbound route, controlled
DNS transport, listening socket, request execution, redirect handling, response body,
or worker attachment. The watchdog entry point must be wired into application startup
with an approved runtime configuration before continuous production monitoring can be
claimed. Rootless live sentinel launch and termination remain hosted-verification work.
