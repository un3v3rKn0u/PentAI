# Isolated HTTP Fixture Transport

This slice proves a first HTTP effect only against a repository-owned synthetic
fixture. The effect runs inside the verified rootless OCI containment boundary on an
internal network with no external route. The core process never opens a target socket.

The image-digest-pinned Rust executable has two strict modes. The server binds only
inside the temporary fixture container. The client accepts exactly:

- target `192.0.2.20:8080` on the documentation-only `192.0.2.0/24` subnet;
- HTTP host `example.test`;
- path `/fixture` and method `GET`;
- a response limit from 1 byte through 1 MiB; and
- an absolute durable deadline that is still in the future and no more than five
  seconds from adapter invocation.

Every other address, host, path, method, option, duplicate, or unknown argument is
rejected before the connection. Before invoking the adapter, the core atomically claims
one committed `GatewayRequestStart`. The claim binds the exact fixture tuple, response
ceiling, absolute deadline, image digest, managed network, runtime instance, and fresh
containment attestation. Claims cannot be replayed; finalization must present the same
claim identifier and completes it in the result transaction. Startup and safety recovery
abandon unfinalized claims before cancelling their starts. The adapter also requires a
fresh complete containment attestation for the exact network. It constructs a fixed argument vector,
uses the managed internal network, a read-only root, no capabilities,
no-new-privileges, and strict CPU/memory/PID limits. It parses only an exact typed JSON
measurement and never returns or logs the response body.

The client validates the supplied wall-clock deadline once, converts it to one monotonic deadline,
and uses that deadline across connection retries, request write,
header parsing, and body reads. Headers are read with an 8 KiB ceiling. Only HTTP/1.1
200 with one valid `Content-Length` is accepted; transfer encoding, ambiguous length,
malformed headers, incomplete bodies, and transport failures deny. Body reads stop at
the authorized limit plus one proof byte.

The host adapter independently derives its OCI command timeout from the same absolute
deadline (still capped at five seconds). The bounded executor kills a command that remains
active at that boundary, timeout is reported as a fixed fixture-deadline denial, and a
completion observed at or after the boundary is reclassified as deadline exceeded.
Every launch also receives a unique container name derived from the one-use execution
claim. After a host timeout, the adapter must successfully force-remove that exact name
within two seconds before returning the deadline denial. Failure to confirm removal is a
distinct fail-closed cleanup error and must invoke the configured global safety pause.
Failure to latch safety is reported separately with fixed non-sensitive diagnostics.
Gateway runtime recovery independently enumerates every durable claim still in `claimed`
state, checks its derived container name, force-removes any match, and verifies absence
before runtime recovery and containment attestation continue. Ambiguous queries, cleanup
failure, or failed absence verification pause global safety.

Every launch carries `com.pentai.managed=true`, the fixed
`com.pentai.role=gateway-http-fixture`, and the exact execution-claim ID label. Recovery
must inspect and match all three labels before a name can authorize force-removal. A
matching name with missing or different ownership labels fails closed without deletion.
Launches also label the durable runtime ID, pinned image digest, and managed gateway
network. Recovery reloads those values through the claim-to-runtime ledger join and
requires exact matches, so incomplete durable linkage or a partially matching container
cannot authorize removal.

Recovery inspects the complete OCI object and also requires a canonical container ID, the
exact claim-derived name, the pinned image as the actual runtime image, and exactly one
network attachment matching the managed gateway network. Removal targets the verified
container ID rather than its name, followed by another exact-name absence check.
Only after verified removal or verified prior absence does recovery append a hash-chained
`gateway.fixture_cleanup_reconciled` event. It records the durable claim/runtime binding,
whether removal occurred, the verified container ID when applicable, and the constant
non-executing state. Failure paths never record a successful reconciliation.

## Hosted containment proof

The Linux rootless Podman workflow creates a unique internal network on the TEST-NET
subnet and constructs two complete supervised authorization chains through source
provenance, manifest validation, policy approval/activation, intent, decision, grant,
network attestation, controlled fixture DNS, budget/rate commitment, runtime launch,
one-use execution claim, result finalization, audit verification, and cleanup. It
launches the fixed fixture server at the fixed address and verifies both a successful
17-byte response and an 8-byte overflow stop. The same run continues to
prove direct egress, external DNS, IPv6, runtime sockets, host mounts, and host
namespaces are blocked and that resource limits and lifecycle recovery remain intact.

The harness fails unless every expected audit action exists, the result links to the
committed start, and the full hash chain verifies. This proof becomes evidence only
when the hosted workflow passes. Local unit tests mock the OCI boundary and do not
claim live containment.

## Compatibility and rollback

The additive `0017` migration preserves immutable claim history and has no downgrade
mutation. The new v1 contract is intentionally fixture-specific; widening its tuple or
authority semantics requires a new major version. The transport remains unreachable
from the public API, UI, agents, and plugins. Rollback disables the coordinator and
leaves claim, authorization, commitment, result, runtime, and audit records readable.

## Deferred enforcement

This is not general gateway authority. HTTPS/TLS, policy-derived destinations,
controlled live DNS, independent grant/start verification inside the isolated process, redirect execution,
response evidence, a dual-homed attested gateway route, general active-session kill switches,
and worker-to-gateway traffic remain deferred. Public, customer, bug-bounty, and other
external targets remain prohibited.
