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
- a timeout from 1 millisecond through 5 seconds.

Every other address, host, path, method, option, duplicate, or unknown argument is
rejected before the connection. The adapter also requires a fresh complete containment
attestation for the exact network. The OCI adapter constructs a fixed argument vector,
uses the managed internal network, a read-only root, no capabilities,
no-new-privileges, and strict CPU/memory/PID limits. It parses only an exact typed JSON
measurement and never returns or logs the response body.

The client uses one monotonic deadline across connection retries, request write,
header parsing, and body reads. Headers are read with an 8 KiB ceiling. Only HTTP/1.1
200 with one valid `Content-Length` is accepted; transfer encoding, ambiguous length,
malformed headers, incomplete bodies, and transport failures deny. Body reads stop at
the authorized limit plus one proof byte.

## Hosted containment proof

The Linux rootless Podman workflow creates a unique internal network on the TEST-NET
subnet, launches the fixed fixture server at the fixed address, and verifies both a
successful 17-byte response and an 8-byte overflow stop. The same run continues to
prove direct egress, external DNS, IPv6, runtime sockets, host mounts, and host
namespaces are blocked and that resource limits and lifecycle recovery remain intact.

This proof becomes evidence only when the hosted workflow passes. Local unit tests
mock the OCI boundary and do not claim live containment.

## Compatibility and rollback

No authorization contract or database schema changes. The transport consumes the
existing `GatewayResponseMeasurement` shape and remains unreachable from the public
API, UI, agents, and plugins. Rollback removes the fixture modes and adapter; existing
authorization, commitment, result, runtime, and audit records are unchanged.

## Deferred enforcement

This is not general gateway authority. HTTPS/TLS, policy-derived destinations,
controlled live DNS, grant/start loading inside the gateway, redirect execution,
response evidence, a dual-homed attested gateway route, active-session kill switches,
and worker-to-gateway traffic remain deferred. Public, customer, bug-bounty, and other
external targets remain prohibited.
