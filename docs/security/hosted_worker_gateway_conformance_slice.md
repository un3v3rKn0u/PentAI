# Phase 1 hosted worker gateway conformance

**Status:** Implemented; evidence is valid only after the hosted workflow passes

## Outcome

The rootless Podman TEST-NET workflow now launches an exactly named, digest-pinned worker with
no network, attaches it through the bounded connector to the managed internal network, and
verifies the exact gateway/worker two-peer topology and attached worker controls. From inside
that exact worker it then proves the fixed TEST-NET gateway fixture is reachable while direct
alternate IPv4 egress, external DNS, IPv6, runtime sockets, host mounts, host namespaces, and
unbounded resources remain blocked.

The fixture client has one compiled destination (`192.0.2.20:8080`), request, Host value, and
path. It accepts no caller-supplied target or request arguments and is not exposed by the core.
This is conformance evidence, not production execution authority.

## Compatibility and rollback

No database or public contract changes are introduced. The workflow remains limited to
rootless Linux and TEST-NET resources. Rolling back removes the worker attachment bypass proof;
worker execution must remain disabled without equivalent passing hosted evidence.

The product execution boundary still requires a durable, authorized worker-to-gateway request
contract before the Phase 1 HTTP/browser worker can be marked complete.
