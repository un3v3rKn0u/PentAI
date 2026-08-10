# Controlled DNS transport

## Outcome

The local core can compose the existing deterministic `ControlledResolver` with a
pinned DNS wire backend. This supplies a trusted resolver transport for future gateway
destination authorization without adding an HTTP socket, worker access, or an
execution API.

The feature is disabled by default. Enabling it requires network attestation to be
enabled, the selected DNS server IP to appear in the exact attested resolver set, and
the resolver mode and identity to come from the same trusted local configuration.

## Transport rules

- `tunnel_resolver` sends length-framed DNS over TCP directly to the configured IP on
  port 53. It has no UDP, search-domain, system-resolver, proxy, or fallback path.
- `approved_resolver` sends the same bounded DNS framing over TLS directly to the
  configured IP on port 853. TLS 1.2 or newer, normal certificate validation, and the
  configured canonical server name are mandatory.
- A and AAAA questions use independently generated 16-bit transaction identifiers.
  The response must match the identifier, canonical question name, type, and class.
- A and AAAA responses must report the same ordered CNAME chain. A random identifier
  collision is retried within a fixed bound; ambiguous identity generation denies.
- Responses are limited to 4 KiB and 64 total resource records. Truncation, non-zero
  result codes, invalid opcode/reserved flags, malformed labels, compression loops,
  unrelated owners, invalid CNAME chains, duplicate addresses, trailing bytes, early
  EOF, and transport timeouts fail closed. Connect, TLS handshake, framing, and reads
  share one monotonic deadline per query rather than resetting the timeout per chunk.

The parser extracts only IN-class A, AAAA, and CNAME answer records. The outer
`ControlledResolver` still enforces answer and CNAME limits and binds the resolver
mode and identifier to the current network attestation. Destination authorization
then rejects non-global production addresses, unapproved IPv6, out-of-scope CNAMEs,
and changed pinned answers.

## Configuration

All configuration is trusted local deployment input:

- `PENTAI_CONTROLLED_DNS_ENABLED=1`
- `PENTAI_CONTROLLED_DNS_SERVER_IP=<literal IPv4 or IPv6 address>`
- `PENTAI_CONTROLLED_DNS_TIMEOUT_SECONDS=<0.1 through 10>` (optional; default `2`)
- `PENTAI_CONTROLLED_DNS_TLS_HOSTNAME=<certificate DNS name>` only when
  `PENTAI_NETWORK_RESOLVER_MODE=approved_resolver`

Partial configuration, a server outside `PENTAI_NETWORK_RESOLVER_ADDRESSES`, a TLS
name on a tunnel resolver, or a missing TLS name on an approved resolver prevents
startup. Configuration does not create authority and is inaccessible to UI, AI,
workers, and public API callers.

## Compatibility and rollback

No schema or migration changes are required. Disabled deployments retain the previous
non-executing behavior and store `None` as the application resolver. Existing
attestations and destination decisions remain readable.

Before rollback, disable controlled DNS and verify that no assessment is active and no
gateway session is prepared. Older code cannot supply the pinned production transport.

## Remaining enforcement

Repository tests use only in-memory packets and mocked owned sockets; they perform no
live DNS query. Hosted tunnel/DoT interoperability, resolver route binding, certificate
failure, platform firewall denial of worker port 53/853, known DoH endpoints, custom
resolvers, raw sockets, and alternate proxies remain required. `INV-NET-003` is
therefore only partially implemented, and target-facing execution remains prohibited.
