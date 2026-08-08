# Phase 1 guarded URL-source acquisition

**Status:** Implemented; sole-maintainer security review recorded

The authenticated local API can acquire a single HTTP(S) source document and store it
through the encrypted source store. This is source intake only; it is not an assessment
HTTP gateway and grants no testing authority.

## Deterministic boundary

- URLs are limited to HTTP or HTTPS on ports 80 and 443, with IDNA host normalization.
- Credentials, fragments, control characters, overlong URLs, malformed authorities,
  and non-web schemes fail closed.
- Every hop is resolved by the designated resolver. Empty, malformed, private,
  loopback, link-local, reserved, multicast, and mixed public/private answers are denied.
- The selected address is pinned for the connection and must equal the observed peer.
- Redirects are canonicalized, resolved, and checked again, with at most three hops.
- Requests use GET, fixed headers, a ten-second timeout, and a 2 MiB response ceiling.
- Only text, Markdown, HTML, JSON, and PDF storage media are accepted. Stored content
  receives the same encoding/structure checks as bounded file intake.

Tests use injected DNS and transport fixtures and make no external requests. Negative
proofs cover private IPv4/IPv6, mixed answers, empty DNS, redirect-to-loopback, peer
mismatch, oversized responses, unapproved media, unsafe ports, credentials, fragments,
and malformed URLs.

## Compatibility, rollback, and limits

No migration is required: existing provenance rows already support `source_kind=url`.
The endpoint and acquisition module are additive and can be removed without making
stored originals unreadable. The system does not render, execute, crawl, authenticate,
extract links from, or decompress acquired content. Proxy/VPN route attestation and OS
egress containment belong to the later assessment gateway and are not claimed here.
