# Phase 1 probe-side execution claim verification

**Status:** Implemented for the isolated HTTP fixture; sole-maintainer review recorded

## Outcome

The network probe now verifies execution authority inside the isolated, digest-pinned image
before its first socket operation. The conformance image embeds only the Ed25519 public key
before its digest is measured. Launch supplies the canonical signed v2 payload and signature;
the private key remains with the core authority.

The probe verifies the signature against the embedded trust anchor, parses the complete
no-unknown-field unsigned claim, checks the fixed HTTP tuple and non-executing flags, requires
the response ceiling to match exactly, and prevents the command deadline from extending the
signed durable deadline. Missing, malformed, wrong-key, modified, or contradictory inputs
fail before connection.

## Safety and compatibility

The v2 schema and durable database ledger are unchanged, so no contract version or migration
is required. The canonical payload is split into at most five ordered, numbered chunks; each
argument remains within 256 characters and the complete OCI vector remains within 32 items.
The probe rejects missing, duplicate, reordered, inconsistent, excessive, or oversized chunks.
These arguments carry synthetic authorization metadata and a public signature, not secrets or
response data. The new Rust dependencies are lockfile-pinned
and used only for base64 decoding, strict JSON parsing, RFC 3339 time comparison, and Ed25519
verification.

Rollback disables the fixture coordinator or returns to the prior digest-pinned image while
retaining claim and audit history. The proof remains limited to an ephemeral owned TEST-NET
image. General gateway destinations, key rotation, and full ledger verification in the probe
remain deferred.
