# Trusted Network Attestor and Controlled Resolver Slice

## Outcome

This dependent Phase 1 slice supplies two non-executing infrastructure boundaries:

- `NetworkAttestor` requires at least two uniquely identified observers to report the
  same canonical IPv4/IPv6 identity before it creates a short-lived attestation.
- `ControlledResolver` binds every lookup to the resolver mode and identity stored in
  that attestation, bounds answer and CNAME counts, and rejects malformed or duplicate
  results before deterministic destination authorization.

The core derives the assessment and policy binding from current durable state. Callers
cannot select a different policy hash. The controlled resolver feeds the existing
destination authorization method; the raw decision method is private to the core.

## Failure and trust model

Observer failure, disagreement, duplicate endpoint identity, wrong address family,
missing route identity, resolver mismatch, invalid names or ports, empty/oversized
answers, and duplicate address/CNAME records fail closed. No result enables execution.

Observers and resolver backends are trusted infrastructure adapters, not agent tools.
No public API or UI can provide their measurements. Synthetic tests inject owned
fixtures; this slice deliberately provides no host-system resolver, public-IP endpoint,
HTTP client, retry loop, or background monitor.

## Compatibility and rollback

The slice adds no migration or contract version. It produces the existing
`NetworkAttestation v1` and consumes its resolver fields. Rolling back removes these
producer boundaries while leaving previously persisted attestations as immutable audit
history; those attestations remain unusable after expiry or a safety transition.

## Deferred verification

Production adapters must pin an approved endpoint set, authenticate endpoint responses,
bind route/interface inspection to the operating system, enforce timeouts and bounded
concurrency, and continuously re-attest. Controlled DNS transport, port 53/853 and
DoH/DoT blocking, gateway sockets, session termination, and worker network isolation
remain required before any target-facing execution.
