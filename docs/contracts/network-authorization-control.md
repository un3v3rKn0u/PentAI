# Network Authorization Control Contracts

This slice adds deterministic preflight authorization without opening sockets or
enabling target-facing execution. `NetworkAttestation` records measurements produced
by a trusted future attestor. `DestinationDecision` binds a current gateway-audience
grant to one attestation and one canonical destination evaluation.

## Authority and lifecycle

- Only core service code may persist an attestation; no public API, UI, AI, worker, or
  tool can self-attest.
- An attestation is accepted only for the active, signed policy while global and
  assessment safety are active. Route and source identities must match that policy.
- Policy activation/replacement/revocation, assessment pause, global pause/stop, and
  startup recovery permanently invalidate affected attestations.
- Destination authorization requires an unused, unrevoked, unexpired, correctly
  signed `pentai-egress-gateway` grant with exact policy and revocation-epoch linkage.
- Destination decisions are immutable audit records. They never consume the grant and
  always carry `execution_enabled: false` in this slice.

## Destination checks

Every candidate is canonicalized and evaluated under the active policy. Protocol and
port changes, unapproved redirects, out-of-scope CNAMEs, SNI/Host mismatches, empty or
duplicate answers, non-global addresses, changed pinned answers, and unapproved IPv6
deny before use. All accepted answers are pinned in the decision.

RFC 5737 and RFC 3849 documentation addresses are accepted only when the attestation
uses the explicit `fixture:` resolver namespace. This supports owned, deterministic
tests and is not available to production resolver identities. No resolver or public-IP
probe is implemented here.

## Compatibility and rollback

Migration `0009_network_authorization_control.sql` is additive. Existing grants and
policies remain readable, but cannot gain network authority without a fresh matching
attestation and destination decision. Rolling code back leaves the new tables unused;
the migration is not destructively reversed. Historical decisions and attestations
must remain available for audit.

## Deferred enforcement

The trusted measurement process, controlled resolver, gateway sockets, live redirect
loop, session termination, worker network isolation, OS firewall rules, and two-endpoint
public-IP comparison are prerequisites for execution and remain deferred. This slice
must not be interpreted as satisfying gateway containment or target-facing verification.
