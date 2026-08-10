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

## Continuous identity verification

Once a valid attestation exists, the application-owned network safety supervisor
re-measures the route, resolver, and source identities before reporting the monitor
ready and at a bounded interval afterward. Measurements are compared with the exact
current attestation and active policy without rotating or extending that authority.
Every successful comparison appends `network.identity_checked` to the audit chain.

Expired authority, policy or safety races, route/resolver/source changes, observer
disagreement, malformed measurements, monitor exceptions, and watchdog shutdown
failure deny. The assessment safety transition invalidates its attestations, revokes
unused grants, aborts prepared gateway sessions, releases reservations, and records
the stop in the audit chain. Diagnostics expose only fixed reason codes and counts.

If network authority exists while no monitor is configured, readiness degrades and
global safety is paused. An empty authority set remains compatible with the default
non-executing local configuration.

Production composition is explicit and disabled by default. Each configured observer
has a unique identity and HTTPS origin, uses TLS 1.2 or newer with normal hostname and
certificate validation, ignores ambient proxy settings, permits no redirect, applies
a bounded timeout and 1 KiB response limit, and accepts only an exact `{"ip": "..."}`
JSON document containing the configured public address family. Each address family
that is observed requires agreement from at least two endpoints.

The host route inspector compares the exact default interface, optional next hop, and
complete configured resolver-address set before returning the policy's route and
resolver identities. Ambiguous routes, unsupported platforms, command failure,
malformed output, partial configuration, duplicate observer identities/origins, and
route or resolver drift degrade readiness and pause safety.

## Destination checks

Every candidate is canonicalized and evaluated under the active policy. Protocol and
port changes, unapproved redirects, out-of-scope CNAMEs, SNI/Host mismatches, empty or
duplicate answers, non-global addresses, changed pinned answers, and unapproved IPv6
deny before use. All accepted answers are pinned in the decision.

RFC 5737 and RFC 3849 documentation addresses are accepted only when the attestation
uses the explicit `fixture:` resolver namespace. This supports owned, deterministic
tests and is not available to production resolver identities. A later dependent slice
adds an injectable controlled-resolver boundary, but no production DNS backend or
public-IP probe is implemented yet.

## Compatibility and rollback

Migration `0009_network_authorization_control.sql` is additive. Existing grants and
policies remain readable, but cannot gain network authority without a fresh matching
attestation and destination decision. Rolling code back leaves the new tables unused;
the migration is not destructively reversed. Historical decisions and attestations
must remain available for audit.

## Deferred enforcement

Deployment-owned observer availability and independence, live VPN/interface matrices,
resolver transport enforcement, gateway sockets, the live redirect loop, worker
network isolation, and OS firewall rules are prerequisites for execution and remain
deferred. Synthetic observers are not production public-IP evidence. This slice must
not be interpreted as satisfying gateway containment or target-facing verification.
