# Network identity supervisor

## Outcome

The local core owns a bounded continuous check of every assessment that has a valid
network attestation. It performs one check before the supervisor reports ready and
repeats checks until shutdown. It never opens a socket, rotates an attestation, resumes
an assessment, or enables execution.

The check re-measures the public source IPv4/IPv6, route profile, resolver mode, and
resolver identity through a trusted `NetworkAttestor`. The result must match
the current attestation and active signed policy exactly. The current attestation must
also remain unexpired and active throughout the check.

## Kill-switch behavior

Any missing, expired, changed, conflicting, malformed, stale, or unverifiable state
pauses the assessment. That existing durable transition invalidates attestations,
revokes unused grants, aborts prepared gateway sessions, releases budget reservations,
and appends audit events. Unexpected monitor failures additionally degrade application
readiness and pause global safety.

Successful checks append `network.identity_checked` with the policy hash and current
attestation identifier. Source addresses and observer output are not copied into the
event or health diagnostics. Status reports contain only a fixed reason code, the
number of monitored assessments, watchdog state, and `execution_enabled: false`.

## Compatibility and rollback

No schema or migration changes are required. Existing attestation, safety, grant,
session, budget, and audit records provide the durable enforcement path. With no valid
network authority, the unconfigured monitor reports `disabled`; if authority appears
without a monitor, it latches `degraded` and pauses global safety.

Before rolling back, pause all assessments and verify that no valid network
attestations or prepared gateway sessions remain. Older code cannot continuously
verify their identity.

## Production composition

Production adapters are disabled unless `PENTAI_NETWORK_ATTESTATION_ENABLED=1` and
every required identity is configured:

- `PENTAI_NETWORK_OBSERVERS`: two to four semicolon-separated
  `<id>|<ipv4-or-ipv6>|<https-url>` records. Each observed family needs two distinct
  HTTPS origins that return exactly `{"ip":"<public-address>"}` without redirects.
- `PENTAI_NETWORK_ROUTE_PROFILE_ID`, `PENTAI_NETWORK_ROUTE_INTERFACE`, and optional
  `PENTAI_NETWORK_ROUTE_GATEWAY` identify the expected default route.
- `PENTAI_NETWORK_RESOLVER_MODE`, `PENTAI_NETWORK_RESOLVER_ID`, and comma-separated
  `PENTAI_NETWORK_RESOLVER_ADDRESSES` identify the complete expected resolver set.
- Optional observer, route, and watchdog timeouts are bounded from 0.1 through 10
  seconds.

The adapters use direct TLS connections rather than environment proxy settings,
require normal certificate/hostname validation and TLS 1.2 or newer, limit responses
to 1 KiB, and reject credentials, queries, fragments, non-default ports, IP-literal
observer hosts, extra JSON fields, non-public answers, and wrong address families.
Host route inspection uses fixed operating-system commands without a shell and fails
closed on ambiguous or malformed output. Incomplete or invalid enabled composition
pauses global safety with a fixed diagnostic and degrades readiness.

Configuration values are trusted local deployment inputs. Endpoint independence must
be established and reviewed by the deployer; different DNS names alone do not prove
different operators or infrastructure.

## Deferred enforcement

No external observer has been designated or contacted by repository tests. Live route
and VPN-loss matrices, endpoint-operator independence, resolver transport enforcement,
gateway HTTP sockets, redirect execution, worker attachment, and automatic assessment
resumption remain absent. Target-facing execution remains disabled.
