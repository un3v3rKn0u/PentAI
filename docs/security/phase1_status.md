# Phase 1 status

## Decision

Phase 1 implementation is complete for the `local-development-owned-fixtures` assurance
scope. This milestone supplies the Safe Supervised MVP control plane and one fully traced,
owned TEST-NET HTTP effect. It does not authorize external targets, autonomous testing,
browser automation, production distribution, or a production release.

The machine-readable evidence map is
[`phase1_completion_manifest.json`](phase1_completion_manifest.json). Contract validation
fails when one of the nine required capability groups, its implementation, its negative
tests, its invariant mapping, or its security review is absent. Gateway and worker groups
also require the protected rootless containment workflow to remain present.

## Completed capability groups

1. Signed policy lifecycle and typed, expiring activation approval.
2. Intent, deterministic decision, single-use grant, bounded effect, and immutable trace.
3. Controlled DNS and destination reauthorization for protocol, host/SNI, port, redirects,
   CNAMEs, address families, and rebinding.
4. Rootless digest-pinned worker isolation with gateway-only networking and hosted bypass
   tests.
5. Multi-observer source-IP and OS route/resolver attestation with continuous kill switches.
6. Durable workflow, fencing, recovery, and hash-chained audit.
7. Encrypted classified evidence, inactive redacted text previews, retention deletion,
   authenticated backup, and isolated restore.
8. Finding and coverage-aware No Findings reports with explicit approval and local export.
9. Global/assessment emergency stop, stale-authority revocation, and storage-failure gates.

## Exit evidence

- The protected rootless Podman matrix demonstrates the exact worker-to-gateway product
  path and rejects alternate IPv4, DNS, IPv6, runtime socket, host mount/namespace, and
  resource-control bypasses.
- Every enabled effect is limited to a signed, single-use owned-fixture claim and produces
  a complete immutable execution trace.
- Route/source observer failure, identity drift, expiry, clock uncertainty, cleanup
  ambiguity, and storage failure all close new authority and request cleanup.
- Fault-injection tests cover transaction rollback, interrupted writes, startup recovery,
  stale-grant revocation, backup authentication, tombstone preservation, and isolated
  restore.
- Report artifacts bind policy, timestamps, evidence, coverage, explicit human approval,
  and supervised local export.

## Assurance boundary and later phases

Hosted checks are required before this completion decision is accepted. Physical power-cut,
full-device-loss, VPN/provider production matrices, general external HTTP(S), browser
automation, production signing/notarization, and independent security assurance remain
release requirements in later phases. They are not silently treated as passing Phase 1
evidence, and Phase 1 credentials or fixture claims cannot enable them.

## Security review

The final review uses the documented sole-maintainer exception and is therefore
non-independent. It must examine the complete branch diff, the manifest evidence, negative
paths, migration and compatibility impact, hosted results, and the remaining assurance
boundary. Any failed or skipped required check blocks acceptance.
