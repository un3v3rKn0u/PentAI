# Network Health Kill-Switch Slice

## Outcome

Every trusted network-attestation refresh now acts as a synchronous safety checkpoint.
The core derives current policy state, compares the new route, source IPv4/IPv6, and
resolver identity with the sole valid prior attestation, and persists a replacement
only when the identity is unchanged and still policy-compliant.

An observer/route failure, disagreement, malformed measurement, policy mismatch, or
identity change pauses the assessment through the durable safety control plane. That
transaction revokes outstanding grants, increments the revocation epoch, and
invalidates the current attestation. A successful refresh also invalidates the prior
attestation in the same persistence transaction, so only one remains valid.

## Failure behavior

- The original diagnostic code is returned to the trusted monitor.
- Pause is attempted even when measurement fails before a new document exists.
- Failure to pause never turns the measurement into an allow; the original operation
  still fails closed.
- Resume remains human-supervised and requires a current signed policy followed by a
  fresh network attestation. Invalidated attestations cannot be restored.

## Compatibility and rollback

No schema or migration changes are required. Existing attestation history remains
immutable. Rollback removes automatic refresh failure handling but does not restore
revoked grants or invalidated attestations.

## Deferred enforcement

This slice supplies the deterministic checkpoint and kill-switch transition, not a
background scheduler or production network adapters. Continuous polling, OS route
events, authenticated public-IP endpoints, active gateway-session closure, controlled
DNS transport, firewall containment, and worker isolation remain prerequisites for
target-facing execution.
