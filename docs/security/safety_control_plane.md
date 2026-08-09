# Safety Control Plane Runbook

**Scope:** local supervised development only; no target-facing execution

## Startup and recovery

Every core startup atomically revokes all unused grants, pauses active assessments,
increments their revocation epochs, sets global safety to `paused`, and appends
`safety.startup_recovery` to the audit chain. This is expected behavior, not a health
failure.

To recover safely:

1. Verify the authenticated core is healthy and the audit chain is valid.
2. Review the reported startup-recovery counts and the active signed policy.
3. Explicitly set global safety to `active` with a meaningful reason.
4. Explicitly resume each intended assessment. This fails closed if its policy is
   missing, revoked, expired, or unverifiable.
5. Re-evaluate the intended action and mint a new grant. Never reuse a pre-restart
   grant.

## Pause and emergency stop

Use assessment pause to stop one assessment. Use global pause for a planned halt and
global stop for an emergency. Both global halt states revoke all outstanding grants
and pause all active assessments. Repeating a halt is safe and creates another audited
generation. Global resume does not automatically resume any assessment.

## Diagnostics

`GET /api/v1/safety-state` reports status, reason, generation, updater, and update
time. It deliberately reports `network_attested: false` and
`execution_enabled: false`. Audit events contain actor identity, reason, revoked-grant
count, and paused-assessment count, but no credentials or source content.

The stable denial codes are `SAFETY_STATE_MISSING`, `SAFETY_STATE_INVALID`,
`SAFETY_REASON_REQUIRED`, `SAFETY_RESUME_DENIED`, `ASSESSMENT_STATE_INVALID`,
`ASSESSMENT_PAUSED`, and `GLOBAL_SAFETY_PAUSED`.

## Compatibility and rollback

Migration `0008_safety_control_plane.sql` is additive. Older application versions
ignore the table, but they do not enforce these controls and must not be used for
security-sensitive work. Retain the table and audit records during rollback. Do not
delete or modify safety state directly to clear a pause.

## Deferred prerequisites

This control plane does not attest time, routes, DNS, public source addresses, worker
isolation, or gateway containment. Those controls and their negative bypass tests must
exist before any grant can cause a network effect.
