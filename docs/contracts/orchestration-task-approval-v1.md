# Orchestration task approval v1

This additive, non-executing boundary records a trusted-core asserted human decision for one
exact approval-gated orchestration task. The trusted core creates a short-lived request
bound to the current assessment, active policy hash, plan/task identities and revisions,
purpose, capability, and a digest of the bounded task parameters. The decision repeats
those bindings, requires explicit confirmation, identifies the authenticated local-core
actor, and is signed with the existing Ed25519 policy signer. Authenticated session
composition is deliberately deferred rather than falsely asserted by this service.

Approval satisfies only a recorded readiness condition. It deliberately leaves the task
in `awaiting_human`; it is not a task transition, policy decision, ActionIntent approval,
ActionGrant, dispatch instruction, or execution authority. Rejection atomically cancels
the task using the existing allowed transition and recomputes the plan state. A later
slice must design a dedicated approval-consuming readiness transition without weakening
the shared orchestration transition fence.

Both records fix `authority` to `none` and `execution_enabled` to `false`. Exact replay is
idempotent only while the signed decision, expiry, plan/task revisions, policy, assessment,
and resulting state remain current. Changed replay, missing confirmation, malformed
identity, expiry, cancellation, terminal state, policy replacement, cross-scope
substitution, digest tampering, or signer unavailability denies with stable codes.
Requests and decisions are immutable and linked to the audit ledger and outbox.

Migration 0039 is additive. Rollback disables the approval service and retains its
immutable history; the migration is not reversed. No prompts, evidence, targets,
credentials, secret references, or provider payloads are stored. Compatibility is limited
to schema version `1.0.0`; unknown fields and unsupported versions deny. Runtime approval
consumption, authenticated API/UI composition, leases, checkpoints, provider execution,
and effect-specific policy approval remain deferred.

## Authenticated API composition and v2 compatibility

The authenticated local-core API emits additive request and decision v2 documents.
The bearer-credential middleware derives `local-desktop-session`; closed request bodies
contain no actor, requester, authentication-context, role, delegation, or proxy field.
Request v2 persists that server-derived principal, a fresh per-process session UUID, and
`local_core_authenticated_session`. Decision v2 requires the same current principal,
session, explicit confirmation, and all original security bindings. Changed-principal
or cross-session reuse denies with `ORCHESTRATION_APPROVAL_ACTOR_MISMATCH`.

Version 1 remains readable and available to trusted internal callers for stored-record
compatibility, but it cannot be mixed with an authenticated v2 decision. V2 is additive
and requires no migration because the existing immutable tables store canonical closed
documents and their digests. Rollback removes the routes and v2 production while
retaining both v1 and v2 records. The current transport represents one local desktop
actor rather than multiple user accounts, but each process session is independently
fenced. Richer user identity and UI remain deferred. Approval consumption remains
separately blocked behind the unchanged task transition fence.
