# Assessment workflow v1

`AssessmentWorkflow` and `WorkflowTask` define PentAI's first durable supervised-work
boundary. They are coordination records, not authorization records.

## Lifecycle

Workflows move only through these deterministic transitions:

- `planned` to `ready` or `cancelled`;
- `ready` to `running` or `cancelled`;
- `running` to `paused`, `completed`, or `cancelled`;
- `paused` to `running` or `cancelled`.

Starting or resuming requires a human actor, the caller's expected version must match,
and the engagement, active policy, expiry, revocation, and global safety state are
revalidated. Startup recovery changes every `running` workflow to `paused`; it never
resumes work automatically. Completion is denied while queued tasks remain. Cancelling
a workflow atomically cancels its queued tasks.

Tasks are idempotent within a workflow and may reference only an available parent in
that same workflow. They have only `queued` and `cancelled` states in v1.
`dispatch_enabled` and `external_effect_enabled` are contract constants set to false.
Neither a workflow nor a task can substitute for an `ActionGrant`, gateway request
commitment, execution claim, or any other authority.

## Persistence and audit

Migration `0018_assessment_workflows.sql` adds the workflow and task tables without
rewriting earlier rows. Database triggers protect identity, allowed state transitions,
version increments, terminal timestamps, and non-execution flags. Deletion is denied.
Every successful mutation appends a hash-chained audit event and transactional outbox
record. Invalid, stale, conflicting, or unverifiable input rolls back without either.

## Compatibility and rollback

Both schemas begin at `1.0.0`, reject unknown fields, and use new table names and API
routes, so existing consumers and databases remain compatible. Application rollback is
safe because older code ignores the additive tables. The migration is intentionally
not reversed: retained immutable records preserve audit and recovery evidence.

## Deferred behavior

Task claiming, leases, heartbeats, retries, checkpoints, fencing tokens for workers,
dead-letter handling, and any dispatch integration are deferred. Until those controls
exist and are reviewed, no workflow task can reach a worker or gateway.
