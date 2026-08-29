# Orchestration dead-letter registration v1

This additive boundary registers immutable metadata for one exact current attempt-three
terminal-consumption receipt and its authoritative `dead_letter` task revision. It is
not a transport queue, deliverable message, operator-review request, retry instruction,
or execution request.

Trusted core revalidates the complete terminal decision, failed attempt, failure,
checkpoint, lease, worker, approval, manifest, budget, retry, policy, cancellation,
safety, fencing, and recovery lineage in one immediate transaction. The command cannot
select a queue, destination, routing key, priority, schedule, retry behavior, retention
override, payload, operator instruction, or security meaning.

One terminal consumption produces at most one deterministic registration. Exact replay
returns the existing receipt only while every durable security binding remains current;
changed identity, competing registration, stale state, policy replacement, cancellation,
safety pause, worker revocation, account-version change, fencing change, or recovery
advancement denies.

The receipt fixes the record to `registered` and `immutable_history`. Delivery, claim,
acknowledgement, retry, deletion, cleanup, operator review, and execution flags are all
false. `authority` is `none`. Registration changes neither task nor plan state and the
metadata-only outbox event is not a publication or delivery instruction. `registered_at`
is audit chronology only; it defines no processing order, priority, or eligibility time.

Migration 0076 adds a separate immutable one-to-one ledger with exact terminal-
consumption, terminal-decision, scope, revision, and current dead-letter-state guards.
The older workflow-task lifecycle remains a separate subsystem and cannot satisfy this
boundary. Existing terminal, retry, and plan-graph contracts remain unchanged.

Application rollback disables new registrations while retaining readable history.
Destructive migration reversal is unsupported. Delivery, claiming, acknowledgement,
retention cleanup, operator workflows, notifications, dispatch, providers/plugins, UI,
and runtime composition remain deferred.
