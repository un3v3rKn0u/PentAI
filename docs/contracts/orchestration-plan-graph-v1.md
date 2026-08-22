# Orchestration plan graph v1

## Boundary and outcome

`OrchestrationPlanGraph v1` is PentAI's durable, assessment-scoped coordination graph.
It stores bounded specialist task metadata and typed `requires_success` edges, computes
readiness deterministically, and applies revision-fenced state changes. It is not the
Master Orchestrator runtime and cannot dispatch work.

Plans and tasks fix `authority` to `none` and `execution_enabled` to `false`. A plan,
dependency, state, command, or recovered record is not policy, approval, a capability,
an `ActionIntent`, or an `ActionGrant`. Existing Phase 1 authorization and gateway
boundaries remain the only route to an external effect.

## Graph and state rules

A new graph binds one UUID plan and all tasks to one exact assessment. It contains 1–128
tasks, at most 512 unique typed edges, bounded objectives and opaque input references,
and a stable idempotency key. Duplicate task identities or edges, self-edges, missing
references, unsupported task/dependency types, cycles, malformed fields, and initial
state other than `pending` deny.

Creation derives root tasks as `ready` or `awaiting_human` and dependent tasks as
`blocked`. Only these coordination transitions are implemented:

- `ready` to `cancelled` through the general transition service;
- `ready` to `running` only through an exact current lease-consumption receipt and
  dedicated trusted-core operation;
- `awaiting_human` or `blocked` to `cancelled`;
- `awaiting_human` to `ready` only through an exact authenticated approval-consumption
  receipt and dedicated trusted-core operation;
- `running` to `cancelling`, `succeeded`, or `failed`;
- `cancelling` to `cancelled` or `failed`.

Success recomputes dependent readiness. The general transition command cannot make an
`awaiting_human` task ready. Terminal tasks cannot be
reopened. Plans become completed only when every task succeeds, cancelled when all
tasks terminate without failure, or failed when all tasks terminate and any failed.

## Durability, replay, and recovery

Migration `0035_orchestration_plan_graph.sql` adds normalized plan, task, dependency,
and command tables. Identity and non-authority fields are immutable, deletion is
denied, and every state mutation increments the relevant revision. Commands bind exact
plan, assessment, task, plan revision, task revision, target state, and a five-minute
request time. Identical command replay returns the stored result; changed reuse of the
same command identity denies.

Transactions begin immediately, so concurrent commands cannot both consume one
revision. Startup recovery changes `running` and `cancelling` tasks to `failed`,
recomputes dependents, and increments revisions. It never resumes, retries, leases,
dispatches, or reconstructs authority. Repeated recovery is inert.

## Compatibility, privacy, rollback, and residual risk

The contracts, service, and migration are additive. Earlier workflows and consumers
are unchanged. Application rollback disables the service while retaining immutable
history; the migration is not reversed. Stored values are bounded coordination
metadata and opaque references only. Raw secrets, evidence content, prompts, provider
payloads, model output, targets, and tool arguments are absent.

Plan authorship/authentication, Master Orchestrator decisions, checkpoints,
general retry scheduling, and plan-transition audit/outbox events,
retention/deletion, agents, provider calls, worker assignment, `ActionIntent`
conversion, and execution remain deferred. The broader orchestration action remains
open. A separate additive task-budget boundary now composes current plan/task state,
capability manifests, cancellation fencing, durable integer reservations, and recovery;
provider usage charging and end-to-end action budget enforcement remain deferred.
An additive task-approval boundary persists and consumes an exact authenticated signed
v2 human decision through a storage-gated readiness transition. The receipt and state
change grant no execution authority.
An additive orchestration lease boundary can assign non-executing coordination
ownership to an exact ready validation task using the v2 manifest/budget prerequisites
and a trusted worker-registry identity. Dedicated lease consumption can move that task
to durable running coordination state while atomically releasing the lease. It does not
dispatch or contact the worker, and the general transition service remains denied.
Metadata-only orchestration checkpoints may record monotonic progress for the exact
running task and lease-consumption receipt. They do not alter plan/task state or provide
resume, retry, completion, dispatch, or execution authority.
