# Orchestration task snapshot v2

## Boundary

`OrchestrationTaskSnapshot v2` is a read-only, version-exact view of one durable
orchestration task. It reads state only from `orchestration_tasks.state`; it is not a
second state source, a task command, or a replacement for plan-graph v1 creation.

The snapshot binds the assessment, plan identity/revision/state, task
identity/revision/type/state, observation time, and fixed non-authority fields. It omits
objectives, input references, diagnostics, evidence, prompts, commands, paths, URLs,
provider/plugin output, targets, and secrets.

## Terminal lineage

Every non-dead-letter state requires `terminal_lineage: null`. A `dead_letter` snapshot
requires exactly one immutable terminal-consumption v1 row for the same assessment,
plan, task, plan revision, and resulting task revision. The trusted reader validates the
receipt contract, stored content hash, self-digest, decision identity/digest, outcome,
and reason before returning bounded terminal identifiers. Missing, ambiguous, malformed,
tampered, cross-scope, or revision-mismatched lineage denies.

The reader creates no transition or terminal record and emits no audit/outbox event.
Recovery cannot invent, translate, or advance a snapshot.

## Compatibility and limitations

Plan-graph v1 remains unchanged for graph creation and legacy reads. After terminal
consumption makes `dead_letter` reachable, v1 readers fail closed rather than silently
misrepresenting it; consumers must use this version-exact boundary. Application rollback
to a version without snapshot v2 is unsupported once a dead-letter row exists.

Plan-state composition, queueing, operator review, notification, completion, dispatch,
providers/plugins, UI, and runtime composition remain deferred. Every snapshot fixes
`authority: none` and `execution_enabled: false` and cannot authorize any effect.
