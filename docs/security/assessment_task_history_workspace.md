# Phase 1 durable assessment task history

**Status:** Implemented; sole-maintainer security review recorded

The Assessments workspace now consumes the existing authenticated workflow snapshot to
reconstruct task intent, lifecycle state, attempts, and non-sensitive failure codes after
a restart or exact workflow lookup. Enqueue and cancellation refresh that snapshot rather
than treating session memory as authoritative.

The presentation accepts a snapshot only when its workflow identity matches the exact
requested UUID, workflow execution is disabled, every task belongs to that workflow,
every task and lifecycle asserts dispatch and external effects are disabled, identities
are unique, and task/lifecycle membership is complete. Invalid or partial snapshots clear
the displayed workflow and fail closed.

Lease tokens, lease owners, worker operations, checkpoint outputs, dispatch controls, and
gateway operations are not exposed. This slice changes no schema, migration, persistence,
workflow lifecycle, or execution behavior. Rollback restores session-only task display
without changing durable records.
