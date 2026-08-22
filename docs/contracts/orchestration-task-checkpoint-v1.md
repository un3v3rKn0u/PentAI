# Orchestration task checkpoint v1

This additive boundary persists immutable, metadata-only progress for one exact current
`running` validation task. Each command binds the current policy, plan/task revisions,
ready-bound manifest and budget, approval when applicable, lease-consumption receipt,
trusted worker identity, lease/fencing/recovery generations, sequence, predecessor
digest, and a bounded validity window.

Sequence starts at one and increases without gaps. Later records must name the exact
prior checkpoint digest and cannot decrease progress. Immediate transactions and unique
task/revision/sequence storage reject concurrent forks. Exact command replay returns the
existing receipt; changed reuse denies.

Only progress percentage and a closed status value are accepted. Artifact references,
paths, URLs, commands, flags, evidence, prompts, model/provider/plugin content, targets,
credentials, secrets, and raw lease tokens are excluded. Records fix `authority` to
`none` and `execution_enabled` to false and cannot transition or complete a task,
dispatch/contact a worker, schedule a retry, or create an external effect.

Migration 0044 is additive and immutable. Application rollback disables new checkpoint
production while retaining history; reversal is unsupported. Existing Phase 1 workflow
checkpoints remain separate and unchanged. Artifact references, retries, completion,
dispatch, and runtime resume semantics remain deferred.
