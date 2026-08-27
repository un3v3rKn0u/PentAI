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

## Retry-bound checkpoint v2

Command and receipt v2 add the exact retry activation, immutable attempt two, consumed
retry unit, TaskCapabilityManifest v3 digest, task-budget reservation v3 request digest,
and lease-consumption v2 lineage. V1 and mixed-version records cannot satisfy this
boundary. The service revalidates the complete current lineage before initial production
and exact replay; safety, worker, policy, budget, or recovery changes fence stale replay.

Migration 0056 adds nullable immutable retry-lineage columns and an exact insert guard to
the existing checkpoint table. V1 rows require no conversion. Application rollback
disables v2 production while retaining immutable history; migration reversal is
unsupported. V2 remains metadata-only and cannot fail, complete, retry, resume, lease,
dispatch, contact a worker, invoke providers/plugins, or create execution authority.

## Attempt-three checkpoint v3

Command and receipt v3 are version-exact to the spent lease-consumption v3 lineage,
attempt three, activation v2, TaskCapabilityManifest v4, and task-budget reservation v4.
They use a separate immutable table so v1/v2 rows and head semantics remain unchanged.
Sequence starts at one for the exact running attempt-three task revision; every later
record names the current predecessor digest, and progress cannot decrease.

Trusted core revalidates the active policy and assessment, safety state, running task,
worker registry version, budget account version, manifest and reservation validity,
lease fence, and recovery generation on creation and exact replay. Migration 0069 adds
the version-exact table, unique head constraints, immutable triggers, and a storage guard
that requires the matching lease-consumption v3 receipt. Rollback disables production
while retaining immutable history; destructive migration reversal is unsupported.

V3 stores bounded progress metadata only, fixes `authority: none` and
`execution_enabled: false`, and cannot transition state, resume work, dispatch a worker,
record failure or completion, contact providers/plugins/targets, or create an effect.
