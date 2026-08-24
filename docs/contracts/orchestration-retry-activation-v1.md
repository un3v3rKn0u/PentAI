# Orchestration retry activation v1

This additive trusted-core boundary consumes one exact immutable retry schedule and
reopens only its failed validation task and failed plan into non-executing `ready` and
`active` coordination state. It is the sole storage-authorized `failed → ready` path;
the general transition contract remains closed to that edge.

The command binds the exact assessment, plan/task revisions, schedule and digest,
attempt-two identity and digest, purpose, and bounded validity window. Consumption
revalidates the complete schedule, attempt, typed-failure, checkpoint, lease, worker,
manifest, approval, policy, retry-policy, retry-budget, safety, cancellation, and
recovery lineage. It denies before the deterministic due time and after schedule expiry.

Migration 0051 atomically stores one immutable activation receipt before the exact
storage-fenced task and plan transitions. Unique schedule and attempt constraints prevent
forks or multiple activations. Byte-equivalent replay returns the recorded receipt only
while the resulting plan/task revisions and states remain current; changed or stale replay
denies. Startup recovery never creates or consumes an activation.

The receipt is fixed to `authority: none` and `execution_enabled: false`. Activation does
not issue a current ready-state capability manifest or budget reservation, acquire a lease,
assign/contact/dispatch a worker, invoke a provider or plugin, create an `ActionIntent`,
evaluate policy, mint an `ActionGrant`, create a gateway request, contact a target, or
perform any external effect. Consequently, the reopened task is not runnable until later
independently reviewed prerequisites are issued and consumed.

Stored data is bounded identifiers, hashes, revisions, closed state values, and timestamps.
Secrets, credentials, evidence, prompts, diagnostics, paths, URLs, commands, provider or
plugin payloads, targets, and raw tokens are excluded. Application rollback disables new
consumption while retaining immutable history; migration reversal is unsupported.
