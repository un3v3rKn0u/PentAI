# Supervised Assessments workspace

The Assessments workspace presents the existing durable workflow coordination contract.
It creates a planned workflow only for the currently displayed engagement after an active
policy exists, or loads one exact operator-entered workflow UUID. Creation retains one
idempotency key across failed responses so an operator retry cannot duplicate a workflow.

Lifecycle buttons are derived from the contract's exact transition graph and every request
binds the displayed workflow version. Starting or resuming is explicitly labeled as a
human-supervised action. The core revalidates engagement, active policy, expiry, revocation,
and safety state and remains authoritative for every transition.

Before enabling transitions, the UI requires the loaded policy bundle to equal the active
policy displayed in the workspace and requires `execution_enabled: false`. These checks
are presentation safeguards, not substitutes for core authorization. A workflow is a
coordination record. The workspace can enqueue one of the four contract task kinds with
exact unique UUID input references and an optional exact parent, then cancel a queued task.
It preserves the task idempotency key across uncertain responses and accepts a task into
the session list only when the exact workflow matches and both `dispatch_enabled` and
`external_effect_enabled` are false. There is no durable list endpoint, so the UI explicitly
labels the list as current-session-only rather than presenting it as complete history.

The workspace cannot claim leases, heartbeat, checkpoint, finalize, or dispatch tasks,
mint grants, launch workers, access the gateway, or cause external effects.

No endpoint, contract, schema, migration, or persistence behavior changes. Rollback removes
only this presentation layer and leaves immutable workflow and audit records intact.
