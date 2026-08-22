CREATE TABLE orchestration_task_lease_fences (
    task_id TEXT PRIMARY KEY REFERENCES orchestration_tasks(task_id),
    current_lease_generation INTEGER NOT NULL CHECK (current_lease_generation >= 0),
    recovery_generation INTEGER NOT NULL CHECK (recovery_generation >= 1),
    version INTEGER NOT NULL CHECK (version >= 1),
    updated_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TABLE orchestration_task_leases (
    lease_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    task_type TEXT NOT NULL CHECK (task_type = 'validation'),
    agent_id TEXT NOT NULL,
    capability_manifest_id TEXT NOT NULL REFERENCES task_capability_manifests(manifest_id),
    manifest_revision INTEGER NOT NULL CHECK (manifest_revision = 1),
    budget_reservation_id TEXT NOT NULL REFERENCES orchestration_task_budget_reservations(reservation_id),
    budget_account_version INTEGER NOT NULL CHECK (budget_account_version >= 2),
    approval_consumption_id TEXT REFERENCES orchestration_task_approval_consumptions(consumption_id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    worker_id TEXT NOT NULL REFERENCES worker_runtime_instances(worker_id),
    worker_version INTEGER NOT NULL CHECK (worker_version >= 1),
    token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
    recovery_generation INTEGER NOT NULL CHECK (recovery_generation >= 1),
    lease_generation INTEGER NOT NULL CHECK (lease_generation >= 1),
    fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
    lease_version INTEGER NOT NULL CHECK (lease_version >= 1),
    state TEXT NOT NULL CHECK (state IN ('active', 'released', 'expired', 'invalidated')),
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    maximum_expires_at TEXT NOT NULL,
    released_at TEXT,
    release_reason TEXT NOT NULL CHECK (release_reason IN (
        'none', 'released', 'expired', 'cancelled', 'recovery',
        'worker_ineligible', 'security_state'
    )),
    purpose TEXT NOT NULL CHECK (purpose = 'coordinate_validation_task'),
    state_json TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, lease_generation),
    UNIQUE(task_id, fencing_token),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE UNIQUE INDEX orchestration_task_one_active_lease
ON orchestration_task_leases(task_id, task_revision) WHERE state = 'active';

CREATE TABLE orchestration_task_lease_events (
    event_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    lease_id TEXT NOT NULL REFERENCES orchestration_task_leases(lease_id),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'acquired', 'renewed', 'released', 'expired', 'invalidated'
    )),
    event_json TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
    occurred_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER orchestration_task_lease_fence_identity_immutable
BEFORE UPDATE OF task_id, authority, execution_enabled ON orchestration_task_lease_fences
BEGIN SELECT RAISE(ABORT, 'orchestration task lease fence identity is immutable'); END;
CREATE TRIGGER orchestration_task_lease_fence_versioned
BEFORE UPDATE ON orchestration_task_lease_fences
WHEN NEW.version != OLD.version + 1
  OR NEW.current_lease_generation < OLD.current_lease_generation
  OR NEW.recovery_generation < OLD.recovery_generation
BEGIN SELECT RAISE(ABORT, 'orchestration task lease fence is stale'); END;
CREATE TRIGGER orchestration_task_lease_fences_no_delete
BEFORE DELETE ON orchestration_task_lease_fences
BEGIN SELECT RAISE(ABORT, 'orchestration task lease fences cannot be deleted'); END;

CREATE TRIGGER orchestration_task_lease_identity_immutable
BEFORE UPDATE OF lease_id, request_id, request_digest, assessment_id, plan_id,
    plan_revision, task_id, task_revision, task_type, agent_id,
    capability_manifest_id, manifest_revision, budget_reservation_id,
    budget_account_version, approval_consumption_id, policy_bundle_id, policy_hash,
    worker_id, worker_version, token_hash, recovery_generation, lease_generation,
    fencing_token, acquired_at, maximum_expires_at, purpose, authority,
    execution_enabled
ON orchestration_task_leases
BEGIN SELECT RAISE(ABORT, 'orchestration task lease identity is immutable'); END;
CREATE TRIGGER orchestration_task_lease_versioned
BEFORE UPDATE ON orchestration_task_leases
WHEN NEW.lease_version != OLD.lease_version + 1 OR NOT (
    (OLD.state = 'active' AND NEW.state IN ('active', 'released', 'expired', 'invalidated'))
)
BEGIN SELECT RAISE(ABORT, 'orchestration task lease transition is invalid'); END;
CREATE TRIGGER orchestration_task_leases_no_delete
BEFORE DELETE ON orchestration_task_leases
BEGIN SELECT RAISE(ABORT, 'orchestration task leases cannot be deleted'); END;

CREATE TRIGGER orchestration_task_lease_events_immutable
BEFORE UPDATE ON orchestration_task_lease_events
BEGIN SELECT RAISE(ABORT, 'orchestration task lease events are immutable'); END;
CREATE TRIGGER orchestration_task_lease_events_no_delete
BEFORE DELETE ON orchestration_task_lease_events
BEGIN SELECT RAISE(ABORT, 'orchestration task lease events cannot be deleted'); END;
