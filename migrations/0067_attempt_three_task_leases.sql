CREATE TABLE orchestration_task_leases_v3 (
    lease_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71),
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    capability_manifest_id TEXT NOT NULL UNIQUE REFERENCES task_capability_manifests_v4(manifest_id),
    budget_reservation_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_budget_reservations_v4(reservation_id),
    retry_activation_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_activations_v2(activation_id),
    retry_attempt_id TEXT NOT NULL UNIQUE REFERENCES orchestration_retry_attempts_v2(attempt_id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    worker_id TEXT NOT NULL REFERENCES worker_runtime_instances(worker_id),
    worker_version INTEGER NOT NULL,
    token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
    recovery_generation INTEGER NOT NULL,
    lease_generation INTEGER NOT NULL,
    fencing_token INTEGER NOT NULL,
    lease_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'expired', 'invalidated')),
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    maximum_expires_at TEXT NOT NULL,
    released_at TEXT,
    release_reason TEXT NOT NULL CHECK (release_reason IN ('none', 'expired', 'recovery')),
    purpose TEXT NOT NULL CHECK (purpose = 'coordinate_attempt_three_validation_task'),
    state_json TEXT NOT NULL,
    state_hash TEXT NOT NULL CHECK (length(state_hash) = 64),
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(task_id, lease_generation),
    UNIQUE(task_id, fencing_token),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE UNIQUE INDEX orchestration_task_leases_v3_one_active
ON orchestration_task_leases_v3(task_id, task_revision) WHERE state='active';

CREATE TABLE orchestration_task_lease_events_v3 (
    event_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest) = 71),
    lease_id TEXT NOT NULL REFERENCES orchestration_task_leases_v3(lease_id),
    event_type TEXT NOT NULL CHECK (event_type IN ('acquired', 'expired', 'invalidated')),
    event_json TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
    occurred_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0)
);

CREATE TRIGGER orchestration_task_leases_v3_binding_valid
BEFORE INSERT ON orchestration_task_leases_v3
WHEN json_extract(NEW.state_json, '$.schema_version') IS NOT '3.0.0'
  OR json_extract(NEW.state_json, '$.lease_id') IS NOT NEW.lease_id
  OR json_extract(NEW.state_json, '$.request_id') IS NOT NEW.request_id
  OR json_extract(NEW.state_json, '$.request_digest') IS NOT NEW.request_digest
  OR json_extract(NEW.state_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.state_json, '$.plan_id') IS NOT NEW.plan_id
  OR json_extract(NEW.state_json, '$.plan_revision') IS NOT NEW.plan_revision
  OR json_extract(NEW.state_json, '$.task_id') IS NOT NEW.task_id
  OR json_extract(NEW.state_json, '$.task_revision') IS NOT NEW.task_revision
  OR json_extract(NEW.state_json, '$.agent_id') IS NOT NEW.agent_id
  OR json_extract(NEW.state_json, '$.capability_manifest_id') IS NOT NEW.capability_manifest_id
  OR json_extract(NEW.state_json, '$.budget_reservation_id') IS NOT NEW.budget_reservation_id
  OR json_extract(NEW.state_json, '$.retry_activation_id') IS NOT NEW.retry_activation_id
  OR json_extract(NEW.state_json, '$.retry_attempt_id') IS NOT NEW.retry_attempt_id
  OR json_extract(NEW.state_json, '$.attempt_number') IS NOT 3
  OR json_extract(NEW.state_json, '$.worker_id') IS NOT NEW.worker_id
  OR json_extract(NEW.state_json, '$.worker_version') IS NOT NEW.worker_version
  OR json_extract(NEW.state_json, '$.recovery_generation') IS NOT NEW.recovery_generation
  OR json_extract(NEW.state_json, '$.lease_generation') IS NOT NEW.lease_generation
  OR json_extract(NEW.state_json, '$.fencing_token') IS NOT NEW.fencing_token
  OR json_extract(NEW.state_json, '$.lease_version') IS NOT 1
  OR json_extract(NEW.state_json, '$.state') IS NOT 'active'
  OR json_extract(NEW.state_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.state_json, '$.execution_enabled') IS NOT 0
  OR NOT EXISTS (
      SELECT 1 FROM task_capability_manifests_v4 m
      JOIN orchestration_task_budget_reservations_v4 b
        ON b.capability_manifest_id=m.manifest_id
      JOIN orchestration_retry_activations_v2 a ON a.activation_id=m.retry_activation_id
      JOIN worker_runtime_instances w ON w.worker_id=NEW.worker_id
      JOIN orchestration_task_lease_fences f ON f.task_id=NEW.task_id
      JOIN orchestration_plans p ON p.plan_id=NEW.plan_id
      JOIN orchestration_tasks t ON t.plan_id=NEW.plan_id AND t.task_id=NEW.task_id
      WHERE m.manifest_id=NEW.capability_manifest_id
        AND b.reservation_id=NEW.budget_reservation_id
        AND a.activation_id=NEW.retry_activation_id
        AND m.retry_attempt_id=NEW.retry_attempt_id
        AND m.assessment_id=NEW.assessment_id
        AND m.plan_id=NEW.plan_id AND m.plan_revision=NEW.plan_revision
        AND m.task_id=NEW.task_id AND m.task_revision=NEW.task_revision
        AND m.agent_id=NEW.agent_id
        AND m.policy_bundle_id=NEW.policy_bundle_id AND m.policy_hash=NEW.policy_hash
        AND b.state='reserved' AND json_extract(b.receipt_json, '$.attempt_number')=3
        AND json_extract(NEW.state_json, '$.capability_manifest_digest')
            = 'sha256:' || m.manifest_hash
        AND json_extract(NEW.state_json, '$.budget_request_digest')=b.request_digest
        AND json_extract(NEW.state_json, '$.budget_account_version')=b.account_version
        AND json_extract(NEW.state_json, '$.retry_policy_id')
            = json_extract(m.manifest_json, '$.retry_policy_id')
        AND json_extract(NEW.state_json, '$.retry_policy_digest')
            = json_extract(m.manifest_json, '$.retry_policy_digest')
        AND json_extract(NEW.state_json, '$.retry_activation_digest')
            = json_extract(m.manifest_json, '$.retry_activation_digest')
        AND json_extract(NEW.state_json, '$.retry_schedule_id')
            = json_extract(m.manifest_json, '$.retry_schedule_id')
        AND json_extract(NEW.state_json, '$.retry_schedule_digest')
            = json_extract(m.manifest_json, '$.retry_schedule_digest')
        AND json_extract(NEW.state_json, '$.retry_attempt_digest')
            = json_extract(m.manifest_json, '$.retry_attempt_digest')
        AND json_extract(NEW.state_json, '$.prior_retry_budget_consumption_id')
            = json_extract(m.manifest_json, '$.prior_retry_budget_consumption_id')
        AND json_extract(NEW.state_json, '$.retry_budget_consumption_id')
            = json_extract(m.manifest_json, '$.retry_budget_consumption_id')
        AND json_extract(NEW.state_json, '$.approval_consumption_id')
            IS json_extract(m.manifest_json, '$.approval_consumption_id')
        AND json_extract(NEW.state_json, '$.policy_bundle_id')=NEW.policy_bundle_id
        AND json_extract(NEW.state_json, '$.policy_hash')=NEW.policy_hash
        AND json_extract(NEW.state_json, '$.purpose')
            = 'coordinate_attempt_three_validation_task'
        AND w.status='running' AND w.version=NEW.worker_version
        AND w.execution_enabled=0 AND w.container_id IS NOT NULL
        AND f.current_lease_generation=NEW.lease_generation
        AND f.recovery_generation=NEW.recovery_generation
        AND p.state='active' AND p.revision=NEW.plan_revision
        AND t.state='ready' AND t.revision=NEW.task_revision
  )
BEGIN SELECT RAISE(ABORT, 'attempt-three task lease binding is invalid'); END;

CREATE TRIGGER orchestration_task_leases_v3_identity_immutable
BEFORE UPDATE OF lease_id, request_id, request_digest, assessment_id, plan_id,
    plan_revision, task_id, task_revision, agent_id, capability_manifest_id,
    budget_reservation_id, retry_activation_id, retry_attempt_id, policy_bundle_id,
    policy_hash, worker_id, worker_version, token_hash, recovery_generation,
    lease_generation, fencing_token, acquired_at, maximum_expires_at, purpose,
    authority, execution_enabled
ON orchestration_task_leases_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three task lease identity is immutable'); END;

CREATE TRIGGER orchestration_task_leases_v3_versioned
BEFORE UPDATE ON orchestration_task_leases_v3
WHEN NEW.lease_version != OLD.lease_version + 1
  OR OLD.state != 'active' OR NEW.state NOT IN ('expired', 'invalidated')
BEGIN SELECT RAISE(ABORT, 'attempt-three task lease transition is invalid'); END;

CREATE TRIGGER orchestration_task_leases_v3_no_delete
BEFORE DELETE ON orchestration_task_leases_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three task leases cannot be deleted'); END;
CREATE TRIGGER orchestration_task_lease_events_v3_immutable
BEFORE UPDATE ON orchestration_task_lease_events_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three task lease events are immutable'); END;
CREATE TRIGGER orchestration_task_lease_events_v3_no_delete
BEFORE DELETE ON orchestration_task_lease_events_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three task lease events cannot be deleted'); END;
