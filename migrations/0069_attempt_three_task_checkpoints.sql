CREATE TABLE orchestration_task_checkpoints_v3 (
    checkpoint_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK (length(command_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    lease_consumption_id TEXT NOT NULL REFERENCES orchestration_task_lease_consumptions_v3(consumption_id),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 10000),
    previous_checkpoint_digest TEXT CHECK (previous_checkpoint_digest IS NULL OR length(previous_checkpoint_digest)=71),
    checkpoint_digest TEXT NOT NULL UNIQUE CHECK (length(checkpoint_digest)=71),
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority='none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled=0),
    UNIQUE(task_id, task_revision, sequence),
    FOREIGN KEY(plan_id, assessment_id) REFERENCES orchestration_plans(plan_id, assessment_id),
    FOREIGN KEY(plan_id, task_id) REFERENCES orchestration_tasks(plan_id, task_id)
);

CREATE TRIGGER orchestration_task_checkpoints_v3_binding_valid
BEFORE INSERT ON orchestration_task_checkpoints_v3
WHEN json_extract(NEW.receipt_json,'$.schema_version') IS NOT '3.0.0'
 OR json_extract(NEW.receipt_json,'$.checkpoint_id') IS NOT NEW.checkpoint_id
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.receipt_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.receipt_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.receipt_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.receipt_json,'$.task_revision') IS NOT NEW.task_revision
 OR json_extract(NEW.receipt_json,'$.lease_consumption_id') IS NOT NEW.lease_consumption_id
 OR json_extract(NEW.receipt_json,'$.sequence') IS NOT NEW.sequence
 OR json_extract(NEW.receipt_json,'$.previous_checkpoint_digest') IS NOT NEW.previous_checkpoint_digest
 OR json_extract(NEW.receipt_json,'$.checkpoint_digest') IS NOT NEW.checkpoint_digest
 OR json_extract(NEW.receipt_json,'$.attempt_number') IS NOT 3
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
 OR NOT EXISTS (
   SELECT 1 FROM orchestration_task_lease_consumptions_v3 c
   WHERE c.consumption_id=NEW.lease_consumption_id
    AND c.assessment_id=NEW.assessment_id AND c.plan_id=NEW.plan_id
    AND c.resulting_plan_revision=NEW.plan_revision AND c.task_id=NEW.task_id
    AND c.resulting_task_revision=NEW.task_revision
    AND json_extract(c.receipt_json,'$.schema_version')='3.0.0'
    AND json_extract(c.receipt_json,'$.attempt_number')=3
    AND json_extract(NEW.receipt_json,'$.lease_consumption_digest')='sha256:'||c.receipt_hash
    AND json_extract(NEW.receipt_json,'$.retry_attempt_id')=json_extract(c.receipt_json,'$.retry_attempt_id')
    AND json_extract(NEW.receipt_json,'$.capability_manifest_id')=json_extract(c.receipt_json,'$.capability_manifest_id')
    AND json_extract(NEW.receipt_json,'$.budget_reservation_id')=json_extract(c.receipt_json,'$.budget_reservation_id')
 )
BEGIN SELECT RAISE(ABORT, 'attempt-three checkpoint binding is invalid'); END;

CREATE TRIGGER orchestration_task_checkpoints_v3_immutable
BEFORE UPDATE ON orchestration_task_checkpoints_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three checkpoint is immutable'); END;
CREATE TRIGGER orchestration_task_checkpoints_v3_no_delete
BEFORE DELETE ON orchestration_task_checkpoints_v3
BEGIN SELECT RAISE(ABORT, 'attempt-three checkpoint cannot be deleted'); END;
