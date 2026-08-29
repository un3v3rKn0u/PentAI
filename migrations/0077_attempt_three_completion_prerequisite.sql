CREATE TABLE orchestration_task_completions_v3 (
    completion_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL UNIQUE CHECK(length(command_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    expected_plan_revision INTEGER NOT NULL CHECK(expected_plan_revision > 0),
    resulting_plan_revision INTEGER NOT NULL CHECK(resulting_plan_revision=expected_plan_revision+1),
    task_id TEXT NOT NULL,
    expected_task_revision INTEGER NOT NULL CHECK(expected_task_revision > 0),
    resulting_task_revision INTEGER NOT NULL CHECK(resulting_task_revision=expected_task_revision+1),
    retry_attempt_id TEXT NOT NULL UNIQUE,
    lease_consumption_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_lease_consumptions_v3(consumption_id),
    checkpoint_id TEXT REFERENCES orchestration_task_checkpoints_v3(checkpoint_id),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK(length(receipt_hash)=64),
    recorded_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(task_id, expected_task_revision),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER orchestration_task_completions_v3_binding_valid
BEFORE INSERT ON orchestration_task_completions_v3
WHEN json_extract(NEW.receipt_json,'$.schema_version') IS NOT '3.0.0'
 OR json_extract(NEW.receipt_json,'$.completion_id') IS NOT NEW.completion_id
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.receipt_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.receipt_json,'$.expected_plan_revision') IS NOT NEW.expected_plan_revision
 OR json_extract(NEW.receipt_json,'$.resulting_plan_revision') IS NOT NEW.resulting_plan_revision
 OR json_extract(NEW.receipt_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.receipt_json,'$.expected_task_revision') IS NOT NEW.expected_task_revision
 OR json_extract(NEW.receipt_json,'$.resulting_task_revision') IS NOT NEW.resulting_task_revision
 OR json_extract(NEW.receipt_json,'$.retry_attempt_id') IS NOT NEW.retry_attempt_id
 OR json_extract(NEW.receipt_json,'$.lease_consumption_id') IS NOT NEW.lease_consumption_id
 OR json_extract(NEW.receipt_json,'$.checkpoint_id') IS NOT NEW.checkpoint_id
 OR json_extract(NEW.receipt_json,'$.attempt_number') IS NOT 3
 OR json_extract(NEW.receipt_json,'$.resulting_task_state') IS NOT 'succeeded'
 OR json_extract(NEW.receipt_json,'$.purpose') IS NOT 'consume_attempt_three_validation_task_completion'
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'attempt-three completion binding is invalid'); END;

CREATE TRIGGER orchestration_task_completions_v3_producer_disabled
BEFORE INSERT ON orchestration_task_completions_v3
BEGIN SELECT RAISE(ABORT,'attempt-three completion producer is disabled'); END;

CREATE TRIGGER orchestration_task_completions_v3_immutable
BEFORE UPDATE ON orchestration_task_completions_v3
BEGIN SELECT RAISE(ABORT,'attempt-three completions are immutable'); END;

CREATE TRIGGER orchestration_task_completions_v3_no_delete
BEFORE DELETE ON orchestration_task_completions_v3
BEGIN SELECT RAISE(ABORT,'attempt-three completions cannot be deleted'); END;
