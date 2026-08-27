CREATE TABLE orchestration_retry_failed_attempts_v3 (
    attempt_id TEXT PRIMARY KEY REFERENCES orchestration_retry_attempts_v2(attempt_id),
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK(length(command_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    failure_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_failures_v3(failure_id),
    failure_receipt_digest TEXT NOT NULL UNIQUE CHECK(length(failure_receipt_digest)=71),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK(length(receipt_hash)=64),
    registered_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER orchestration_retry_failed_attempts_v3_binding_valid
BEFORE INSERT ON orchestration_retry_failed_attempts_v3
WHEN json_extract(NEW.receipt_json,'$.schema_version') IS NOT '3.0.0'
 OR json_extract(NEW.receipt_json,'$.attempt_id') IS NOT NEW.attempt_id
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.receipt_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.receipt_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.receipt_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.receipt_json,'$.task_revision') IS NOT NEW.task_revision
 OR json_extract(NEW.receipt_json,'$.failure_id') IS NOT NEW.failure_id
 OR json_extract(NEW.receipt_json,'$.failure_receipt_digest') IS NOT NEW.failure_receipt_digest
 OR json_extract(NEW.receipt_json,'$.attempt_number') IS NOT 3
 OR json_extract(NEW.receipt_json,'$.attempt_state') IS NOT 'failed'
 OR json_extract(NEW.receipt_json,'$.terminal_retry_ceiling') IS NOT 3
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
 OR NOT EXISTS (
   SELECT 1 FROM orchestration_retry_attempts_v2 a
   JOIN orchestration_task_failures_v3 f ON f.failure_id=NEW.failure_id
   WHERE a.attempt_id=NEW.attempt_id AND a.assessment_id=NEW.assessment_id
    AND a.plan_id=NEW.plan_id AND a.task_id=NEW.task_id AND a.attempt_number=3
    AND f.assessment_id=NEW.assessment_id AND f.plan_id=NEW.plan_id AND f.task_id=NEW.task_id
    AND f.resulting_plan_revision=NEW.plan_revision AND f.resulting_task_revision=NEW.task_revision
    AND json_extract(NEW.receipt_json,'$.retry_attempt_digest')=json_extract(a.receipt_json,'$.attempt_digest')
    AND NEW.failure_receipt_digest='sha256:'||f.receipt_hash
    AND json_extract(f.receipt_json,'$.retry_attempt_id')=NEW.attempt_id)
BEGIN SELECT RAISE(ABORT,'attempt-three failed-attempt binding is invalid'); END;

CREATE TRIGGER orchestration_retry_failed_attempts_v3_immutable BEFORE UPDATE ON orchestration_retry_failed_attempts_v3
BEGIN SELECT RAISE(ABORT,'attempt-three failed attempts are immutable'); END;
CREATE TRIGGER orchestration_retry_failed_attempts_v3_no_delete BEFORE DELETE ON orchestration_retry_failed_attempts_v3
BEGIN SELECT RAISE(ABORT,'attempt-three failed attempts cannot be deleted'); END;
