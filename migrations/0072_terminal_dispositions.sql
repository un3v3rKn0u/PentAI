CREATE TABLE orchestration_terminal_dispositions (
    decision_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK(length(command_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL,
    failed_attempt_id TEXT NOT NULL UNIQUE
      REFERENCES orchestration_retry_failed_attempts_v3(attempt_id),
    failed_attempt_digest TEXT NOT NULL UNIQUE CHECK(length(failed_attempt_digest)=71),
    failure_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_failures_v3(failure_id),
    failure_receipt_digest TEXT NOT NULL UNIQUE CHECK(length(failure_receipt_digest)=71),
    retry_policy_id TEXT NOT NULL REFERENCES orchestration_retry_policies_v2(retry_policy_id),
    retry_policy_digest TEXT NOT NULL CHECK(length(retry_policy_digest)=71),
    outcome TEXT NOT NULL CHECK(outcome='dead_letter_eligible'),
    reason_code TEXT NOT NULL CHECK(reason_code='retry_ceiling_exhausted'),
    decision_json TEXT NOT NULL,
    decision_hash TEXT NOT NULL UNIQUE CHECK(length(decision_hash)=64),
    decided_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER orchestration_terminal_dispositions_binding_valid
BEFORE INSERT ON orchestration_terminal_dispositions
WHEN json_extract(NEW.decision_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.decision_json,'$.decision_id') IS NOT NEW.decision_id
 OR json_extract(NEW.decision_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.decision_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.decision_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.decision_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.decision_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.decision_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.decision_json,'$.task_revision') IS NOT NEW.task_revision
 OR json_extract(NEW.decision_json,'$.failed_attempt_id') IS NOT NEW.failed_attempt_id
 OR json_extract(NEW.decision_json,'$.failed_attempt_digest') IS NOT NEW.failed_attempt_digest
 OR json_extract(NEW.decision_json,'$.failure_id') IS NOT NEW.failure_id
 OR json_extract(NEW.decision_json,'$.failure_receipt_digest') IS NOT NEW.failure_receipt_digest
 OR json_extract(NEW.decision_json,'$.retry_policy_id') IS NOT NEW.retry_policy_id
 OR json_extract(NEW.decision_json,'$.retry_policy_digest') IS NOT NEW.retry_policy_digest
 OR json_extract(NEW.decision_json,'$.attempt_number') IS NOT 3
 OR json_extract(NEW.decision_json,'$.maximum_attempts') IS NOT 3
 OR json_extract(NEW.decision_json,'$.additional_attempts_permitted') IS NOT 0
 OR json_extract(NEW.decision_json,'$.outcome') IS NOT NEW.outcome
 OR json_extract(NEW.decision_json,'$.reason_code') IS NOT NEW.reason_code
 OR json_extract(NEW.decision_json,'$.dead_letter_transition_enabled') IS NOT 0
 OR json_extract(NEW.decision_json,'$.queue_enabled') IS NOT 0
 OR json_extract(NEW.decision_json,'$.operator_review_enabled') IS NOT 0
 OR json_extract(NEW.decision_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.decision_json,'$.execution_enabled') IS NOT 0
 OR NOT EXISTS (
   SELECT 1 FROM orchestration_retry_failed_attempts_v3 a
   JOIN orchestration_retry_policies_v2 p ON p.retry_policy_id=NEW.retry_policy_id
   WHERE a.attempt_id=NEW.failed_attempt_id AND a.assessment_id=NEW.assessment_id
    AND a.plan_id=NEW.plan_id AND a.plan_revision=NEW.plan_revision
    AND a.task_id=NEW.task_id AND a.task_revision=NEW.task_revision
    AND NEW.failed_attempt_digest='sha256:'||a.receipt_hash
    AND json_extract(a.receipt_json,'$.failure_id')=NEW.failure_id
    AND json_extract(a.receipt_json,'$.failure_receipt_digest')=NEW.failure_receipt_digest
    AND p.assessment_id=NEW.assessment_id
    AND p.policy_digest=NEW.retry_policy_digest
    AND json_extract(p.policy_json,'$.maximum_attempts')=3)
BEGIN SELECT RAISE(ABORT,'terminal disposition binding is invalid'); END;

CREATE TRIGGER orchestration_terminal_dispositions_immutable
BEFORE UPDATE ON orchestration_terminal_dispositions
BEGIN SELECT RAISE(ABORT,'terminal dispositions are immutable'); END;
CREATE TRIGGER orchestration_terminal_dispositions_no_delete
BEFORE DELETE ON orchestration_terminal_dispositions
BEGIN SELECT RAISE(ABORT,'terminal dispositions cannot be deleted'); END;
