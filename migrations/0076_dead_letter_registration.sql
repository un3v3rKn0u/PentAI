CREATE TABLE orchestration_dead_letter_registrations (
    registration_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK(length(command_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL UNIQUE,
    task_revision INTEGER NOT NULL,
    terminal_consumption_id TEXT NOT NULL UNIQUE
      REFERENCES orchestration_terminal_consumptions(consumption_id),
    terminal_consumption_digest TEXT NOT NULL UNIQUE CHECK(length(terminal_consumption_digest)=71),
    terminal_decision_id TEXT NOT NULL UNIQUE
      REFERENCES orchestration_terminal_dispositions(decision_id),
    terminal_decision_digest TEXT NOT NULL UNIQUE CHECK(length(terminal_decision_digest)=71),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK(length(receipt_hash)=64),
    registered_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(task_id,task_revision),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER orchestration_dead_letter_registrations_binding_valid
BEFORE INSERT ON orchestration_dead_letter_registrations
WHEN json_extract(NEW.receipt_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.receipt_json,'$.registration_id') IS NOT NEW.registration_id
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.receipt_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.receipt_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.receipt_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.receipt_json,'$.task_revision') IS NOT NEW.task_revision
 OR json_extract(NEW.receipt_json,'$.task_state') IS NOT 'dead_letter'
 OR json_extract(NEW.receipt_json,'$.terminal_consumption_id') IS NOT NEW.terminal_consumption_id
 OR json_extract(NEW.receipt_json,'$.terminal_consumption_digest') IS NOT NEW.terminal_consumption_digest
 OR json_extract(NEW.receipt_json,'$.terminal_decision_id') IS NOT NEW.terminal_decision_id
 OR json_extract(NEW.receipt_json,'$.terminal_decision_digest') IS NOT NEW.terminal_decision_digest
 OR json_extract(NEW.receipt_json,'$.attempt_number') IS NOT 3
 OR json_extract(NEW.receipt_json,'$.maximum_attempts') IS NOT 3
 OR json_extract(NEW.receipt_json,'$.outcome') IS NOT 'dead_letter_registered'
 OR json_extract(NEW.receipt_json,'$.reason_code') IS NOT 'retry_ceiling_exhausted'
 OR json_extract(NEW.receipt_json,'$.registration_state') IS NOT 'registered'
 OR json_extract(NEW.receipt_json,'$.retention_mode') IS NOT 'immutable_history'
 OR json_extract(NEW.receipt_json,'$.delivery_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.claim_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.acknowledgement_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.retry_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.deletion_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.cleanup_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.operator_review_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.purpose') IS NOT 'register_attempt_three_dead_letter'
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
 OR NOT EXISTS (
   SELECT 1 FROM orchestration_terminal_consumptions c
   JOIN orchestration_terminal_dispositions d ON d.decision_id=c.terminal_decision_id
   JOIN orchestration_tasks t ON t.plan_id=c.plan_id AND t.task_id=c.task_id
   WHERE c.consumption_id=NEW.terminal_consumption_id
    AND NEW.terminal_consumption_digest='sha256:'||c.receipt_hash
    AND c.assessment_id=NEW.assessment_id AND c.plan_id=NEW.plan_id
    AND c.plan_revision=NEW.plan_revision AND c.task_id=NEW.task_id
    AND c.resulting_task_revision=NEW.task_revision
    AND c.terminal_decision_id=NEW.terminal_decision_id
    AND c.terminal_decision_digest=NEW.terminal_decision_digest
    AND json_extract(c.receipt_json,'$.resulting_task_state')='dead_letter'
    AND json_extract(c.receipt_json,'$.queue_enabled')=0
    AND json_extract(c.receipt_json,'$.operator_review_enabled')=0
    AND d.outcome='dead_letter_eligible' AND d.reason_code='retry_ceiling_exhausted'
    AND json_extract(d.decision_json,'$.attempt_number')=3
    AND json_extract(d.decision_json,'$.maximum_attempts')=3
    AND json_extract(d.decision_json,'$.additional_attempts_permitted')=0
    AND json_extract(d.decision_json,'$.queue_enabled')=0
    AND json_extract(d.decision_json,'$.operator_review_enabled')=0
    AND t.state='dead_letter' AND t.revision=NEW.task_revision)
BEGIN SELECT RAISE(ABORT,'dead-letter registration binding is invalid'); END;

CREATE TRIGGER orchestration_dead_letter_registrations_immutable
BEFORE UPDATE ON orchestration_dead_letter_registrations
BEGIN SELECT RAISE(ABORT,'dead-letter registrations are immutable'); END;
CREATE TRIGGER orchestration_dead_letter_registrations_no_delete
BEFORE DELETE ON orchestration_dead_letter_registrations
BEGIN SELECT RAISE(ABORT,'dead-letter registrations cannot be deleted'); END;
