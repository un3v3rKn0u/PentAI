CREATE TABLE orchestration_terminal_consumptions (
    consumption_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL CHECK(length(command_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL,
    task_id TEXT NOT NULL UNIQUE,
    expected_task_revision INTEGER NOT NULL,
    resulting_task_revision INTEGER NOT NULL,
    terminal_decision_id TEXT NOT NULL UNIQUE
      REFERENCES orchestration_terminal_dispositions(decision_id),
    terminal_decision_digest TEXT NOT NULL UNIQUE CHECK(length(terminal_decision_digest)=71),
    receipt_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK(length(receipt_hash)=64),
    consumed_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(task_id,expected_task_revision),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER orchestration_terminal_consumptions_binding_valid
BEFORE INSERT ON orchestration_terminal_consumptions
WHEN NEW.resulting_task_revision != NEW.expected_task_revision+1
 OR json_extract(NEW.receipt_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.receipt_json,'$.consumption_id') IS NOT NEW.consumption_id
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.receipt_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.receipt_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.receipt_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.receipt_json,'$.expected_task_revision') IS NOT NEW.expected_task_revision
 OR json_extract(NEW.receipt_json,'$.resulting_task_revision') IS NOT NEW.resulting_task_revision
 OR json_extract(NEW.receipt_json,'$.resulting_task_state') IS NOT 'dead_letter'
 OR json_extract(NEW.receipt_json,'$.terminal_decision_id') IS NOT NEW.terminal_decision_id
 OR json_extract(NEW.receipt_json,'$.terminal_decision_digest') IS NOT NEW.terminal_decision_digest
 OR json_extract(NEW.receipt_json,'$.outcome') IS NOT 'dead_letter_eligible'
 OR json_extract(NEW.receipt_json,'$.reason_code') IS NOT 'retry_ceiling_exhausted'
 OR json_extract(NEW.receipt_json,'$.queue_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.operator_review_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
 OR NOT EXISTS (
   SELECT 1 FROM orchestration_terminal_dispositions d
   JOIN orchestration_tasks t ON t.plan_id=d.plan_id AND t.task_id=d.task_id
   WHERE d.decision_id=NEW.terminal_decision_id
    AND NEW.terminal_decision_digest='sha256:'||d.decision_hash
    AND d.assessment_id=NEW.assessment_id AND d.plan_id=NEW.plan_id
    AND d.plan_revision=NEW.plan_revision AND d.task_id=NEW.task_id
    AND d.task_revision=NEW.expected_task_revision
    AND d.outcome='dead_letter_eligible' AND d.reason_code='retry_ceiling_exhausted'
    AND json_extract(d.decision_json,'$.dead_letter_transition_enabled')=0
    AND json_extract(d.decision_json,'$.queue_enabled')=0
    AND json_extract(d.decision_json,'$.operator_review_enabled')=0
    AND t.state='failed' AND t.revision=NEW.expected_task_revision)
BEGIN SELECT RAISE(ABORT,'terminal consumption binding is invalid'); END;

CREATE TRIGGER orchestration_terminal_consumptions_producer_disabled
BEFORE INSERT ON orchestration_terminal_consumptions
BEGIN SELECT RAISE(ABORT,'terminal consumption producer is disabled'); END;

CREATE TRIGGER orchestration_terminal_consumptions_immutable
BEFORE UPDATE ON orchestration_terminal_consumptions
BEGIN SELECT RAISE(ABORT,'terminal consumptions are immutable'); END;
CREATE TRIGGER orchestration_terminal_consumptions_no_delete
BEFORE DELETE ON orchestration_terminal_consumptions
BEGIN SELECT RAISE(ABORT,'terminal consumptions cannot be deleted'); END;
