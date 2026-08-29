CREATE TABLE orchestration_provider_usage_measurements_v1 (
    measurement_id TEXT PRIMARY KEY,
    completion_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_completions_v3(completion_id),
    completion_digest TEXT NOT NULL CHECK(length(completion_digest)=71),
    assessment_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_revision INTEGER NOT NULL CHECK(plan_revision > 0),
    task_id TEXT NOT NULL,
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    retry_attempt_id TEXT NOT NULL UNIQUE,
    budget_reservation_id TEXT NOT NULL UNIQUE REFERENCES orchestration_task_budget_reservations_v4(reservation_id),
    budget_account_id TEXT NOT NULL REFERENCES orchestration_budget_accounts(account_id),
    budget_account_version INTEGER NOT NULL CHECK(budget_account_version > 0),
    measurement_json TEXT NOT NULL,
    measurement_digest TEXT NOT NULL UNIQUE CHECK(length(measurement_digest)=71),
    recorded_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(task_id, task_revision),
    FOREIGN KEY(plan_id,assessment_id) REFERENCES orchestration_plans(plan_id,assessment_id),
    FOREIGN KEY(plan_id,task_id) REFERENCES orchestration_tasks(plan_id,task_id)
);

CREATE TRIGGER orchestration_provider_usage_measurements_v1_binding_valid
BEFORE INSERT ON orchestration_provider_usage_measurements_v1
WHEN json_extract(NEW.measurement_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.measurement_json,'$.measurement_id') IS NOT NEW.measurement_id
 OR json_extract(NEW.measurement_json,'$.completion_id') IS NOT NEW.completion_id
 OR json_extract(NEW.measurement_json,'$.completion_digest') IS NOT NEW.completion_digest
 OR json_extract(NEW.measurement_json,'$.assessment_id') IS NOT NEW.assessment_id
 OR json_extract(NEW.measurement_json,'$.plan_id') IS NOT NEW.plan_id
 OR json_extract(NEW.measurement_json,'$.plan_revision') IS NOT NEW.plan_revision
 OR json_extract(NEW.measurement_json,'$.task_id') IS NOT NEW.task_id
 OR json_extract(NEW.measurement_json,'$.task_revision') IS NOT NEW.task_revision
 OR json_extract(NEW.measurement_json,'$.retry_attempt_id') IS NOT NEW.retry_attempt_id
 OR json_extract(NEW.measurement_json,'$.attempt_number') IS NOT 3
 OR json_extract(NEW.measurement_json,'$.budget_reservation_id') IS NOT NEW.budget_reservation_id
 OR json_extract(NEW.measurement_json,'$.budget_account_id') IS NOT NEW.budget_account_id
 OR json_extract(NEW.measurement_json,'$.budget_account_version') IS NOT NEW.budget_account_version
 OR json_extract(NEW.measurement_json,'$.measurement_source') IS NOT 'trusted_runtime_meter'
 OR json_extract(NEW.measurement_json,'$.purpose') IS NOT 'record_attempt_three_provider_usage'
 OR json_extract(NEW.measurement_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.measurement_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'attempt-three provider usage binding is invalid'); END;

CREATE TRIGGER orchestration_provider_usage_measurements_v1_producer_disabled
BEFORE INSERT ON orchestration_provider_usage_measurements_v1
BEGIN SELECT RAISE(ABORT,'attempt-three provider usage producer is disabled'); END;

CREATE TRIGGER orchestration_provider_usage_measurements_v1_immutable
BEFORE UPDATE ON orchestration_provider_usage_measurements_v1
BEGIN SELECT RAISE(ABORT,'attempt-three provider usage measurements are immutable'); END;

CREATE TRIGGER orchestration_provider_usage_measurements_v1_no_delete
BEFORE DELETE ON orchestration_provider_usage_measurements_v1
BEGIN SELECT RAISE(ABORT,'attempt-three provider usage measurements cannot be deleted'); END;
