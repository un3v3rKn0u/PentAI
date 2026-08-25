CREATE TABLE orchestration_retry_policies_v2 (
    retry_policy_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
    revision INTEGER NOT NULL CHECK (revision = 1),
    policy_json TEXT NOT NULL,
    policy_digest TEXT NOT NULL UNIQUE CHECK (length(policy_digest) = 71),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (authority = 'none'),
    execution_enabled INTEGER NOT NULL CHECK (execution_enabled = 0),
    UNIQUE(assessment_id, policy_bundle_id, policy_hash, revision)
);

CREATE TRIGGER orchestration_retry_policies_v2_binding_valid
BEFORE INSERT ON orchestration_retry_policies_v2
WHEN json_extract(NEW.policy_json, '$.schema_version') IS NOT '2.0.0'
  OR json_extract(NEW.policy_json, '$.retry_policy_id') IS NOT NEW.retry_policy_id
  OR json_extract(NEW.policy_json, '$.assessment_id') IS NOT NEW.assessment_id
  OR json_extract(NEW.policy_json, '$.policy_bundle_id') IS NOT NEW.policy_bundle_id
  OR json_extract(NEW.policy_json, '$.policy_hash') IS NOT NEW.policy_hash
  OR json_extract(NEW.policy_json, '$.revision') IS NOT NEW.revision
  OR json_extract(NEW.policy_json, '$.failure_contract_version') IS NOT '2.0.0'
  OR json_extract(NEW.policy_json, '$.attempt_contract_version') IS NOT '2.0.0'
  OR json_extract(NEW.policy_json, '$.maximum_attempts') IS NOT 3
  OR json_extract(NEW.policy_json, '$.policy_digest') IS NOT NEW.policy_digest
  OR json_extract(NEW.policy_json, '$.issued_at') IS NOT NEW.issued_at
  OR json_extract(NEW.policy_json, '$.expires_at') IS NOT NEW.expires_at
  OR json_extract(NEW.policy_json, '$.authority') IS NOT 'none'
  OR json_extract(NEW.policy_json, '$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT, 'retry policy v2 binding is invalid'); END;

CREATE TRIGGER orchestration_retry_policies_v2_immutable
BEFORE UPDATE ON orchestration_retry_policies_v2
BEGIN SELECT RAISE(ABORT, 'retry policy v2 is immutable'); END;

CREATE TRIGGER orchestration_retry_policies_v2_no_delete
BEFORE DELETE ON orchestration_retry_policies_v2
BEGIN SELECT RAISE(ABORT, 'retry policies v2 cannot be deleted'); END;
