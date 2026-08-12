CREATE TABLE assessment_coverage (
    coverage_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    idempotency_key TEXT NOT NULL,
    asset_rule_id TEXT NOT NULL,
    capability_rule_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('tested_no_findings', 'finding_identified', 'blocked', 'not_tested')
    ),
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    limitations_json TEXT NOT NULL,
    notes TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    UNIQUE(workflow_id, idempotency_key),
    CHECK (ended_at >= started_at),
    CHECK (outcome IN ('blocked', 'not_tested') OR evidence_ids_json != '[]')
);

CREATE INDEX assessment_coverage_by_workflow
ON assessment_coverage(workflow_id, asset_rule_id, capability, started_at, coverage_id);

CREATE TRIGGER assessment_coverage_immutable BEFORE UPDATE ON assessment_coverage
BEGIN SELECT RAISE(ABORT, 'assessment coverage is immutable'); END;

CREATE TRIGGER assessment_coverage_no_delete BEFORE DELETE ON assessment_coverage
BEGIN SELECT RAISE(ABORT, 'assessment coverage cannot be deleted'); END;
