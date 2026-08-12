CREATE TABLE report_export_approvals (
    approval_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    report_kind TEXT NOT NULL CHECK (report_kind IN ('findings', 'no_findings')),
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    report_content_hash TEXT NOT NULL CHECK (length(report_content_hash) = 64),
    artifact_digests_json TEXT NOT NULL,
    expected_status TEXT NOT NULL CHECK (expected_status = 'draft'),
    decision TEXT NOT NULL CHECK (decision = 'approved'),
    reason TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    UNIQUE(report_kind, report_id)
);

CREATE INDEX report_export_approvals_by_workflow
ON report_export_approvals(workflow_id, approved_at, approval_id);

CREATE TRIGGER report_export_approvals_immutable BEFORE UPDATE ON report_export_approvals
BEGIN SELECT RAISE(ABORT, 'report export approvals are immutable'); END;

CREATE TRIGGER report_export_approvals_no_delete BEFORE DELETE ON report_export_approvals
BEGIN SELECT RAISE(ABORT, 'report export approvals cannot be deleted'); END;
