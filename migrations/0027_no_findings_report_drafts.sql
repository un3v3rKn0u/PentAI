CREATE TABLE no_findings_report_drafts (
    report_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    idempotency_key TEXT NOT NULL,
    template TEXT NOT NULL CHECK (template IN ('generic', 'hackerone', 'bugcrowd', 'intigriti')),
    title TEXT NOT NULL,
    coverage_refs_json TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(workflow_id, idempotency_key)
);

CREATE INDEX no_findings_reports_by_workflow
ON no_findings_report_drafts(workflow_id, created_at, report_id);

CREATE TABLE no_findings_report_artifacts (
    report_id TEXT NOT NULL REFERENCES no_findings_report_drafts(report_id),
    format TEXT NOT NULL CHECK (format IN ('markdown', 'html', 'json', 'pdf')),
    media_type TEXT NOT NULL,
    content BLOB NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 2097152),
    PRIMARY KEY(report_id, format)
);

CREATE TRIGGER no_findings_reports_immutable BEFORE UPDATE ON no_findings_report_drafts
BEGIN SELECT RAISE(ABORT, 'no findings report drafts are immutable'); END;
CREATE TRIGGER no_findings_reports_no_delete BEFORE DELETE ON no_findings_report_drafts
BEGIN SELECT RAISE(ABORT, 'no findings report drafts cannot be deleted'); END;
CREATE TRIGGER no_findings_artifacts_immutable BEFORE UPDATE ON no_findings_report_artifacts
BEGIN SELECT RAISE(ABORT, 'no findings report artifacts are immutable'); END;
CREATE TRIGGER no_findings_artifacts_no_delete BEFORE DELETE ON no_findings_report_artifacts
BEGIN SELECT RAISE(ABORT, 'no findings report artifacts cannot be deleted'); END;
