CREATE TABLE report_drafts (
    report_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES assessment_workflows(workflow_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    policy_bundle_id TEXT NOT NULL REFERENCES policy_bundles(id),
    idempotency_key TEXT NOT NULL,
    template TEXT NOT NULL CHECK (template IN ('generic', 'hackerone', 'bugcrowd', 'intigriti')),
    title TEXT NOT NULL,
    finding_refs_json TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(workflow_id, idempotency_key)
);

CREATE INDEX report_drafts_by_workflow
ON report_drafts(workflow_id, created_at, report_id);

CREATE TABLE report_draft_artifacts (
    report_id TEXT NOT NULL REFERENCES report_drafts(report_id),
    format TEXT NOT NULL CHECK (format IN ('markdown', 'html', 'json', 'pdf')),
    media_type TEXT NOT NULL,
    content BLOB NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 1 AND size_bytes <= 2097152),
    PRIMARY KEY(report_id, format)
);

CREATE TRIGGER report_drafts_immutable BEFORE UPDATE ON report_drafts
BEGIN SELECT RAISE(ABORT, 'report drafts are immutable'); END;
CREATE TRIGGER report_drafts_no_delete BEFORE DELETE ON report_drafts
BEGIN SELECT RAISE(ABORT, 'report drafts cannot be deleted'); END;
CREATE TRIGGER report_artifacts_immutable BEFORE UPDATE ON report_draft_artifacts
BEGIN SELECT RAISE(ABORT, 'report artifacts are immutable'); END;
CREATE TRIGGER report_artifacts_no_delete BEFORE DELETE ON report_draft_artifacts
BEGIN SELECT RAISE(ABORT, 'report artifacts cannot be deleted'); END;
