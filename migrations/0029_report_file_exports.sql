CREATE TABLE report_file_exports (
    export_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    report_kind TEXT NOT NULL CHECK (report_kind IN ('findings', 'no_findings')),
    approval_id TEXT NOT NULL REFERENCES report_export_approvals(approval_id),
    format TEXT NOT NULL CHECK (format IN ('markdown', 'html', 'json', 'pdf')),
    artifact_sha256 TEXT NOT NULL CHECK (length(artifact_sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    filename TEXT NOT NULL,
    destination_directory_sha256 TEXT NOT NULL CHECK (length(destination_directory_sha256) = 64),
    exported_by TEXT NOT NULL,
    exported_at TEXT NOT NULL,
    document_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE CHECK (length(content_hash) = 64),
    UNIQUE(report_kind, report_id, format, destination_directory_sha256)
);

CREATE TRIGGER report_file_exports_immutable BEFORE UPDATE ON report_file_exports
BEGIN SELECT RAISE(ABORT, 'report file exports are immutable'); END;

CREATE TRIGGER report_file_exports_no_delete BEFORE DELETE ON report_file_exports
BEGIN SELECT RAISE(ABORT, 'report file exports cannot be deleted'); END;
