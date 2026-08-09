ALTER TABLE manifest_versions ADD COLUMN version_number INTEGER NOT NULL DEFAULT 1;
ALTER TABLE manifest_versions ADD COLUMN validation_status TEXT NOT NULL DEFAULT 'legacy_unverified'
    CHECK (validation_status IN ('valid', 'invalid', 'legacy_unverified'));
ALTER TABLE manifest_versions ADD COLUMN validation_issues_json TEXT NOT NULL DEFAULT '[]';

UPDATE manifest_versions
SET version_number = (
    SELECT COUNT(*) FROM manifest_versions AS earlier
    WHERE earlier.engagement_id = manifest_versions.engagement_id
      AND (earlier.created_at < manifest_versions.created_at
           OR (earlier.created_at = manifest_versions.created_at
               AND earlier.rowid <= manifest_versions.rowid))
);

CREATE UNIQUE INDEX manifest_version_sequence
ON manifest_versions(engagement_id, version_number);

CREATE TRIGGER immutable_manifest_version_update
BEFORE UPDATE ON manifest_versions
BEGIN
    SELECT RAISE(ABORT, 'manifest versions are immutable');
END;

CREATE TRIGGER immutable_manifest_version_delete
BEFORE DELETE ON manifest_versions
BEGIN
    SELECT RAISE(ABORT, 'manifest versions are immutable');
END;
