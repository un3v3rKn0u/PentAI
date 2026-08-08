DROP TRIGGER immutable_active_policy_update;
DROP TRIGGER immutable_approved_manifest_update;

CREATE TRIGGER immutable_active_policy_update
BEFORE UPDATE OF
    id, engagement_id, manifest_version_id, schema_version, compiler_version,
    policy_json, content_hash, signature, signer_key_id, activated_at
ON policy_bundles
WHEN OLD.activated_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'activated policy bundles are immutable');
END;

CREATE TRIGGER immutable_approved_manifest_update
BEFORE UPDATE ON manifest_versions
WHEN EXISTS (
    SELECT 1 FROM approvals
    WHERE approvals.manifest_version_id = OLD.id
      AND approvals.decision = 'approved'
)
BEGIN
    SELECT RAISE(ABORT, 'approved manifest versions are immutable');
END;

CREATE TRIGGER immutable_approval_update
BEFORE UPDATE OF
    id, approval_type, engagement_id, manifest_version_id, manifest_hash,
    policy_bundle_id, policy_hash, decision, approver_id, decided_at,
    expires_at, document_json
ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approval records are immutable');
END;

CREATE TRIGGER immutable_approval_delete
BEFORE DELETE ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approval records are immutable');
END;
