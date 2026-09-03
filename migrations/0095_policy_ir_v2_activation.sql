DROP TRIGGER policy_ir_v2_immutable;

CREATE TRIGGER policy_ir_v2_lifecycle_guard
BEFORE UPDATE ON policy_bundles
WHEN (
    OLD.schema_version = '2.0.0'
    OR (
        json_valid(OLD.policy_json) = 1
        AND json_extract(OLD.policy_json, '$.schema_version') = '2.0.0'
    )
)
AND (
    NEW.id IS NOT OLD.id
    OR NEW.engagement_id IS NOT OLD.engagement_id
    OR NEW.manifest_version_id IS NOT OLD.manifest_version_id
    OR NEW.schema_version IS NOT OLD.schema_version
    OR NEW.compiler_version IS NOT OLD.compiler_version
    OR NEW.policy_json IS NOT OLD.policy_json
    OR NEW.content_hash IS NOT OLD.content_hash
    OR NEW.signature IS NOT OLD.signature
    OR NEW.signer_key_id IS NOT OLD.signer_key_id
    OR NOT (
        (
            OLD.activated_at IS NULL
            AND OLD.revoked_at IS NULL
            AND NEW.activated_at IS NOT NULL
            AND NEW.revoked_at IS NULL
            AND EXISTS (
                SELECT 1 FROM approvals a
                WHERE a.policy_bundle_id = OLD.id
                  AND a.engagement_id = OLD.engagement_id
                  AND a.manifest_version_id = OLD.manifest_version_id
                  AND a.manifest_hash = json_extract(OLD.policy_json, '$.manifest_hash')
                  AND a.policy_hash = OLD.content_hash
                  AND a.approval_type = 'policy_activation'
                  AND a.decision = 'approved'
                  AND a.invalidated_at IS NULL
                  AND julianday(a.decided_at) <= julianday(NEW.activated_at)
                  AND julianday(a.expires_at) > julianday(NEW.activated_at)
                  AND json_valid(a.document_json) = 1
                  AND json_extract(a.document_json, '$.schema_version') = '2.0.0'
                  AND json_extract(a.document_json, '$.approval_id') = a.id
                  AND json_extract(a.document_json, '$.assessment_id') = a.engagement_id
                  AND json_extract(a.document_json, '$.manifest_version_id') = a.manifest_version_id
                  AND json_extract(a.document_json, '$.manifest_schema_version') = '3.0.0'
                  AND json_extract(a.document_json, '$.manifest_hash') = a.manifest_hash
                  AND json_extract(a.document_json, '$.policy_bundle_id') = a.policy_bundle_id
                  AND json_extract(a.document_json, '$.policy_schema_version') = '2.0.0'
                  AND json_extract(a.document_json, '$.policy_hash') = a.policy_hash
                  AND json_extract(a.document_json, '$.decision') = 'approved'
                  AND json_extract(a.document_json, '$.authority') = 'none'
                  AND json_extract(a.document_json, '$.execution_enabled') = 0
                  AND json_extract(a.document_json, '$.signature.algorithm') = 'Ed25519'
                  AND json_extract(a.document_json, '$.signature.key_id') = OLD.signer_key_id
            )
        )
        OR (
            OLD.activated_at IS NOT NULL
            AND OLD.revoked_at IS NULL
            AND NEW.activated_at IS OLD.activated_at
            AND NEW.revoked_at IS NOT NULL
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'policy IR v2 lifecycle transition is invalid');
END;
