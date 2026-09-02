CREATE TRIGGER policy_ir_v2_approval_document_required
BEFORE INSERT ON approvals
WHEN EXISTS (
    SELECT 1 FROM policy_bundles p
    WHERE p.id = NEW.policy_bundle_id AND p.schema_version = '2.0.0'
)
AND (
    json_valid(NEW.document_json) != 1
    OR json_extract(NEW.document_json, '$.schema_version') IS NOT '2.0.0'
)
BEGIN
    SELECT RAISE(ABORT, 'policy IR v2 approval document is required');
END;

CREATE TRIGGER policy_ir_v2_approval_binding_valid
BEFORE INSERT ON approvals
WHEN json_valid(NEW.document_json) = 1
 AND json_extract(NEW.document_json, '$.schema_version') = '2.0.0'
 AND (
    NEW.approval_type != 'policy_activation'
    OR json_extract(NEW.document_json, '$.approval_id') IS NOT NEW.id
    OR json_extract(NEW.document_json, '$.approval_type') IS NOT NEW.approval_type
    OR json_extract(NEW.document_json, '$.assessment_id') IS NOT NEW.engagement_id
    OR json_extract(NEW.document_json, '$.manifest_version_id') IS NOT NEW.manifest_version_id
    OR json_extract(NEW.document_json, '$.manifest_schema_version') IS NOT '3.0.0'
    OR json_extract(NEW.document_json, '$.manifest_hash') IS NOT NEW.manifest_hash
    OR json_extract(NEW.document_json, '$.policy_bundle_id') IS NOT NEW.policy_bundle_id
    OR json_extract(NEW.document_json, '$.policy_schema_version') IS NOT '2.0.0'
    OR json_extract(NEW.document_json, '$.policy_hash') IS NOT NEW.policy_hash
    OR json_extract(NEW.document_json, '$.decision') IS NOT NEW.decision
    OR json_extract(NEW.document_json, '$.approver.actor_type') IS NOT 'human'
    OR json_extract(NEW.document_json, '$.approver.actor_id') IS NOT NEW.approver_id
    OR json_extract(NEW.document_json, '$.decided_at') IS NOT NEW.decided_at
    OR json_extract(NEW.document_json, '$.expires_at') IS NOT NEW.expires_at
    OR json_extract(NEW.document_json, '$.authority') IS NOT 'none'
    OR json_extract(NEW.document_json, '$.execution_enabled') IS NOT 0
    OR json_extract(NEW.document_json, '$.signature.algorithm') IS NOT 'Ed25519'
    OR json_extract(NEW.document_json, '$.signature.key_id') IS NULL
    OR json_extract(NEW.document_json, '$.signature.value') IS NULL
    OR NOT EXISTS (
        SELECT 1 FROM policy_bundles p
        JOIN manifest_versions m ON m.id = p.manifest_version_id
        WHERE p.id = NEW.policy_bundle_id
          AND p.engagement_id = NEW.engagement_id
          AND p.manifest_version_id = NEW.manifest_version_id
          AND p.content_hash = NEW.policy_hash
          AND p.schema_version = '2.0.0'
          AND p.signer_key_id = json_extract(NEW.document_json, '$.signature.key_id')
          AND p.activated_at IS NULL
          AND p.revoked_at IS NULL
          AND m.schema_version = '3.0.0'
          AND m.content_hash = NEW.manifest_hash
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'policy IR v2 approval binding is invalid');
END;
