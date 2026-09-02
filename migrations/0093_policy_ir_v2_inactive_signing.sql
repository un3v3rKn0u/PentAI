CREATE TRIGGER policy_ir_v2_insert_inactive
BEFORE INSERT ON policy_bundles
WHEN (
    NEW.schema_version = '2.0.0'
    OR (
        json_valid(NEW.policy_json) = 1
        AND json_extract(NEW.policy_json, '$.schema_version') = '2.0.0'
    )
) AND (
    NEW.activated_at IS NOT NULL
    OR NEW.revoked_at IS NOT NULL
    OR json_valid(NEW.policy_json) != 1
    OR json_extract(NEW.policy_json, '$.schema_version') IS NOT '2.0.0'
    OR json_extract(NEW.policy_json, '$.content_hash') IS NOT NEW.content_hash
    OR json_extract(NEW.policy_json, '$.signature.algorithm') IS NOT 'Ed25519'
    OR json_extract(NEW.policy_json, '$.signature.key_id') IS NOT NEW.signer_key_id
    OR json_extract(NEW.policy_json, '$.signature.value') IS NOT NEW.signature
)
BEGIN
    SELECT RAISE(ABORT, 'policy IR v2 must be exact and inactive');
END;

CREATE TRIGGER policy_ir_v2_immutable
BEFORE UPDATE ON policy_bundles
WHEN OLD.schema_version = '2.0.0' OR (
    json_valid(OLD.policy_json) = 1
    AND json_extract(OLD.policy_json, '$.schema_version') = '2.0.0'
)
BEGIN
    SELECT RAISE(ABORT, 'policy IR v2 bundles are immutable and inactive');
END;

CREATE TRIGGER policy_ir_v2_no_delete
BEFORE DELETE ON policy_bundles
WHEN OLD.schema_version = '2.0.0' OR (
    json_valid(OLD.policy_json) = 1
    AND json_extract(OLD.policy_json, '$.schema_version') = '2.0.0'
)
BEGIN
    SELECT RAISE(ABORT, 'policy IR v2 bundles are immutable and retained');
END;
