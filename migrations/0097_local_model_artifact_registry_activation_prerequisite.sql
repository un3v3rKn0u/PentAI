CREATE TABLE local_model_artifact_registry_activations_v1 (
    activation_id TEXT PRIMARY KEY,
    receipt_digest TEXT NOT NULL UNIQUE CHECK(length(receipt_digest)=71),
    command_id TEXT NOT NULL UNIQUE,
    command_digest TEXT NOT NULL UNIQUE CHECK(length(command_digest)=71),
    manifest_id TEXT NOT NULL CHECK(manifest_id='macos-arm64-llama-b10516-qwen25-coder-3b-q4km'),
    manifest_revision INTEGER NOT NULL CHECK(manifest_revision=1),
    manifest_digest TEXT NOT NULL CHECK(manifest_digest='sha256:20a4fe2660706615ef7db2688b6a54ecbb2644601bb5966ff54f98983f4b6e9a'),
    actor_id TEXT NOT NULL CHECK(actor_id IN ('local-desktop-session','test-session')),
    session_id TEXT NOT NULL,
    command_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state='active'),
    review_period_days INTEGER NOT NULL CHECK(review_period_days=180),
    verification_enabled INTEGER NOT NULL CHECK(verification_enabled=0),
    revocation_enabled INTEGER NOT NULL CHECK(revocation_enabled=0),
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(manifest_id,manifest_revision)
);

CREATE TRIGGER local_model_artifact_registry_activations_v1_producer_disabled
BEFORE INSERT ON local_model_artifact_registry_activations_v1
BEGIN SELECT RAISE(ABORT,'local model artifact registry activation producer is disabled'); END;

CREATE TRIGGER local_model_artifact_registry_activations_v1_binding_valid
BEFORE INSERT ON local_model_artifact_registry_activations_v1
WHEN json_extract(NEW.command_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.command_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.command_json,'$.manifest_id') IS NOT NEW.manifest_id
 OR json_extract(NEW.command_json,'$.manifest_revision') IS NOT NEW.manifest_revision
 OR json_extract(NEW.command_json,'$.manifest_digest') IS NOT NEW.manifest_digest
 OR json_extract(NEW.command_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.command_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.command_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.command_json,'$.purpose') IS NOT 'activate_local_model_artifact_registry'
 OR json_extract(NEW.command_json,'$.review_period_days') IS NOT 180
 OR json_extract(NEW.command_json,'$.activation_enabled') IS NOT 0
 OR json_extract(NEW.command_json,'$.verification_enabled') IS NOT 0
 OR json_extract(NEW.command_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.command_json,'$.execution_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.receipt_json,'$.activation_id') IS NOT NEW.activation_id
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.manifest_id') IS NOT NEW.manifest_id
 OR json_extract(NEW.receipt_json,'$.manifest_revision') IS NOT NEW.manifest_revision
 OR json_extract(NEW.receipt_json,'$.manifest_digest') IS NOT NEW.manifest_digest
 OR json_extract(NEW.receipt_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.receipt_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.receipt_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.receipt_json,'$.state') IS NOT NEW.state
 OR json_extract(NEW.receipt_json,'$.review_period_days') IS NOT NEW.review_period_days
 OR json_extract(NEW.receipt_json,'$.activated_at') IS NOT NEW.activated_at
 OR json_extract(NEW.receipt_json,'$.expires_at') IS NOT NEW.expires_at
 OR json_extract(NEW.receipt_json,'$.verification_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.revocation_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'local model artifact registry activation binding is invalid'); END;

CREATE TRIGGER local_model_artifact_registry_activations_v1_immutable
BEFORE UPDATE ON local_model_artifact_registry_activations_v1
BEGIN SELECT RAISE(ABORT,'local model artifact registry activations are immutable'); END;

CREATE TRIGGER local_model_artifact_registry_activations_v1_no_delete
BEFORE DELETE ON local_model_artifact_registry_activations_v1
BEGIN SELECT RAISE(ABORT,'local model artifact registry activations cannot be deleted'); END;
