CREATE TABLE ai_provider_configuration_snapshot_productions_v1 (
    command_id TEXT PRIMARY KEY,
    command_digest TEXT NOT NULL UNIQUE CHECK(length(command_digest)=71),
    snapshot_id TEXT NOT NULL UNIQUE REFERENCES ai_provider_configuration_snapshots_v1(snapshot_id),
    snapshot_digest TEXT NOT NULL UNIQUE CHECK(length(snapshot_digest)=71),
    configuration_id TEXT NOT NULL UNIQUE,
    configuration_hash TEXT NOT NULL UNIQUE CHECK(length(configuration_hash)=64),
    activation_id TEXT NOT NULL REFERENCES ai_provider_registry_activations_v1(activation_id),
    activation_receipt_digest TEXT NOT NULL CHECK(length(activation_receipt_digest)=71),
    registry_snapshot_id TEXT NOT NULL REFERENCES ai_provider_registry_snapshots_v1(snapshot_id),
    registry_snapshot_digest TEXT NOT NULL CHECK(length(registry_snapshot_digest)=71),
    registry_snapshot_receipt_digest TEXT NOT NULL CHECK(length(registry_snapshot_receipt_digest)=71),
    registry_id TEXT NOT NULL,
    registry_revision INTEGER NOT NULL CHECK(registry_revision > 0),
    registry_digest TEXT NOT NULL CHECK(length(registry_digest)=71),
    providers_digest TEXT NOT NULL CHECK(length(providers_digest)=71),
    provider_type TEXT NOT NULL CHECK(provider_type IN ('approved_remote','local_runtime')),
    provider_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    secret_reference_digest TEXT CHECK(secret_reference_digest IS NULL OR length(secret_reference_digest)=71),
    actor_id TEXT NOT NULL CHECK(actor_id IN ('local-desktop-session','test-session')),
    session_id TEXT NOT NULL,
    command_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK(length(receipt_digest)=71),
    recorded_at TEXT NOT NULL,
    production_enabled INTEGER NOT NULL CHECK(production_enabled=0),
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(activation_id,configuration_id),
    UNIQUE(registry_id,registry_revision,provider_id,model_id,configuration_id)
);

CREATE TRIGGER ai_provider_configuration_snapshot_productions_v1_binding_valid
BEFORE INSERT ON ai_provider_configuration_snapshot_productions_v1
WHEN json_extract(NEW.command_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.command_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.command_json,'$.snapshot_id') IS NOT NEW.snapshot_id
 OR json_extract(NEW.command_json,'$.configuration_id') IS NOT NEW.configuration_id
 OR json_extract(NEW.command_json,'$.configuration_hash') IS NOT NEW.configuration_hash
 OR json_extract(NEW.command_json,'$.activation_id') IS NOT NEW.activation_id
 OR json_extract(NEW.command_json,'$.activation_receipt_digest') IS NOT NEW.activation_receipt_digest
 OR json_extract(NEW.command_json,'$.registry_snapshot_id') IS NOT NEW.registry_snapshot_id
 OR json_extract(NEW.command_json,'$.registry_snapshot_digest') IS NOT NEW.registry_snapshot_digest
 OR json_extract(NEW.command_json,'$.registry_snapshot_receipt_digest') IS NOT NEW.registry_snapshot_receipt_digest
 OR json_extract(NEW.command_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.command_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.command_json,'$.registry_digest') IS NOT NEW.registry_digest
 OR json_extract(NEW.command_json,'$.providers_digest') IS NOT NEW.providers_digest
 OR json_extract(NEW.command_json,'$.provider_type') IS NOT NEW.provider_type
 OR json_extract(NEW.command_json,'$.provider_id') IS NOT NEW.provider_id
 OR json_extract(NEW.command_json,'$.model_id') IS NOT NEW.model_id
 OR json_extract(NEW.command_json,'$.secret_reference_digest') IS NOT NEW.secret_reference_digest
 OR json_extract(NEW.command_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.command_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.command_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.command_json,'$.purpose') IS NOT 'record_provider_configuration_snapshot'
 OR json_extract(NEW.command_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.command_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.command_json,'$.execution_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.schema_version') IS NOT '2.0.0'
 OR json_extract(NEW.receipt_json,'$.snapshot_id') IS NOT NEW.snapshot_id
 OR json_extract(NEW.receipt_json,'$.snapshot_digest') IS NOT NEW.snapshot_digest
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.configuration_id') IS NOT NEW.configuration_id
 OR json_extract(NEW.receipt_json,'$.configuration_hash') IS NOT NEW.configuration_hash
 OR json_extract(NEW.receipt_json,'$.activation_id') IS NOT NEW.activation_id
 OR json_extract(NEW.receipt_json,'$.activation_receipt_digest') IS NOT NEW.activation_receipt_digest
 OR json_extract(NEW.receipt_json,'$.registry_snapshot_id') IS NOT NEW.registry_snapshot_id
 OR json_extract(NEW.receipt_json,'$.registry_snapshot_digest') IS NOT NEW.registry_snapshot_digest
 OR json_extract(NEW.receipt_json,'$.registry_snapshot_receipt_digest') IS NOT NEW.registry_snapshot_receipt_digest
 OR json_extract(NEW.receipt_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.receipt_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.receipt_json,'$.registry_digest') IS NOT NEW.registry_digest
 OR json_extract(NEW.receipt_json,'$.providers_digest') IS NOT NEW.providers_digest
 OR json_extract(NEW.receipt_json,'$.provider_type') IS NOT NEW.provider_type
 OR json_extract(NEW.receipt_json,'$.provider_id') IS NOT NEW.provider_id
 OR json_extract(NEW.receipt_json,'$.model_id') IS NOT NEW.model_id
 OR json_extract(NEW.receipt_json,'$.secret_reference_digest') IS NOT NEW.secret_reference_digest
 OR json_extract(NEW.receipt_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.receipt_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.receipt_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.receipt_json,'$.state') IS NOT 'inactive'
 OR json_extract(NEW.receipt_json,'$.meter_binding_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.recorded_at') IS NOT NEW.recorded_at
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot production binding is invalid'); END;

CREATE TRIGGER ai_provider_configuration_snapshot_productions_v1_producer_disabled
BEFORE INSERT ON ai_provider_configuration_snapshot_productions_v1
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot production is disabled'); END;

CREATE TRIGGER ai_provider_configuration_snapshot_productions_v1_immutable
BEFORE UPDATE ON ai_provider_configuration_snapshot_productions_v1
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot productions are immutable'); END;

CREATE TRIGGER ai_provider_configuration_snapshot_productions_v1_no_delete
BEFORE DELETE ON ai_provider_configuration_snapshot_productions_v1
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot productions cannot be deleted'); END;
