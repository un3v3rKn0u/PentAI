CREATE TABLE ai_runtime_meter_implementation_productions_v1 (
    command_id TEXT PRIMARY KEY,
    command_digest TEXT NOT NULL UNIQUE CHECK(length(command_digest)=71),
    capability_id TEXT NOT NULL UNIQUE REFERENCES ai_runtime_meter_implementations_v1(capability_id),
    capability_digest TEXT NOT NULL UNIQUE CHECK(length(capability_digest)=71),
    implementation_id TEXT NOT NULL,
    implementation_version INTEGER NOT NULL CHECK(implementation_version > 0),
    provider_types_json TEXT NOT NULL CHECK(json_type(provider_types_json)='array'),
    supported_dimensions_json TEXT NOT NULL CHECK(json_type(supported_dimensions_json)='array'),
    capability_valid_from TEXT NOT NULL,
    capability_expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL CHECK(actor_id IN ('local-desktop-session','test-session')),
    session_id TEXT NOT NULL,
    command_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK(length(receipt_digest)=71),
    recorded_at TEXT NOT NULL,
    production_enabled INTEGER NOT NULL CHECK(production_enabled=0),
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(implementation_id,implementation_version)
);

CREATE TRIGGER ai_runtime_meter_implementation_productions_v1_binding_valid
BEFORE INSERT ON ai_runtime_meter_implementation_productions_v1
WHEN json_extract(NEW.command_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.command_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.command_json,'$.capability_id') IS NOT NEW.capability_id
 OR json_extract(NEW.command_json,'$.implementation_id') IS NOT NEW.implementation_id
 OR json_extract(NEW.command_json,'$.implementation_version') IS NOT NEW.implementation_version
 OR json(json_extract(NEW.command_json,'$.provider_types')) IS NOT json(NEW.provider_types_json)
 OR json(json_extract(NEW.command_json,'$.supported_dimensions')) IS NOT json(NEW.supported_dimensions_json)
 OR json_extract(NEW.command_json,'$.capability_valid_from') IS NOT NEW.capability_valid_from
 OR json_extract(NEW.command_json,'$.capability_expires_at') IS NOT NEW.capability_expires_at
 OR json_extract(NEW.command_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.command_json,'$.requester.actor_type') IS NOT 'human'
 OR json_extract(NEW.command_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.command_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.command_json,'$.purpose') IS NOT 'record_runtime_meter_implementation'
 OR json_extract(NEW.command_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.command_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.command_json,'$.execution_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.schema_version') IS NOT '2.0.0'
 OR json_extract(NEW.receipt_json,'$.capability_id') IS NOT NEW.capability_id
 OR json_extract(NEW.receipt_json,'$.capability_digest') IS NOT NEW.capability_digest
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.implementation_id') IS NOT NEW.implementation_id
 OR json_extract(NEW.receipt_json,'$.implementation_version') IS NOT NEW.implementation_version
 OR json(json_extract(NEW.receipt_json,'$.provider_types')) IS NOT json(NEW.provider_types_json)
 OR json(json_extract(NEW.receipt_json,'$.supported_dimensions')) IS NOT json(NEW.supported_dimensions_json)
 OR json_extract(NEW.receipt_json,'$.capability_valid_from') IS NOT NEW.capability_valid_from
 OR json_extract(NEW.receipt_json,'$.capability_expires_at') IS NOT NEW.capability_expires_at
 OR json_extract(NEW.receipt_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.receipt_json,'$.requester.actor_type') IS NOT 'human'
 OR json_extract(NEW.receipt_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.receipt_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.receipt_json,'$.state') IS NOT 'inactive'
 OR json_extract(NEW.receipt_json,'$.identity_binding_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.attestation_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.measurement_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.recorded_at') IS NOT NEW.recorded_at
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'runtime meter implementation production binding is invalid'); END;

CREATE TRIGGER ai_runtime_meter_implementation_productions_v1_producer_disabled
BEFORE INSERT ON ai_runtime_meter_implementation_productions_v1
BEGIN SELECT RAISE(ABORT,'runtime meter implementation production is disabled'); END;

CREATE TRIGGER ai_runtime_meter_implementation_productions_v1_immutable
BEFORE UPDATE ON ai_runtime_meter_implementation_productions_v1
BEGIN SELECT RAISE(ABORT,'runtime meter implementation productions are immutable'); END;

CREATE TRIGGER ai_runtime_meter_implementation_productions_v1_no_delete
BEFORE DELETE ON ai_runtime_meter_implementation_productions_v1
BEGIN SELECT RAISE(ABORT,'runtime meter implementation productions cannot be deleted'); END;
