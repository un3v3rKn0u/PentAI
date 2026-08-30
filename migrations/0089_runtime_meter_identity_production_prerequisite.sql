CREATE TABLE ai_runtime_meter_identity_productions_v1 (
    command_id TEXT PRIMARY KEY,
    command_digest TEXT NOT NULL UNIQUE CHECK(length(command_digest)=71),
    meter_id TEXT NOT NULL UNIQUE REFERENCES ai_runtime_meter_identities_v1(meter_id),
    meter_identity_digest TEXT NOT NULL UNIQUE CHECK(length(meter_identity_digest)=71),
    configuration_snapshot_id TEXT NOT NULL REFERENCES ai_provider_configuration_snapshots_v1(snapshot_id),
    configuration_snapshot_digest TEXT NOT NULL CHECK(length(configuration_snapshot_digest)=71),
    configuration_id TEXT NOT NULL,
    configuration_hash TEXT NOT NULL CHECK(length(configuration_hash)=64),
    registry_id TEXT NOT NULL,
    registry_revision INTEGER NOT NULL CHECK(registry_revision > 0),
    provider_type TEXT NOT NULL CHECK(provider_type IN ('approved_remote','local_runtime')),
    provider_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    worker_id TEXT NOT NULL REFERENCES worker_runtime_instances(worker_id),
    worker_version INTEGER NOT NULL CHECK(worker_version > 0),
    runtime_instance_id TEXT NOT NULL,
    containment_attestation_id TEXT NOT NULL,
    image_digest TEXT NOT NULL CHECK(length(image_digest)=71),
    implementation_id TEXT NOT NULL,
    implementation_version INTEGER NOT NULL CHECK(implementation_version > 0),
    supported_dimensions_json TEXT NOT NULL CHECK(json_type(supported_dimensions_json)='array'),
    identity_valid_from TEXT NOT NULL,
    identity_expires_at TEXT NOT NULL,
    actor_id TEXT NOT NULL CHECK(actor_id IN ('local-desktop-session','test-session')),
    session_id TEXT NOT NULL,
    command_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK(length(receipt_digest)=71),
    recorded_at TEXT NOT NULL,
    production_enabled INTEGER NOT NULL CHECK(production_enabled=0),
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(configuration_snapshot_id,worker_id,implementation_id,implementation_version)
);

CREATE TRIGGER ai_runtime_meter_identity_productions_v1_binding_valid
BEFORE INSERT ON ai_runtime_meter_identity_productions_v1
WHEN json_extract(NEW.command_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.command_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.command_json,'$.meter_id') IS NOT NEW.meter_id
 OR json_extract(NEW.command_json,'$.implementation_id') IS NOT NEW.implementation_id
 OR json_extract(NEW.command_json,'$.implementation_version') IS NOT NEW.implementation_version
 OR json(json_extract(NEW.command_json,'$.supported_dimensions')) IS NOT json(NEW.supported_dimensions_json)
 OR json_extract(NEW.command_json,'$.configuration_snapshot_id') IS NOT NEW.configuration_snapshot_id
 OR json_extract(NEW.command_json,'$.configuration_snapshot_digest') IS NOT NEW.configuration_snapshot_digest
 OR json_extract(NEW.command_json,'$.configuration_id') IS NOT NEW.configuration_id
 OR json_extract(NEW.command_json,'$.configuration_hash') IS NOT NEW.configuration_hash
 OR json_extract(NEW.command_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.command_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.command_json,'$.provider_type') IS NOT NEW.provider_type
 OR json_extract(NEW.command_json,'$.provider_id') IS NOT NEW.provider_id
 OR json_extract(NEW.command_json,'$.model_id') IS NOT NEW.model_id
 OR json_extract(NEW.command_json,'$.worker_id') IS NOT NEW.worker_id
 OR json_extract(NEW.command_json,'$.worker_version') IS NOT NEW.worker_version
 OR json_extract(NEW.command_json,'$.runtime_instance_id') IS NOT NEW.runtime_instance_id
 OR json_extract(NEW.command_json,'$.containment_attestation_id') IS NOT NEW.containment_attestation_id
 OR json_extract(NEW.command_json,'$.image_digest') IS NOT NEW.image_digest
 OR json_extract(NEW.command_json,'$.identity_valid_from') IS NOT NEW.identity_valid_from
 OR json_extract(NEW.command_json,'$.identity_expires_at') IS NOT NEW.identity_expires_at
 OR json_extract(NEW.command_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.command_json,'$.requester.actor_type') IS NOT 'human'
 OR json_extract(NEW.command_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.command_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.command_json,'$.purpose') IS NOT 'record_runtime_meter_identity'
 OR json_extract(NEW.command_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.command_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.command_json,'$.execution_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.schema_version') IS NOT '2.0.0'
 OR json_extract(NEW.receipt_json,'$.meter_id') IS NOT NEW.meter_id
 OR json_extract(NEW.receipt_json,'$.meter_identity_digest') IS NOT NEW.meter_identity_digest
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.implementation_id') IS NOT NEW.implementation_id
 OR json_extract(NEW.receipt_json,'$.implementation_version') IS NOT NEW.implementation_version
 OR json(json_extract(NEW.receipt_json,'$.supported_dimensions')) IS NOT json(NEW.supported_dimensions_json)
 OR json_extract(NEW.receipt_json,'$.configuration_snapshot_id') IS NOT NEW.configuration_snapshot_id
 OR json_extract(NEW.receipt_json,'$.configuration_snapshot_digest') IS NOT NEW.configuration_snapshot_digest
 OR json_extract(NEW.receipt_json,'$.configuration_id') IS NOT NEW.configuration_id
 OR json_extract(NEW.receipt_json,'$.configuration_hash') IS NOT NEW.configuration_hash
 OR json_extract(NEW.receipt_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.receipt_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.receipt_json,'$.provider_type') IS NOT NEW.provider_type
 OR json_extract(NEW.receipt_json,'$.provider_id') IS NOT NEW.provider_id
 OR json_extract(NEW.receipt_json,'$.model_id') IS NOT NEW.model_id
 OR json_extract(NEW.receipt_json,'$.worker_id') IS NOT NEW.worker_id
 OR json_extract(NEW.receipt_json,'$.worker_version') IS NOT NEW.worker_version
 OR json_extract(NEW.receipt_json,'$.runtime_instance_id') IS NOT NEW.runtime_instance_id
 OR json_extract(NEW.receipt_json,'$.containment_attestation_id') IS NOT NEW.containment_attestation_id
 OR json_extract(NEW.receipt_json,'$.image_digest') IS NOT NEW.image_digest
 OR json_extract(NEW.receipt_json,'$.identity_valid_from') IS NOT NEW.identity_valid_from
 OR json_extract(NEW.receipt_json,'$.identity_expires_at') IS NOT NEW.identity_expires_at
 OR json_extract(NEW.receipt_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.receipt_json,'$.requester.actor_type') IS NOT 'human'
 OR json_extract(NEW.receipt_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.receipt_json,'$.authentication_context') IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.receipt_json,'$.state') IS NOT 'inactive'
 OR json_extract(NEW.receipt_json,'$.attestation_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.measurement_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.recorded_at') IS NOT NEW.recorded_at
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'runtime meter identity production binding is invalid'); END;

CREATE TRIGGER ai_runtime_meter_identity_productions_v1_producer_disabled
BEFORE INSERT ON ai_runtime_meter_identity_productions_v1
BEGIN SELECT RAISE(ABORT,'runtime meter identity production is disabled'); END;

CREATE TRIGGER ai_runtime_meter_identity_productions_v1_immutable
BEFORE UPDATE ON ai_runtime_meter_identity_productions_v1
BEGIN SELECT RAISE(ABORT,'runtime meter identity productions are immutable'); END;

CREATE TRIGGER ai_runtime_meter_identity_productions_v1_no_delete
BEFORE DELETE ON ai_runtime_meter_identity_productions_v1
BEGIN SELECT RAISE(ABORT,'runtime meter identity productions cannot be deleted'); END;
