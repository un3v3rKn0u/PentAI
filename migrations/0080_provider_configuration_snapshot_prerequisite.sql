CREATE TABLE ai_provider_configuration_snapshots_v1 (
    snapshot_id TEXT PRIMARY KEY,
    configuration_id TEXT NOT NULL UNIQUE,
    configuration_hash TEXT NOT NULL UNIQUE CHECK(length(configuration_hash)=64),
    registry_id TEXT NOT NULL,
    registry_revision INTEGER NOT NULL CHECK(registry_revision > 0),
    provider_type TEXT NOT NULL CHECK(provider_type IN ('approved_remote','local_runtime')),
    provider_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL UNIQUE CHECK(length(snapshot_digest)=71),
    recorded_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state='inactive'),
    meter_binding_enabled INTEGER NOT NULL CHECK(meter_binding_enabled=0),
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(registry_id,registry_revision,provider_id,model_id,configuration_id)
);

CREATE TRIGGER ai_provider_configuration_snapshots_v1_binding_valid
BEFORE INSERT ON ai_provider_configuration_snapshots_v1
WHEN json_extract(NEW.snapshot_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.snapshot_json,'$.snapshot_id') IS NOT NEW.snapshot_id
 OR json_extract(NEW.snapshot_json,'$.configuration_id') IS NOT NEW.configuration_id
 OR json_extract(NEW.snapshot_json,'$.configuration_hash') IS NOT NEW.configuration_hash
 OR json_extract(NEW.snapshot_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.snapshot_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.snapshot_json,'$.provider_type') IS NOT NEW.provider_type
 OR json_extract(NEW.snapshot_json,'$.provider_id') IS NOT NEW.provider_id
 OR json_extract(NEW.snapshot_json,'$.model_id') IS NOT NEW.model_id
 OR json_extract(NEW.snapshot_json,'$.state') IS NOT NEW.state
 OR json_extract(NEW.snapshot_json,'$.meter_binding_enabled') IS NOT 0
 OR json_extract(NEW.snapshot_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.snapshot_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot binding is invalid'); END;

CREATE TRIGGER ai_provider_configuration_snapshots_v1_producer_disabled
BEFORE INSERT ON ai_provider_configuration_snapshots_v1
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot producer is disabled'); END;

CREATE TRIGGER ai_provider_configuration_snapshots_v1_immutable
BEFORE UPDATE ON ai_provider_configuration_snapshots_v1
BEGIN SELECT RAISE(ABORT,'provider configuration snapshots are immutable'); END;

CREATE TRIGGER ai_provider_configuration_snapshots_v1_no_delete
BEFORE DELETE ON ai_provider_configuration_snapshots_v1
BEGIN SELECT RAISE(ABORT,'provider configuration snapshots cannot be deleted'); END;
