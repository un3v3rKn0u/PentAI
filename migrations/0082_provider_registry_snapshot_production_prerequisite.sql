CREATE TABLE ai_provider_registry_snapshot_productions_v1 (
    command_id TEXT PRIMARY KEY,
    command_digest TEXT NOT NULL UNIQUE CHECK(length(command_digest)=71),
    snapshot_id TEXT NOT NULL UNIQUE REFERENCES ai_provider_registry_snapshots_v1(snapshot_id),
    registry_id TEXT NOT NULL,
    registry_revision INTEGER NOT NULL CHECK(registry_revision > 0),
    registry_digest TEXT NOT NULL CHECK(length(registry_digest)=71),
    providers_digest TEXT NOT NULL CHECK(length(providers_digest)=71),
    actor_id TEXT NOT NULL CHECK(actor_id IN ('local-desktop-session','test-session')),
    session_id TEXT NOT NULL,
    command_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE CHECK(length(receipt_digest)=71),
    recorded_at TEXT NOT NULL,
    production_enabled INTEGER NOT NULL CHECK(production_enabled=0),
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(registry_id,registry_revision)
);

CREATE TRIGGER ai_provider_registry_snapshot_productions_v1_binding_valid
BEFORE INSERT ON ai_provider_registry_snapshot_productions_v1
WHEN json_extract(NEW.command_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.command_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.command_json,'$.snapshot_id') IS NOT NEW.snapshot_id
 OR json_extract(NEW.command_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.command_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.command_json,'$.registry_digest') IS NOT NEW.registry_digest
 OR json_extract(NEW.command_json,'$.providers_digest') IS NOT NEW.providers_digest
 OR json_extract(NEW.command_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.command_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.command_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.command_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.command_json,'$.execution_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.schema_version') IS NOT '2.0.0'
 OR json_extract(NEW.receipt_json,'$.command_id') IS NOT NEW.command_id
 OR json_extract(NEW.receipt_json,'$.command_digest') IS NOT NEW.command_digest
 OR json_extract(NEW.receipt_json,'$.snapshot_id') IS NOT NEW.snapshot_id
 OR json_extract(NEW.receipt_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.receipt_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.receipt_json,'$.registry_digest') IS NOT NEW.registry_digest
 OR json_extract(NEW.receipt_json,'$.providers_digest') IS NOT NEW.providers_digest
 OR json_extract(NEW.receipt_json,'$.requester.actor_id') IS NOT NEW.actor_id
 OR json_extract(NEW.receipt_json,'$.requester.session_id') IS NOT NEW.session_id
 OR json_extract(NEW.receipt_json,'$.production_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.receipt_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'provider registry snapshot production binding is invalid'); END;

CREATE TRIGGER ai_provider_registry_snapshot_productions_v1_producer_disabled
BEFORE INSERT ON ai_provider_registry_snapshot_productions_v1
BEGIN SELECT RAISE(ABORT,'provider registry snapshot production is disabled'); END;

CREATE TRIGGER ai_provider_registry_snapshot_productions_v1_immutable
BEFORE UPDATE ON ai_provider_registry_snapshot_productions_v1
BEGIN SELECT RAISE(ABORT,'provider registry snapshot productions are immutable'); END;

CREATE TRIGGER ai_provider_registry_snapshot_productions_v1_no_delete
BEFORE DELETE ON ai_provider_registry_snapshot_productions_v1
BEGIN SELECT RAISE(ABORT,'provider registry snapshot productions cannot be deleted'); END;
