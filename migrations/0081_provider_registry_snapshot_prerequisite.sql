CREATE TABLE ai_provider_registry_snapshots_v1 (
    snapshot_id TEXT PRIMARY KEY,
    registry_id TEXT NOT NULL,
    registry_revision INTEGER NOT NULL CHECK(registry_revision > 0),
    registry_digest TEXT NOT NULL UNIQUE CHECK(length(registry_digest)=71),
    providers_digest TEXT NOT NULL CHECK(length(providers_digest)=71),
    snapshot_json TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL UNIQUE CHECK(length(snapshot_digest)=71),
    recorded_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state='inactive'),
    activation_enabled INTEGER NOT NULL CHECK(activation_enabled=0),
    revocation_enabled INTEGER NOT NULL CHECK(revocation_enabled=0),
    authority TEXT NOT NULL CHECK(authority='none'),
    execution_enabled INTEGER NOT NULL CHECK(execution_enabled=0),
    UNIQUE(registry_id,registry_revision)
);

CREATE TRIGGER ai_provider_registry_snapshots_v1_binding_valid
BEFORE INSERT ON ai_provider_registry_snapshots_v1
WHEN json_extract(NEW.snapshot_json,'$.schema_version') IS NOT '1.0.0'
 OR json_extract(NEW.snapshot_json,'$.snapshot_id') IS NOT NEW.snapshot_id
 OR json_extract(NEW.snapshot_json,'$.registry_id') IS NOT NEW.registry_id
 OR json_extract(NEW.snapshot_json,'$.registry_revision') IS NOT NEW.registry_revision
 OR json_extract(NEW.snapshot_json,'$.registry_digest') IS NOT NEW.registry_digest
 OR json_extract(NEW.snapshot_json,'$.providers_digest') IS NOT NEW.providers_digest
 OR json_extract(NEW.snapshot_json,'$.state') IS NOT NEW.state
 OR json_extract(NEW.snapshot_json,'$.activation_enabled') IS NOT 0
 OR json_extract(NEW.snapshot_json,'$.revocation_enabled') IS NOT 0
 OR json_extract(NEW.snapshot_json,'$.authority') IS NOT 'none'
 OR json_extract(NEW.snapshot_json,'$.execution_enabled') IS NOT 0
BEGIN SELECT RAISE(ABORT,'provider registry snapshot binding is invalid'); END;

CREATE TRIGGER ai_provider_registry_snapshots_v1_producer_disabled
BEFORE INSERT ON ai_provider_registry_snapshots_v1
BEGIN SELECT RAISE(ABORT,'provider registry snapshot producer is disabled'); END;

CREATE TRIGGER ai_provider_registry_snapshots_v1_immutable
BEFORE UPDATE ON ai_provider_registry_snapshots_v1
BEGIN SELECT RAISE(ABORT,'provider registry snapshots are immutable'); END;

CREATE TRIGGER ai_provider_registry_snapshots_v1_no_delete
BEFORE DELETE ON ai_provider_registry_snapshots_v1
BEGIN SELECT RAISE(ABORT,'provider registry snapshots cannot be deleted'); END;
