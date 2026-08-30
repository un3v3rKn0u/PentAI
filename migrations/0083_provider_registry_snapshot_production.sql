DROP TRIGGER ai_provider_registry_snapshot_productions_v1_producer_disabled;
DROP TRIGGER ai_provider_registry_snapshots_v1_producer_disabled;

CREATE TRIGGER ai_provider_registry_snapshot_productions_v1_current_binding
BEFORE INSERT ON ai_provider_registry_snapshot_productions_v1
WHEN json_extract(NEW.command_json,'$.requester.actor_type') IS NOT 'human'
 OR length(NEW.command_id) != 36
 OR length(NEW.snapshot_id) != 36
 OR length(NEW.registry_id) != 36
 OR length(NEW.session_id) != 36
 OR json_extract(NEW.command_json,'$.authentication_context')
      IS NOT 'local_core_authenticated_session'
 OR json_extract(NEW.command_json,'$.purpose')
      IS NOT 'record_provider_registry_snapshot'
 OR json_type(NEW.command_json,'$.requested_at') IS NOT 'text'
 OR json_type(NEW.command_json,'$.expires_at') IS NOT 'text'
 OR julianday(json_extract(NEW.command_json,'$.requested_at')) > julianday(NEW.recorded_at)
 OR julianday(json_extract(NEW.command_json,'$.expires_at')) <= julianday(NEW.recorded_at)
 OR json_extract(NEW.receipt_json,'$.snapshot_digest') IS NULL
 OR length(json_extract(NEW.receipt_json,'$.snapshot_digest')) != 71
 OR json_extract(NEW.receipt_json,'$.recorded_at') IS NOT NEW.recorded_at
 OR json_extract(NEW.receipt_json,'$.state') IS NOT 'inactive'
 OR json_extract(NEW.receipt_json,'$.activation_enabled') IS NOT 0
 OR json_extract(NEW.receipt_json,'$.revocation_enabled') IS NOT 0
 OR EXISTS (
      SELECT 1 FROM ai_provider_registry_snapshots_v1 s
      WHERE s.registry_id=NEW.registry_id
        AND s.registry_revision>=NEW.registry_revision
 )
BEGIN SELECT RAISE(ABORT,'provider registry snapshot production is not current'); END;

CREATE TRIGGER ai_provider_registry_snapshots_v1_production_required
BEFORE INSERT ON ai_provider_registry_snapshots_v1
WHEN NOT EXISTS (
  SELECT 1 FROM ai_provider_registry_snapshot_productions_v1 p
  WHERE p.snapshot_id=NEW.snapshot_id
    AND p.registry_id=NEW.registry_id
    AND p.registry_revision=NEW.registry_revision
    AND p.registry_digest=NEW.registry_digest
    AND p.providers_digest=NEW.providers_digest
    AND p.recorded_at=NEW.recorded_at
    AND json_extract(p.receipt_json,'$.snapshot_digest')=NEW.snapshot_digest
    AND json_extract(p.receipt_json,'$.state')='inactive'
    AND json_extract(p.receipt_json,'$.activation_enabled')=0
    AND json_extract(p.receipt_json,'$.revocation_enabled')=0
    AND p.production_enabled=0 AND p.authority='none' AND p.execution_enabled=0
)
BEGIN SELECT RAISE(ABORT,'authenticated provider registry production is required'); END;
