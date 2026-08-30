DROP TRIGGER ai_provider_registry_activations_v1_producer_disabled;

CREATE TRIGGER ai_provider_registry_activations_v1_current_binding
BEFORE INSERT ON ai_provider_registry_activations_v1
WHEN julianday(NEW.activated_at) IS NULL
 OR julianday(NEW.expires_at) IS NULL
 OR julianday(NEW.expires_at)<=julianday(NEW.activated_at)
 OR NOT EXISTS (
   SELECT 1 FROM ai_provider_registry_snapshots_v1 s
   JOIN ai_provider_registry_snapshot_productions_v1 p ON p.snapshot_id=s.snapshot_id
   WHERE s.snapshot_id=NEW.snapshot_id
     AND s.snapshot_digest=NEW.snapshot_digest
     AND s.registry_id=NEW.registry_id
     AND s.registry_revision=NEW.registry_revision
     AND s.registry_digest=NEW.registry_digest
     AND s.providers_digest=NEW.providers_digest
     AND s.state='inactive' AND s.activation_enabled=0 AND s.revocation_enabled=0
     AND s.authority='none' AND s.execution_enabled=0
     AND p.receipt_digest=NEW.snapshot_receipt_digest
     AND json_extract(p.receipt_json,'$.snapshot_id')=NEW.snapshot_id
     AND json_extract(p.receipt_json,'$.snapshot_digest')=NEW.snapshot_digest
     AND json_extract(p.receipt_json,'$.state')='inactive'
     AND json_extract(s.snapshot_json,'$.expires_at')=NEW.expires_at
 )
 OR EXISTS (
   SELECT 1 FROM ai_provider_registry_snapshots_v1 newer
   WHERE newer.registry_id=NEW.registry_id
     AND newer.registry_revision>NEW.registry_revision
 )
 OR EXISTS (
   SELECT 1 FROM ai_provider_registry_activations_v1 current
   WHERE julianday(current.activated_at)<=julianday(NEW.activated_at)
     AND julianday(current.expires_at)>julianday(NEW.activated_at)
 )
BEGIN SELECT RAISE(ABORT,'provider registry activation is not current'); END;
