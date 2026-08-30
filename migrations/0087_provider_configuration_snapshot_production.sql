DROP TRIGGER ai_provider_configuration_snapshot_productions_v1_producer_disabled;
DROP TRIGGER ai_provider_configuration_snapshots_v1_producer_disabled;

CREATE TRIGGER ai_provider_configuration_snapshot_productions_v1_current_binding
BEFORE INSERT ON ai_provider_configuration_snapshot_productions_v1
WHEN NOT EXISTS (
    SELECT 1
    FROM ai_provider_registry_activations_v1 AS a
    JOIN ai_provider_registry_snapshots_v1 AS s ON s.snapshot_id=a.snapshot_id
    JOIN ai_provider_registry_snapshot_productions_v1 AS p
      ON p.snapshot_id=s.snapshot_id
    WHERE a.activation_id=NEW.activation_id
      AND a.receipt_digest=NEW.activation_receipt_digest
      AND a.snapshot_id=NEW.registry_snapshot_id
      AND a.snapshot_digest=NEW.registry_snapshot_digest
      AND a.snapshot_receipt_digest=NEW.registry_snapshot_receipt_digest
      AND a.registry_id=NEW.registry_id
      AND a.registry_revision=NEW.registry_revision
      AND a.registry_digest=NEW.registry_digest
      AND a.providers_digest=NEW.providers_digest
      AND a.state='active'
      AND a.configuration_snapshot_enabled=0
      AND a.authority='none'
      AND a.execution_enabled=0
      AND julianday(a.expires_at)>julianday(NEW.recorded_at)
      AND s.snapshot_digest=NEW.registry_snapshot_digest
      AND s.registry_id=NEW.registry_id
      AND s.registry_revision=NEW.registry_revision
      AND s.registry_digest=NEW.registry_digest
      AND s.providers_digest=NEW.providers_digest
      AND s.state='inactive'
      AND s.authority='none'
      AND s.execution_enabled=0
      AND p.receipt_digest=NEW.registry_snapshot_receipt_digest
      AND p.registry_id=NEW.registry_id
      AND p.registry_revision=NEW.registry_revision
      AND p.registry_digest=NEW.registry_digest
      AND p.providers_digest=NEW.providers_digest
      AND EXISTS (
          SELECT 1
          FROM json_each(s.snapshot_json,'$.providers') AS provider,
               json_each(provider.value,'$.models') AS model
          WHERE json_extract(provider.value,'$.provider_id')=NEW.provider_id
            AND json_extract(provider.value,'$.provider_type')=NEW.provider_type
            AND json_extract(provider.value,'$.state')='enabled'
            AND model.value=NEW.model_id
      )
      AND (
          (NEW.provider_type='approved_remote' AND NEW.secret_reference_digest IS NOT NULL)
          OR (NEW.provider_type='local_runtime' AND NEW.secret_reference_digest IS NULL)
      )
)
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot production is not current'); END;

CREATE TRIGGER ai_provider_configuration_snapshots_v1_production_required
BEFORE INSERT ON ai_provider_configuration_snapshots_v1
WHEN NOT EXISTS (
    SELECT 1
    FROM ai_provider_configuration_snapshot_productions_v1 AS p
    WHERE p.snapshot_id=NEW.snapshot_id
      AND p.snapshot_digest=NEW.snapshot_digest
      AND p.configuration_id=NEW.configuration_id
      AND p.configuration_hash=NEW.configuration_hash
      AND p.registry_id=NEW.registry_id
      AND p.registry_revision=NEW.registry_revision
      AND p.provider_type=NEW.provider_type
      AND p.provider_id=NEW.provider_id
      AND p.model_id=NEW.model_id
      AND p.recorded_at=NEW.recorded_at
      AND p.production_enabled=0
      AND p.authority='none'
      AND p.execution_enabled=0
      AND json_extract(NEW.snapshot_json,'$.secret_reference_digest')
          IS p.secret_reference_digest
)
BEGIN SELECT RAISE(ABORT,'provider configuration snapshot production is required'); END;
