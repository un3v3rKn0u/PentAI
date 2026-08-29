DROP TRIGGER orchestration_task_completions_v3_producer_disabled;

CREATE TRIGGER orchestration_task_completions_v3_current_binding
BEFORE INSERT ON orchestration_task_completions_v3
WHEN NOT EXISTS (
  SELECT 1
  FROM orchestration_task_lease_consumptions_v3 c
  JOIN orchestration_tasks t ON t.plan_id=c.plan_id AND t.task_id=c.task_id
  JOIN orchestration_plans p ON p.plan_id=c.plan_id AND p.assessment_id=c.assessment_id
  JOIN worker_runtime_instances w
    ON w.worker_id=json_extract(c.receipt_json,'$.worker_id')
  JOIN orchestration_task_lease_fences f ON f.task_id=c.task_id
  JOIN task_capability_manifests_v4 m
    ON m.manifest_id=json_extract(c.receipt_json,'$.capability_manifest_id')
  JOIN orchestration_task_budget_reservations_v4 b
    ON b.reservation_id=json_extract(c.receipt_json,'$.budget_reservation_id')
  JOIN orchestration_budget_accounts a ON a.account_id=b.account_id
  JOIN engagements e ON e.id=c.assessment_id
  LEFT JOIN orchestration_task_checkpoints_v3 k ON k.checkpoint_id=NEW.checkpoint_id
  WHERE c.consumption_id=NEW.lease_consumption_id
    AND c.assessment_id=NEW.assessment_id AND c.plan_id=NEW.plan_id
    AND c.resulting_plan_revision=NEW.expected_plan_revision
    AND c.task_id=NEW.task_id AND c.resulting_task_revision=NEW.expected_task_revision
    AND json_extract(c.receipt_json,'$.schema_version')='3.0.0'
    AND json_extract(c.receipt_json,'$.attempt_number')=3
    AND json_extract(NEW.receipt_json,'$.lease_consumption_digest')='sha256:'||c.receipt_hash
    AND json_extract(NEW.receipt_json,'$.retry_attempt_id')=
        json_extract(c.receipt_json,'$.retry_attempt_id')
    AND t.state='running' AND t.revision=NEW.expected_task_revision
    AND p.state='active' AND p.revision=NEW.expected_plan_revision
    AND e.status='active' AND e.active_policy_id=json_extract(NEW.receipt_json,'$.policy_bundle_id')
    AND w.status='running' AND w.execution_enabled=0
    AND w.version=json_extract(NEW.receipt_json,'$.worker_version')
    AND f.current_lease_generation=json_extract(NEW.receipt_json,'$.lease_generation')
    AND f.recovery_generation=json_extract(NEW.receipt_json,'$.recovery_generation')
    AND m.manifest_hash=substr(json_extract(NEW.receipt_json,'$.capability_manifest_digest'),8)
    AND b.request_digest=json_extract(NEW.receipt_json,'$.budget_request_digest')
    AND b.state='reserved'
    AND b.account_version=json_extract(NEW.receipt_json,'$.budget_account_version')
    AND a.version=b.account_version
    AND (SELECT global_status FROM safety_state WHERE singleton_id=1)='active'
    AND ((NEW.checkpoint_id IS NULL
      AND json_extract(NEW.receipt_json,'$.checkpoint_sequence') IS NULL
      AND json_extract(NEW.receipt_json,'$.checkpoint_digest') IS NULL
      AND NOT EXISTS (SELECT 1 FROM orchestration_task_checkpoints_v3 h
        WHERE h.task_id=NEW.task_id AND h.task_revision=NEW.expected_task_revision))
     OR (k.task_id=NEW.task_id AND k.task_revision=NEW.expected_task_revision
      AND json_extract(k.receipt_json,'$.schema_version')='3.0.0'
      AND k.sequence=json_extract(NEW.receipt_json,'$.checkpoint_sequence')
      AND k.checkpoint_digest=json_extract(NEW.receipt_json,'$.checkpoint_digest')
      AND NOT EXISTS (SELECT 1 FROM orchestration_task_checkpoints_v3 h
        WHERE h.task_id=NEW.task_id AND h.task_revision=NEW.expected_task_revision
          AND h.sequence>k.sequence)))
)
BEGIN SELECT RAISE(ABORT,'attempt-three completion current binding is invalid'); END;

CREATE TRIGGER orchestration_attempt_three_completion_required
BEFORE UPDATE ON orchestration_tasks
WHEN OLD.state='running' AND NEW.state='succeeded'
 AND EXISTS (
   SELECT 1 FROM orchestration_retry_attempts_v2 a
   WHERE a.task_id=OLD.task_id AND a.attempt_number=3
 )
 AND NOT EXISTS (
   SELECT 1 FROM orchestration_task_completions_v3 c
   WHERE c.plan_id=OLD.plan_id AND c.task_id=OLD.task_id
     AND c.assessment_id=OLD.assessment_id
     AND c.expected_plan_revision=(SELECT revision FROM orchestration_plans
       WHERE plan_id=OLD.plan_id)
     AND c.resulting_plan_revision=(SELECT revision+1 FROM orchestration_plans
       WHERE plan_id=OLD.plan_id)
     AND c.expected_task_revision=OLD.revision
     AND c.resulting_task_revision=NEW.revision
     AND json_extract(c.receipt_json,'$.schema_version')='3.0.0'
     AND json_extract(c.receipt_json,'$.attempt_number')=3
     AND json_extract(c.receipt_json,'$.resulting_task_state')='succeeded'
     AND c.authority='none' AND c.execution_enabled=0
 )
BEGIN SELECT RAISE(ABORT,'attempt-three completion receipt is required'); END;
