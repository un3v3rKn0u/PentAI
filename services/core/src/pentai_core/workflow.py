from __future__ import annotations

import json
import re
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.database import transaction

_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$")
_TASK_KINDS = {
    "manual_checkpoint",
    "supervised_action",
    "evidence_capture",
    "report_draft",
}
_TRANSITIONS = {
    "planned": {"ready", "cancelled"},
    "ready": {"running", "cancelled"},
    "running": {"paused", "completed", "cancelled"},
    "paused": {"running", "cancelled"},
}


class WorkflowError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AssessmentWorkflowService:
    """Persist supervised workflow intent without dispatching work or granting authority."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def create(
        self,
        engagement_id: str,
        *,
        idempotency_key: str,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        _identity(actor_id, "WORKFLOW_ACTOR_REQUIRED")
        _key(idempotency_key)
        created_at = _timestamp(instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT * FROM assessment_workflows
                WHERE engagement_id = ? AND idempotency_key = ?
                """,
                (engagement_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = _workflow(existing)
                _valid(document, "assessment-workflow-v1.schema.json")
                return document
            authority = _active_authority(connection, engagement_id, instant)
            workflow_id = str(uuid4())
            document = {
                "schema_version": "1.0.0",
                "workflow_id": workflow_id,
                "engagement_id": engagement_id,
                "policy_bundle_id": authority["policy_bundle_id"],
                "idempotency_key": idempotency_key,
                "status": "planned",
                "version": 1,
                "created_at": created_at,
                "updated_at": created_at,
                "started_at": None,
                "finalized_at": None,
                "execution_enabled": False,
            }
            _valid(document, "assessment-workflow-v1.schema.json")
            connection.execute(
                """
                INSERT INTO assessment_workflows(
                    workflow_id, engagement_id, policy_bundle_id, idempotency_key,
                    status, version, created_at, updated_at, execution_enabled
                ) VALUES (?, ?, ?, ?, 'planned', 1, ?, ?, 0)
                """,
                (
                    workflow_id,
                    engagement_id,
                    authority["policy_bundle_id"],
                    idempotency_key,
                    created_at,
                    created_at,
                ),
            )
            _record(
                connection,
                action="workflow.created",
                subject_type="assessment_workflow",
                subject_id=workflow_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "engagement_id": engagement_id,
                    "policy_bundle_id": authority["policy_bundle_id"],
                    "status": "planned",
                    "version": 1,
                    "execution_enabled": False,
                },
                occurred_at=created_at,
            )
        return document

    def transition(
        self,
        workflow_id: str,
        *,
        target_status: str,
        expected_version: int,
        actor_type: str,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        _identity(actor_id, "WORKFLOW_ACTOR_REQUIRED")
        if actor_type not in {"human", "service"}:
            raise WorkflowError("WORKFLOW_ACTOR_INVALID", "workflow actor is invalid")
        if target_status == "running" and actor_type != "human":
            raise WorkflowError(
                "WORKFLOW_SUPERVISION_REQUIRED", "a human must start or resume work"
            )
        changed_at = _timestamp(instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if row is None:
                raise WorkflowError("WORKFLOW_NOT_FOUND", "assessment workflow does not exist")
            if row["version"] != expected_version:
                raise WorkflowError("WORKFLOW_FENCED", "workflow version is stale")
            if target_status not in _TRANSITIONS.get(str(row["status"]), set()):
                raise WorkflowError("WORKFLOW_TRANSITION_DENIED", "workflow transition is invalid")
            if target_status in {"ready", "running", "completed"}:
                authority = _active_authority(connection, str(row["engagement_id"]), instant)
                if authority["policy_bundle_id"] != row["policy_bundle_id"]:
                    raise WorkflowError("WORKFLOW_AUTHORITY_STALE", "workflow policy is stale")
            if target_status == "completed":
                queued = connection.execute(
                    """SELECT COUNT(*) FROM workflow_task_lifecycles l
                    JOIN workflow_tasks t ON t.task_id = l.task_id
                    WHERE t.workflow_id = ?
                      AND l.state NOT IN ('succeeded', 'dead_letter', 'cancelled')""",
                    (workflow_id,),
                ).fetchone()[0]
                if queued:
                    raise WorkflowError(
                        "WORKFLOW_TRANSITION_DENIED",
                        "queued tasks must be resolved before completion",
                    )
            version = expected_version + 1
            started_at = row["started_at"]
            if target_status == "running" and started_at is None:
                started_at = changed_at
            finalized_at = changed_at if target_status in {"completed", "cancelled"} else None
            updated = connection.execute(
                """
                UPDATE assessment_workflows
                SET status = ?, version = ?, updated_at = ?, started_at = ?, finalized_at = ?
                WHERE workflow_id = ? AND version = ? AND status = ?
                """,
                (
                    target_status,
                    version,
                    changed_at,
                    started_at,
                    finalized_at,
                    workflow_id,
                    expected_version,
                    row["status"],
                ),
            )
            if updated.rowcount != 1:
                raise WorkflowError("WORKFLOW_FENCED", "workflow version changed")
            cancelled_tasks = 0
            if target_status == "cancelled":
                cancelled_tasks = connection.execute(
                    """
                    UPDATE workflow_tasks SET state = 'cancelled', finalized_at = ?
                    WHERE workflow_id = ? AND state = 'queued'
                    """,
                    (changed_at, workflow_id),
                ).rowcount
                connection.execute(
                    """
                    UPDATE workflow_task_lifecycles
                    SET state = 'cancelled', version = version + 1,
                        lease_owner = NULL, lease_token_hash = NULL,
                        lease_expires_at = NULL, next_attempt_at = NULL,
                        updated_at = ?, finalized_at = ?
                    WHERE task_id IN (
                        SELECT task_id FROM workflow_tasks WHERE workflow_id = ?
                    ) AND state NOT IN ('succeeded', 'dead_letter', 'cancelled')
                    """,
                    (changed_at, changed_at, workflow_id),
                )
            current = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            assert current is not None
            document = _workflow(current)
            _valid(document, "assessment-workflow-v1.schema.json")
            _record(
                connection,
                action="workflow.transitioned",
                subject_type="assessment_workflow",
                subject_id=workflow_id,
                actor_type=actor_type,
                actor_id=actor_id,
                data={
                    "from_status": row["status"],
                    "to_status": target_status,
                    "version": version,
                    "cancelled_tasks": cancelled_tasks,
                    "execution_enabled": False,
                },
                occurred_at=changed_at,
            )
        return document

    def enqueue(
        self,
        workflow_id: str,
        *,
        task_kind: str,
        idempotency_key: str,
        input_refs: list[str],
        parent_task_id: str | None,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        _identity(actor_id, "WORKFLOW_ACTOR_REQUIRED")
        _key(idempotency_key)
        if task_kind not in _TASK_KINDS:
            raise WorkflowError("WORKFLOW_TASK_INVALID", "task kind is invalid")
        created_at = _timestamp(instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            workflow = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if workflow is None or workflow["status"] not in {"ready", "running"}:
                raise WorkflowError("WORKFLOW_TASK_DENIED", "workflow does not accept tasks")
            authority = _active_authority(
                connection, str(workflow["engagement_id"]), instant
            )
            if authority["policy_bundle_id"] != workflow["policy_bundle_id"]:
                raise WorkflowError("WORKFLOW_AUTHORITY_STALE", "workflow policy is stale")
            existing = connection.execute(
                """
                SELECT * FROM workflow_tasks
                WHERE workflow_id = ? AND idempotency_key = ?
                """,
                (workflow_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = _task(existing)
                _valid(document, "workflow-task-v1.schema.json")
                if (
                    document["task_kind"] != task_kind
                    or document["parent_task_id"] != parent_task_id
                    or document["input_refs"] != input_refs
                ):
                    raise WorkflowError(
                        "WORKFLOW_TASK_CONFLICT", "idempotency key is already bound"
                    )
                return document
            if parent_task_id is not None:
                parent = connection.execute(
                    """
                    SELECT state FROM workflow_tasks
                    WHERE task_id = ? AND workflow_id = ?
                    """,
                    (parent_task_id, workflow_id),
                ).fetchone()
                if parent is None or parent["state"] == "cancelled":
                    raise WorkflowError("WORKFLOW_TASK_DENIED", "parent task is unavailable")
            task_id = str(uuid4())
            document = {
                "schema_version": "1.0.0",
                "task_id": task_id,
                "workflow_id": workflow_id,
                "parent_task_id": parent_task_id,
                "task_kind": task_kind,
                "state": "queued",
                "idempotency_key": idempotency_key,
                "input_refs": input_refs,
                "created_at": created_at,
                "finalized_at": None,
                "dispatch_enabled": False,
                "external_effect_enabled": False,
            }
            _valid(document, "workflow-task-v1.schema.json")
            connection.execute(
                """
                INSERT INTO workflow_tasks(
                    task_id, workflow_id, parent_task_id, task_kind, state,
                    idempotency_key, input_refs_json, created_at, dispatch_enabled,
                    external_effect_enabled
                ) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, 0, 0)
                """,
                (
                    task_id,
                    workflow_id,
                    parent_task_id,
                    task_kind,
                    idempotency_key,
                    canonical_json(input_refs),
                    created_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO workflow_task_lifecycles(
                    task_id, state, version, attempt_count, max_attempts,
                    updated_at, dispatch_enabled, external_effect_enabled
                ) VALUES (?, 'queued', 1, 0, 3, ?, 0, 0)
                """,
                (task_id, created_at),
            )
            _record(
                connection,
                action="workflow.task_queued",
                subject_type="workflow_task",
                subject_id=task_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "workflow_id": workflow_id,
                    "task_kind": task_kind,
                    "dispatch_enabled": False,
                    "external_effect_enabled": False,
                },
                occurred_at=created_at,
            )
        return document

    def cancel_task(
        self, task_id: str, *, actor_id: str, now: datetime | None = None
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        _identity(actor_id, "WORKFLOW_ACTOR_REQUIRED")
        finalized_at = _timestamp(instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM workflow_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise WorkflowError("WORKFLOW_TASK_NOT_FOUND", "task does not exist")
            if row["state"] != "queued":
                raise WorkflowError("WORKFLOW_TASK_FINALIZED", "task is already final")
            children = connection.execute(
                """SELECT COUNT(*) FROM workflow_tasks t
                JOIN workflow_task_lifecycles l ON l.task_id = t.task_id
                WHERE t.parent_task_id = ?
                  AND l.state NOT IN ('succeeded', 'dead_letter', 'cancelled')""",
                (task_id,),
            ).fetchone()[0]
            if children:
                raise WorkflowError("WORKFLOW_TASK_DENIED", "queued child tasks exist")
            connection.execute(
                """
                UPDATE workflow_tasks SET state = 'cancelled', finalized_at = ?
                WHERE task_id = ? AND state = 'queued'
                """,
                (finalized_at, task_id),
            )
            lifecycle = connection.execute(
                "SELECT state FROM workflow_task_lifecycles WHERE task_id = ?", (task_id,)
            ).fetchone()
            if lifecycle is None or lifecycle["state"] in {"succeeded", "dead_letter"}:
                raise WorkflowError("WORKFLOW_TASK_FINALIZED", "task is already final")
            connection.execute(
                """
                UPDATE workflow_task_lifecycles
                SET state = 'cancelled', version = version + 1,
                    lease_owner = NULL, lease_token_hash = NULL,
                    lease_expires_at = NULL, next_attempt_at = NULL,
                    updated_at = ?, finalized_at = ?
                WHERE task_id = ?
                """,
                (finalized_at, finalized_at, task_id),
            )
            current = connection.execute(
                "SELECT * FROM workflow_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            assert current is not None
            document = _task(current)
            _valid(document, "workflow-task-v1.schema.json")
            _record(
                connection,
                action="workflow.task_cancelled",
                subject_type="workflow_task",
                subject_id=task_id,
                actor_type="human",
                actor_id=actor_id,
                data={"workflow_id": row["workflow_id"], "state": "cancelled"},
                occurred_at=finalized_at,
            )
        return document

    def claim_task(
        self,
        task_id: str,
        *,
        expected_version: int,
        lease_owner: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        _identity(lease_owner, "WORKFLOW_LEASE_OWNER_REQUIRED")
        if not 5 <= lease_seconds <= 300:
            raise WorkflowError("WORKFLOW_LEASE_INVALID", "lease duration is invalid")
        claimed_at = _timestamp(instant)
        expires_at = _timestamp(instant + timedelta(seconds=lease_seconds))
        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = _task_authority(connection, task_id, instant)
            if row["version"] != expected_version:
                raise WorkflowError("WORKFLOW_TASK_FENCED", "task version is stale")
            if row["state"] not in {"queued", "retry_wait"}:
                raise WorkflowError("WORKFLOW_TASK_DENIED", "task is not claimable")
            if row["next_attempt_at"] is not None:
                try:
                    retry_at = parse_time(row["next_attempt_at"])
                except (TypeError, ValueError) as exc:
                    raise WorkflowError(
                        "WORKFLOW_CONTRACT_INVALID", "retry time is malformed"
                    ) from exc
                if retry_at > instant:
                    raise WorkflowError("WORKFLOW_TASK_NOT_READY", "retry delay is active")
            if row["attempt_count"] >= row["max_attempts"]:
                raise WorkflowError("WORKFLOW_TASK_EXHAUSTED", "task attempts are exhausted")
            version = expected_version + 1
            updated = connection.execute(
                """
                UPDATE workflow_task_lifecycles
                SET state = 'leased', version = ?, attempt_count = attempt_count + 1,
                    next_attempt_at = NULL, lease_owner = ?, lease_token_hash = ?,
                    lease_expires_at = ?, last_error_code = NULL, updated_at = ?
                WHERE task_id = ? AND version = ? AND state IN ('queued', 'retry_wait')
                """,
                (
                    version,
                    lease_owner,
                    token_hash,
                    expires_at,
                    claimed_at,
                    task_id,
                    expected_version,
                ),
            )
            if updated.rowcount != 1:
                raise WorkflowError("WORKFLOW_TASK_FENCED", "task claim lost its race")
            lease = {
                "schema_version": "1.0.0",
                "task_id": task_id,
                "task_version": version,
                "lease_owner": lease_owner,
                "lease_token": token,
                "lease_expires_at": expires_at,
                "attempt_count": int(row["attempt_count"]) + 1,
                "dispatch_enabled": False,
                "external_effect_enabled": False,
            }
            _valid(lease, "workflow-task-lease-v1.schema.json")
            _record(
                connection,
                action="workflow.task_claimed",
                subject_type="workflow_task",
                subject_id=task_id,
                actor_type="service",
                actor_id=lease_owner,
                data={
                    "task_version": version,
                    "attempt_count": lease["attempt_count"],
                    "lease_expires_at": expires_at,
                    "dispatch_enabled": False,
                    "external_effect_enabled": False,
                },
                occurred_at=claimed_at,
            )
        return lease

    def heartbeat_task(
        self,
        task_id: str,
        *,
        expected_version: int,
        lease_token: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        if not 5 <= lease_seconds <= 300:
            raise WorkflowError("WORKFLOW_LEASE_INVALID", "lease duration is invalid")
        changed_at = _timestamp(instant)
        expires_at = _timestamp(instant + timedelta(seconds=lease_seconds))
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = _leased_task(connection, task_id, expected_version, lease_token, instant)
            _task_authority(connection, task_id, instant)
            version = expected_version + 1
            connection.execute(
                """
                UPDATE workflow_task_lifecycles
                SET version = ?, lease_expires_at = ?, updated_at = ?
                WHERE task_id = ? AND version = ? AND state = 'leased'
                """,
                (version, expires_at, changed_at, task_id, expected_version),
            )
            _record(
                connection,
                action="workflow.task_heartbeat",
                subject_type="workflow_task",
                subject_id=task_id,
                actor_type="service",
                actor_id=str(row["lease_owner"]),
                data={"task_version": version, "lease_expires_at": expires_at},
                occurred_at=changed_at,
            )
            current = connection.execute(
                "SELECT * FROM workflow_task_lifecycles WHERE task_id = ?", (task_id,)
            ).fetchone()
            assert current is not None
            return _validated_lifecycle(current)

    def checkpoint_task(
        self,
        task_id: str,
        *,
        expected_version: int,
        lease_token: str,
        progress: int,
        output_refs: list[str],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        created_at = _timestamp(instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = _leased_task(connection, task_id, expected_version, lease_token, instant)
            _task_authority(connection, task_id, instant)
            sequence = connection.execute(
                """SELECT COALESCE(MAX(sequence), 0) + 1
                FROM workflow_task_checkpoints WHERE task_id = ?""",
                (task_id,),
            ).fetchone()[0]
            previous = connection.execute(
                """SELECT progress FROM workflow_task_checkpoints
                WHERE task_id = ? ORDER BY sequence DESC LIMIT 1""",
                (task_id,),
            ).fetchone()
            if previous is not None and progress < int(previous["progress"]):
                raise WorkflowError(
                    "WORKFLOW_CHECKPOINT_INVALID", "checkpoint progress cannot decrease"
                )
            version = expected_version + 1
            checkpoint = {
                "schema_version": "1.0.0",
                "checkpoint_id": str(uuid4()),
                "task_id": task_id,
                "task_version": version,
                "sequence": sequence,
                "progress": progress,
                "output_refs": output_refs,
                "created_at": created_at,
            }
            _valid(checkpoint, "workflow-task-checkpoint-v1.schema.json")
            connection.execute(
                """INSERT INTO workflow_task_checkpoints(
                    checkpoint_id, task_id, task_version, sequence, progress,
                    output_refs_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    checkpoint["checkpoint_id"],
                    task_id,
                    version,
                    sequence,
                    progress,
                    canonical_json(output_refs),
                    created_at,
                ),
            )
            connection.execute(
                """UPDATE workflow_task_lifecycles SET version = ?, updated_at = ?
                WHERE task_id = ? AND version = ? AND state = 'leased'""",
                (version, created_at, task_id, expected_version),
            )
            _record(
                connection,
                action="workflow.task_checkpointed",
                subject_type="workflow_task",
                subject_id=task_id,
                actor_type="service",
                actor_id=str(row["lease_owner"]),
                data={"task_version": version, "sequence": sequence, "progress": progress},
                occurred_at=created_at,
            )
        return checkpoint

    def finalize_task(
        self,
        task_id: str,
        *,
        operation: str,
        expected_version: int,
        lease_token: str,
        idempotency_key: str,
        error_code: str | None = None,
        retry_delay_seconds: int = 0,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _trusted_time(now)
        _key(idempotency_key)
        if operation not in {"complete", "fail"}:
            raise WorkflowError("WORKFLOW_TASK_OPERATION_INVALID", "operation is invalid")
        if operation == "complete" and error_code is not None:
            raise WorkflowError("WORKFLOW_TASK_OPERATION_INVALID", "completion has an error")
        if operation == "fail" and not error_code:
            raise WorkflowError("WORKFLOW_TASK_OPERATION_INVALID", "failure code is required")
        if error_code is not None and not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", error_code):
            raise WorkflowError("WORKFLOW_TASK_OPERATION_INVALID", "failure code is invalid")
        if not 0 <= retry_delay_seconds <= 3600:
            raise WorkflowError("WORKFLOW_TASK_OPERATION_INVALID", "retry delay is invalid")
        changed_at = _timestamp(instant)
        token_hash = _token_hash(lease_token)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            receipt = connection.execute(
                """SELECT result_json, lease_token_hash FROM workflow_task_receipts
                WHERE task_id = ? AND operation = ? AND idempotency_key = ?""",
                (task_id, operation, idempotency_key),
            ).fetchone()
            if receipt is not None:
                if not secrets.compare_digest(receipt["lease_token_hash"], token_hash):
                    raise WorkflowError("WORKFLOW_TASK_CONFLICT", "receipt key is already bound")
                return cast(dict[str, Any], json.loads(receipt["result_json"]))
            row = _leased_task(connection, task_id, expected_version, lease_token, instant)
            _task_authority(connection, task_id, instant)
            exhausted = int(row["attempt_count"]) >= int(row["max_attempts"])
            if operation == "complete":
                state = "succeeded"
                next_attempt_at = None
                finalized_at = changed_at
            elif exhausted:
                state = "dead_letter"
                next_attempt_at = None
                finalized_at = changed_at
            else:
                state = "retry_wait"
                next_attempt_at = _timestamp(
                    instant + timedelta(seconds=retry_delay_seconds)
                )
                finalized_at = None
            version = expected_version + 1
            connection.execute(
                """
                UPDATE workflow_task_lifecycles
                SET state = ?, version = ?, next_attempt_at = ?, lease_owner = NULL,
                    lease_token_hash = NULL, lease_expires_at = NULL,
                    last_error_code = ?, updated_at = ?, finalized_at = ?
                WHERE task_id = ? AND version = ? AND state = 'leased'
                """,
                (
                    state,
                    version,
                    next_attempt_at,
                    error_code,
                    changed_at,
                    finalized_at,
                    task_id,
                    expected_version,
                ),
            )
            current = connection.execute(
                "SELECT * FROM workflow_task_lifecycles WHERE task_id = ?", (task_id,)
            ).fetchone()
            assert current is not None
            result = _validated_lifecycle(current)
            connection.execute(
                """INSERT INTO workflow_task_receipts(
                    receipt_id, task_id, operation, idempotency_key,
                    lease_token_hash, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(uuid4()),
                    task_id,
                    operation,
                    idempotency_key,
                    token_hash,
                    canonical_json(result),
                    changed_at,
                ),
            )
            _record(
                connection,
                action=f"workflow.task_{state}",
                subject_type="workflow_task",
                subject_id=task_id,
                actor_type="service",
                actor_id=str(row["lease_owner"]),
                data={
                    "task_version": version,
                    "state": state,
                    "attempt_count": row["attempt_count"],
                    "error_code": error_code,
                    "next_attempt_at": next_attempt_at,
                },
                occurred_at=changed_at,
            )
        return result

    def get(self, workflow_id: str) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if row is None:
                raise WorkflowError("WORKFLOW_NOT_FOUND", "assessment workflow does not exist")
            workflow = _workflow(row)
            _valid(workflow, "assessment-workflow-v1.schema.json")
            tasks = [
                _validated_task(task)
                for task in connection.execute(
                    """SELECT * FROM workflow_tasks
                    WHERE workflow_id = ? ORDER BY created_at, task_id""",
                    (workflow_id,),
                )
            ]
            lifecycles = [
                _validated_lifecycle(lifecycle)
                for lifecycle in connection.execute(
                    """SELECT l.* FROM workflow_task_lifecycles l
                    JOIN workflow_tasks t ON t.task_id = l.task_id
                    WHERE t.workflow_id = ? ORDER BY t.created_at, t.task_id""",
                    (workflow_id,),
                )
            ]
            checkpoints = [
                _validated_checkpoint(checkpoint)
                for checkpoint in connection.execute(
                    """SELECT c.* FROM workflow_task_checkpoints c
                    JOIN workflow_tasks t ON t.task_id = c.task_id
                    WHERE t.workflow_id = ? ORDER BY c.task_id, c.sequence""",
                    (workflow_id,),
                )
            ]
        return {
            "workflow": workflow,
            "tasks": tasks,
            "task_lifecycles": lifecycles,
            "checkpoints": checkpoints,
        }

    def recover_startup(self, *, now: datetime | None = None) -> int:
        instant = _trusted_time(now)
        recovered_at = _timestamp(instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            leases = connection.execute(
                "SELECT * FROM workflow_task_lifecycles WHERE state = 'leased'"
            ).fetchall()
            for lease in leases:
                exhausted = int(lease["attempt_count"]) >= int(lease["max_attempts"])
                state = "dead_letter" if exhausted else "retry_wait"
                finalized_at = recovered_at if exhausted else None
                next_attempt_at = None if exhausted else recovered_at
                connection.execute(
                    """
                    UPDATE workflow_task_lifecycles
                    SET state = ?, version = version + 1, next_attempt_at = ?,
                        lease_owner = NULL, lease_token_hash = NULL,
                        lease_expires_at = NULL, last_error_code = 'LEASE_RECOVERED',
                        updated_at = ?, finalized_at = ?
                    WHERE task_id = ? AND state = 'leased' AND version = ?
                    """,
                    (
                        state,
                        next_attempt_at,
                        recovered_at,
                        finalized_at,
                        lease["task_id"],
                        lease["version"],
                    ),
                )
                _record(
                    connection,
                    action="workflow.task_lease_recovered",
                    subject_type="workflow_task",
                    subject_id=lease["task_id"],
                    actor_type="service",
                    actor_id="startup-recovery",
                    data={
                        "from_state": "leased",
                        "to_state": state,
                        "task_version": int(lease["version"]) + 1,
                        "automatic_claim": False,
                    },
                    occurred_at=recovered_at,
                )
            rows = connection.execute(
                "SELECT * FROM assessment_workflows WHERE status = 'running'"
            ).fetchall()
            for row in rows:
                version = int(row["version"]) + 1
                connection.execute(
                    """
                    UPDATE assessment_workflows
                    SET status = 'paused', version = ?, updated_at = ?, finalized_at = NULL
                    WHERE workflow_id = ? AND status = 'running' AND version = ?
                    """,
                    (version, recovered_at, row["workflow_id"], row["version"]),
                )
                _record(
                    connection,
                    action="workflow.recovered_paused",
                    subject_type="assessment_workflow",
                    subject_id=row["workflow_id"],
                    actor_type="service",
                    actor_id="startup-recovery",
                    data={
                        "from_status": "running",
                        "to_status": "paused",
                        "version": version,
                        "automatic_resume": False,
                        "execution_enabled": False,
                    },
                    occurred_at=recovered_at,
                )
        return len(rows)


def _active_authority(
    connection: sqlite3.Connection, engagement_id: str, instant: datetime
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT e.active_policy_id AS policy_bundle_id, e.status,
               e.expires_at, p.activated_at, p.revoked_at, s.global_status
        FROM engagements e
        LEFT JOIN policy_bundles p ON p.id = e.active_policy_id
        CROSS JOIN safety_state s
        WHERE e.id = ?
        """,
        (engagement_id,),
    ).fetchone()
    try:
        inactive = (
            row is None
            or row["policy_bundle_id"] is None
            or row["status"] != "active"
            or row["activated_at"] is None
            or row["revoked_at"] is not None
            or row["global_status"] != "active"
            or parse_time(row["expires_at"]) <= instant
        )
    except (TypeError, ValueError):
        inactive = True
    if inactive:
        raise WorkflowError("WORKFLOW_AUTHORITY_DENIED", "workflow authority is inactive")
    return cast(sqlite3.Row, row)


def _task_authority(
    connection: sqlite3.Connection, task_id: str, instant: datetime
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT l.*, t.workflow_id, w.status AS workflow_status,
               w.engagement_id, w.policy_bundle_id
        FROM workflow_task_lifecycles l
        JOIN workflow_tasks t ON t.task_id = l.task_id
        JOIN assessment_workflows w ON w.workflow_id = t.workflow_id
        WHERE l.task_id = ?
        """,
        (task_id,),
    ).fetchone()
    if row is None:
        raise WorkflowError("WORKFLOW_TASK_NOT_FOUND", "task does not exist")
    if row["workflow_status"] != "running":
        raise WorkflowError("WORKFLOW_TASK_DENIED", "workflow is not running")
    authority = _active_authority(connection, str(row["engagement_id"]), instant)
    if authority["policy_bundle_id"] != row["policy_bundle_id"]:
        raise WorkflowError("WORKFLOW_AUTHORITY_STALE", "workflow policy is stale")
    return cast(sqlite3.Row, row)


def _leased_task(
    connection: sqlite3.Connection,
    task_id: str,
    expected_version: int,
    lease_token: str,
    instant: datetime,
) -> sqlite3.Row:
    if len(lease_token) < 32 or len(lease_token) > 128:
        raise WorkflowError("WORKFLOW_LEASE_INVALID", "lease token is invalid")
    row = connection.execute(
        "SELECT * FROM workflow_task_lifecycles WHERE task_id = ?", (task_id,)
    ).fetchone()
    if row is None:
        raise WorkflowError("WORKFLOW_TASK_NOT_FOUND", "task does not exist")
    if row["version"] != expected_version:
        raise WorkflowError("WORKFLOW_TASK_FENCED", "task version is stale")
    if row["state"] != "leased" or row["lease_token_hash"] is None:
        raise WorkflowError("WORKFLOW_LEASE_DENIED", "task has no active lease")
    if not secrets.compare_digest(str(row["lease_token_hash"]), _token_hash(lease_token)):
        raise WorkflowError("WORKFLOW_LEASE_DENIED", "lease token does not match")
    try:
        expired = parse_time(row["lease_expires_at"]) <= instant
    except (TypeError, ValueError) as exc:
        raise WorkflowError("WORKFLOW_CONTRACT_INVALID", "lease expiry is malformed") from exc
    if expired:
        raise WorkflowError("WORKFLOW_LEASE_EXPIRED", "task lease has expired")
    return cast(sqlite3.Row, row)


def _token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _workflow(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "workflow_id": row["workflow_id"],
        "engagement_id": row["engagement_id"],
        "policy_bundle_id": row["policy_bundle_id"],
        "idempotency_key": row["idempotency_key"],
        "status": row["status"],
        "version": row["version"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "started_at": row["started_at"],
        "finalized_at": row["finalized_at"],
        "execution_enabled": False,
    }


def _task(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "task_id": row["task_id"],
        "workflow_id": row["workflow_id"],
        "parent_task_id": row["parent_task_id"],
        "task_kind": row["task_kind"],
        "state": row["state"],
        "idempotency_key": row["idempotency_key"],
        "input_refs": json.loads(row["input_refs_json"]),
        "created_at": row["created_at"],
        "finalized_at": row["finalized_at"],
        "dispatch_enabled": False,
        "external_effect_enabled": False,
    }


def _validated_task(row: sqlite3.Row) -> dict[str, Any]:
    document = _task(row)
    _valid(document, "workflow-task-v1.schema.json")
    return document


def _lifecycle(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "task_id": row["task_id"],
        "state": row["state"],
        "version": row["version"],
        "attempt_count": row["attempt_count"],
        "max_attempts": row["max_attempts"],
        "next_attempt_at": row["next_attempt_at"],
        "lease_owner": row["lease_owner"],
        "lease_expires_at": row["lease_expires_at"],
        "last_error_code": row["last_error_code"],
        "updated_at": row["updated_at"],
        "finalized_at": row["finalized_at"],
        "dispatch_enabled": False,
        "external_effect_enabled": False,
    }


def _validated_lifecycle(row: sqlite3.Row) -> dict[str, Any]:
    document = _lifecycle(row)
    _valid(document, "workflow-task-lifecycle-v1.schema.json")
    return document


def _validated_checkpoint(row: sqlite3.Row) -> dict[str, Any]:
    document = {
        "schema_version": "1.0.0",
        "checkpoint_id": row["checkpoint_id"],
        "task_id": row["task_id"],
        "task_version": row["task_version"],
        "sequence": row["sequence"],
        "progress": row["progress"],
        "output_refs": json.loads(row["output_refs_json"]),
        "created_at": row["created_at"],
    }
    _valid(document, "workflow-task-checkpoint-v1.schema.json")
    return document


def _record(
    connection: sqlite3.Connection,
    *,
    action: str,
    subject_type: str,
    subject_id: str,
    actor_type: str,
    actor_id: str,
    data: dict[str, Any],
    occurred_at: str,
) -> None:
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else None
    event = {
        "event_id": str(uuid4()),
        "occurred_at": occurred_at,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "data": data,
        "previous_hash": previous_hash,
    }
    event_hash = content_hash(event)
    connection.execute(
        """
        INSERT INTO audit_events(
            event_id, occurred_at, actor_type, actor_id, action, subject_type,
            subject_id, data_json, previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["event_id"],
            occurred_at,
            actor_type,
            actor_id,
            action,
            subject_type,
            subject_id,
            canonical_json(data),
            previous_hash,
            event_hash,
        ),
    )
    connection.execute(
        """
        INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            str(uuid4()),
            subject_type,
            subject_id,
            action,
            canonical_json(
                {
                    "event_hash": event_hash,
                    "occurred_at": occurred_at,
                    "subject_id": subject_id,
                }
            ),
        ),
    )


def _valid(document: dict[str, Any], schema: str) -> None:
    if contract_issues(document, schema):
        raise WorkflowError("WORKFLOW_CONTRACT_INVALID", "workflow contract is invalid")


def _trusted_time(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise WorkflowError("WORKFLOW_CLOCK_INVALID", "workflow clock is untrusted")
    return instant


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _identity(value: str, code: str) -> None:
    if not value.strip() or len(value) > 128:
        raise WorkflowError(code, "workflow identity is invalid")


def _key(value: str) -> None:
    if not _KEY.fullmatch(value):
        raise WorkflowError("WORKFLOW_IDEMPOTENCY_INVALID", "idempotency key is invalid")
