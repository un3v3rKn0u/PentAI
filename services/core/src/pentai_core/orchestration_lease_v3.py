from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.audit import append_audit_event
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction

_MAX_REQUEST_AGE = timedelta(minutes=1)
_MAX_LEASE_LIFETIME = timedelta(minutes=5)
_NAMESPACE = UUID("43c54f79-c0cc-478e-83ea-31eecc0442c4")


class OrchestrationLeaseV3Error(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationLeaseV3Service:
    """Attempt-three coordination ownership without dispatch or execution authority."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def acquire(
        self, request: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(request)
        if contract_issues(document, "orchestration-task-lease-acquire-v3.schema.json"):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_REQUEST_MALFORMED", "lease request is malformed"
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        if requested_at > instant or instant - requested_at > _MAX_REQUEST_AGE:
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_REQUEST_STALE", "lease request is stale"
            )
        request_digest = "sha256:" + content_hash(document)
        lease_id = str(uuid5(_NAMESPACE, "lease-v3:" + document["request_id"]))
        self.authorization._require_storage_safe()
        verified = self._verified_policy(document, instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT request_digest FROM orchestration_task_leases_v3 WHERE request_id=?",
                (document["request_id"],),
            ).fetchone()
            if replay is not None:
                code = (
                    "ORCHESTRATION_LEASE_V3_ACQUIRE_REPLAY_DENIED"
                    if replay["request_digest"] == request_digest
                    else "ORCHESTRATION_LEASE_V3_IDENTITY_CONFLICT"
                )
                raise OrchestrationLeaseV3Error(code, "lease acquisition cannot be replayed")
            if connection.execute(
                """SELECT 1 FROM orchestration_task_leases_v3
                WHERE task_id=? AND task_revision=? AND state='active'""",
                (document["task_id"], document["expected_task_revision"]),
            ).fetchone() or connection.execute(
                """SELECT 1 FROM orchestration_task_leases
                WHERE task_id=? AND task_revision=? AND state='active'""",
                (document["task_id"], document["expected_task_revision"]),
            ).fetchone():
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_CONFLICT", "task already has an active lease"
                )
            security = self._validate_current(connection, document, instant)
            fence = connection.execute(
                "SELECT * FROM orchestration_task_lease_fences WHERE task_id=?",
                (document["task_id"],),
            ).fetchone()
            if (
                fence is None
                or fence["recovery_generation"] != document["expected_recovery_generation"]
            ):
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_RECOVERY_FENCED", "recovery generation is stale"
                )
            lease_generation = int(fence["current_lease_generation"]) + 1
            connection.execute(
                """UPDATE orchestration_task_lease_fences
                SET current_lease_generation=?, version=version+1, updated_at=?
                WHERE task_id=? AND version=?""",
                (
                    lease_generation,
                    _timestamp(instant),
                    document["task_id"],
                    fence["version"],
                ),
            )
            maximum_expiry = min(
                instant + _MAX_LEASE_LIFETIME,
                parse_time(security["engagement"]["expires_at"]),
                parse_time(verified["policy"]["validity"]["not_after"]),
                parse_time(security["manifest"]["expires_at"]),
                parse_time(security["budget"]["expires_at"]),
                *(
                    [parse_time(security["approval"]["approval_expires_at"])]
                    if security["approval"] is not None
                    else []
                ),
            )
            expires_at = min(
                instant + timedelta(seconds=document["lease_seconds"]), maximum_expiry
            )
            if expires_at <= instant:
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_EXPIRY_INVALID", "lease validity is empty"
                )
            raw_token = secrets.token_urlsafe(32)
            state = _state(
                document,
                lease_id=lease_id,
                request_digest=request_digest,
                lease_generation=lease_generation,
                recovery_generation=fence["recovery_generation"],
                acquired_at=_timestamp(instant),
                expires_at=_timestamp(expires_at),
                maximum_expires_at=_timestamp(maximum_expiry),
            )
            if contract_issues(state, "orchestration-task-lease-state-v3.schema.json"):
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_RESULT_INVALID", "lease state is invalid"
                )
            try:
                connection.execute(
                    """INSERT INTO orchestration_task_leases_v3 (
                    lease_id, request_id, request_digest, assessment_id, plan_id,
                    plan_revision, task_id, task_revision, agent_id, capability_manifest_id,
                    budget_reservation_id, retry_activation_id, retry_attempt_id,
                    policy_bundle_id, policy_hash, worker_id, worker_version, token_hash,
                    recovery_generation, lease_generation, fencing_token, lease_version,
                    state, acquired_at, expires_at, maximum_expires_at, released_at,
                    release_reason, purpose, state_json, state_hash, authority,
                    execution_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, 1, 'active', ?, ?, ?, NULL, 'none', ?, ?, ?, 'none', 0)""",
                    (
                        lease_id,
                        document["request_id"],
                        request_digest,
                        document["assessment_id"],
                        document["plan_id"],
                        document["expected_plan_revision"],
                        document["task_id"],
                        document["expected_task_revision"],
                        document["agent_id"],
                        document["capability_manifest_id"],
                        document["budget_reservation_id"],
                        document["retry_activation_id"],
                        document["retry_attempt_id"],
                        document["policy_bundle_id"],
                        document["policy_hash"],
                        document["worker_id"],
                        document["expected_worker_version"],
                        _token_hash(raw_token),
                        fence["recovery_generation"],
                        lease_generation,
                        lease_generation,
                        state["acquired_at"],
                        state["expires_at"],
                        state["maximum_expires_at"],
                        document["purpose"],
                        canonical_json(state),
                        content_hash(state),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_CONFLICT", "lease storage conflicts"
                ) from error
            self._record_event(
                connection,
                command_id=document["request_id"],
                command_digest=request_digest,
                state=state,
                event_type="acquired",
                previous_version=0,
                reason="acquired",
                instant=instant,
            )
        return {**copy.deepcopy(state), "lease_token": raw_token}

    def consume(
        self, command: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        """Consume exact attempt-three ownership into non-authoritative running state."""
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-task-lease-consumption-v3.schema.json"):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_CONSUMPTION_MALFORMED",
                "lease consumption is malformed",
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        if requested_at > instant or instant - requested_at > _MAX_REQUEST_AGE:
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_CONSUMPTION_STALE",
                "lease consumption is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        consumption_id = str(uuid5(_NAMESPACE, "consumption-v3:" + document["command_id"]))
        self.authorization._require_storage_safe()
        self._verified_policy(document, instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest, receipt_json, receipt_hash
                FROM orchestration_task_lease_consumptions_v3 WHERE command_id=?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationLeaseV3Error(
                        "ORCHESTRATION_LEASE_V3_CONSUMPTION_IDENTITY_CONFLICT",
                        "consumption identity conflicts",
                    )
                receipt = cast(dict[str, Any], json.loads(replay["receipt_json"]))
                self._validate_consumption_replay(connection, receipt, replay, instant)
                return receipt
            row = connection.execute(
                "SELECT * FROM orchestration_task_leases_v3 WHERE lease_id=?",
                (document["lease_id"],),
            ).fetchone()
            if row is None:
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_MISSING", "lease is missing"
                )
            if connection.execute(
                "SELECT 1 FROM orchestration_task_lease_consumptions_v3 WHERE lease_id=?",
                (document["lease_id"],),
            ).fetchone():
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_ALREADY_CONSUMED", "lease is already consumed"
                )
            state = self._load_state(row)
            expected = {
                "assessment_id": state["assessment_id"],
                "plan_id": state["plan_id"],
                "expected_plan_revision": state["plan_revision"],
                "task_id": state["task_id"],
                "expected_task_revision": state["task_revision"],
                "agent_id": state["agent_id"],
                "capability_manifest_id": state["capability_manifest_id"],
                "capability_manifest_digest": state["capability_manifest_digest"],
                "manifest_revision": state["manifest_revision"],
                "budget_reservation_id": state["budget_reservation_id"],
                "budget_request_digest": state["budget_request_digest"],
                "budget_account_version": state["budget_account_version"],
                "retry_policy_id": state["retry_policy_id"],
                "retry_policy_digest": state["retry_policy_digest"],
                "retry_activation_id": state["retry_activation_id"],
                "retry_activation_digest": state["retry_activation_digest"],
                "retry_schedule_id": state["retry_schedule_id"],
                "retry_schedule_digest": state["retry_schedule_digest"],
                "retry_attempt_id": state["retry_attempt_id"],
                "retry_attempt_digest": state["retry_attempt_digest"],
                "attempt_number": 3,
                "prior_retry_budget_consumption_id": state[
                    "prior_retry_budget_consumption_id"
                ],
                "retry_budget_consumption_id": state["retry_budget_consumption_id"],
                "approval_consumption_id": state["approval_consumption_id"],
                "policy_bundle_id": state["policy_bundle_id"],
                "policy_hash": state["policy_hash"],
                "worker_id": state["worker_id"],
                "expected_worker_version": state["worker_version"],
                "expected_lease_version": state["lease_version"],
                "lease_generation": state["lease_generation"],
                "fencing_token": state["fencing_token"],
                "expected_recovery_generation": state["recovery_generation"],
            }
            if any(document[key] != value for key, value in expected.items()):
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_CONSUMPTION_BINDING_MISMATCH",
                    "lease consumption binding mismatches",
                )
            state_digest = "sha256:" + content_hash(state)
            if document["lease_state_digest"] != state_digest:
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_STATE_TAMPERED", "lease state mismatches"
                )
            if row["state"] != "active" or parse_time(row["expires_at"]) <= instant:
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_NOT_ACTIVE", "lease is not current"
                )
            if not hmac.compare_digest(
                row["token_hash"], _token_hash(document["lease_token"])
            ):
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_TOKEN_MISMATCH", "holder proof mismatches"
                )
            self._validate_current(connection, document, instant)
            fence = connection.execute(
                "SELECT * FROM orchestration_task_lease_fences WHERE task_id=?",
                (document["task_id"],),
            ).fetchone()
            if (
                fence is None
                or fence["current_lease_generation"] != document["lease_generation"]
                or fence["recovery_generation"]
                != document["expected_recovery_generation"]
            ):
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_CONSUMPTION_FENCED", "lease fence is stale"
                )
            receipt = _consumption_receipt(
                document,
                state,
                consumption_id=consumption_id,
                command_digest=command_digest,
                consumed_at=_timestamp(instant),
            )
            if contract_issues(
                receipt, "orchestration-task-lease-consumption-receipt-v3.schema.json"
            ):
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_CONSUMPTION_RESULT_INVALID",
                    "lease consumption result is invalid",
                )
            connection.execute(
                """INSERT INTO orchestration_task_lease_consumptions_v3 VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                (
                    consumption_id,
                    document["command_id"],
                    command_digest,
                    state["assessment_id"],
                    state["plan_id"],
                    state["plan_revision"],
                    receipt["resulting_plan_revision"],
                    state["task_id"],
                    state["task_revision"],
                    receipt["resulting_task_revision"],
                    state["lease_id"],
                    state["lease_generation"],
                    state["fencing_token"],
                    state["recovery_generation"],
                    canonical_json(receipt),
                    content_hash(receipt),
                    receipt["consumed_at"],
                ),
            )
            task_update = connection.execute(
                """UPDATE orchestration_tasks SET state='running', revision=revision+1,
                updated_at=? WHERE plan_id=? AND task_id=? AND state='ready' AND revision=?""",
                (
                    receipt["consumed_at"],
                    state["plan_id"],
                    state["task_id"],
                    state["task_revision"],
                ),
            )
            plan_update = connection.execute(
                """UPDATE orchestration_plans SET revision=revision+1, updated_at=?
                WHERE plan_id=? AND state='active' AND revision=?""",
                (receipt["consumed_at"], state["plan_id"], state["plan_revision"]),
            )
            if task_update.rowcount != 1 or plan_update.rowcount != 1:
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_CONSUMPTION_CONFLICT",
                    "coordination revisions conflict",
                )
            audit = append_audit_event(
                connection,
                action="orchestration.attempt_three_task_lease_consumed",
                subject_type="orchestration_task_lease",
                subject_id=state["lease_id"],
                actor_type="service",
                actor_id="pentai-core",
                data={
                    "consumption_id": consumption_id,
                    "lease_id": state["lease_id"],
                    "resulting_task_state": "running",
                    "consumed_at": receipt["consumed_at"],
                    "authority": "none",
                    "execution_enabled": False,
                },
                occurred_at=receipt["consumed_at"],
            )
            connection.execute(
                """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type,
                payload_json) VALUES (?, 'orchestration_task_lease', ?,
                'orchestration.attempt_three_task_lease_consumed', ?)""",
                (
                    str(uuid4()),
                    state["lease_id"],
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": receipt["consumed_at"],
                            "subject_id": state["lease_id"],
                        }
                    ),
                ),
            )
        return receipt

    def recover(self, *, now: datetime | None = None) -> tuple[dict[str, Any], ...]:
        instant = _instant(now)
        events: list[dict[str, Any]] = []
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT * FROM orchestration_task_leases_v3 l WHERE state='active'
                AND NOT EXISTS (SELECT 1 FROM orchestration_task_lease_consumptions_v3 c
                    WHERE c.lease_id=l.lease_id) ORDER BY lease_id"""
            ).fetchall()
            for row in rows:
                state = self._load_state(row)
                fence = connection.execute(
                    "SELECT * FROM orchestration_task_lease_fences WHERE task_id=?",
                    (row["task_id"],),
                ).fetchone()
                if fence is None:
                    raise OrchestrationLeaseV3Error(
                        "ORCHESTRATION_LEASE_V3_RECOVERY_INVALID", "lease fence is missing"
                    )
                recovery_generation = int(fence["recovery_generation"]) + 1
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=?, version=version+1, updated_at=?
                    WHERE task_id=? AND version=?""",
                    (
                        recovery_generation,
                        _timestamp(instant),
                        row["task_id"],
                        fence["version"],
                    ),
                )
                state["lease_version"] = int(row["lease_version"]) + 1
                expired = parse_time(row["expires_at"]) <= instant
                state["state"] = "expired" if expired else "invalidated"
                state["released_at"] = _timestamp(instant)
                state["release_reason"] = "expired" if expired else "recovery"
                if contract_issues(state, "orchestration-task-lease-state-v3.schema.json"):
                    raise OrchestrationLeaseV3Error(
                        "ORCHESTRATION_LEASE_V3_RECOVERY_INVALID", "lease state is invalid"
                    )
                connection.execute(
                    """UPDATE orchestration_task_leases_v3 SET lease_version=?, state=?,
                    released_at=?, release_reason=?, state_json=?, state_hash=?
                    WHERE lease_id=? AND lease_version=? AND state='active'""",
                    (
                        state["lease_version"],
                        state["state"],
                        state["released_at"],
                        state["release_reason"],
                        canonical_json(state),
                        content_hash(state),
                        row["lease_id"],
                        row["lease_version"],
                    ),
                )
                events.append(
                    self._record_event(
                        connection,
                        command_id=str(
                            uuid5(
                                _NAMESPACE,
                                f"recovery:{row['lease_id']}:{recovery_generation}",
                            )
                        ),
                        command_digest="sha256:"
                        + content_hash(
                            {
                                "lease_id": row["lease_id"],
                                "recovery_generation": recovery_generation,
                            }
                        ),
                        state=state,
                        event_type="expired" if expired else "invalidated",
                        previous_version=int(row["lease_version"]),
                        reason=state["release_reason"],
                        instant=instant,
                    )
                )
        return tuple(events)

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id=?", (document["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id=?", (document["plan_id"],)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id=? AND task_id=?",
            (document["plan_id"], document["task_id"]),
        ).fetchone()
        if (
            engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != document["policy_bundle_id"]
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_SAFETY_DENIED", "assessment safety denies"
            )
        if (
            plan is None
            or plan["assessment_id"] != document["assessment_id"]
            or (plan["state"], plan["revision"])
            != ("active", document["expected_plan_revision"])
            or task is None
            or task["assessment_id"] != document["assessment_id"]
            or (task["state"], task["revision"])
            != ("ready", document["expected_task_revision"])
            or task["task_type"] != "validation"
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_TASK_FENCED", "task is not current and ready"
            )
        manifest_row = connection.execute(
            "SELECT * FROM task_capability_manifests_v4 WHERE manifest_id=?",
            (document["capability_manifest_id"],),
        ).fetchone()
        budget_row = connection.execute(
            "SELECT * FROM orchestration_task_budget_reservations_v4 WHERE reservation_id=?",
            (document["budget_reservation_id"],),
        ).fetchone()
        if manifest_row is None or budget_row is None:
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_PREREQUISITE_MISSING", "prerequisite is missing"
            )
        manifest = cast(dict[str, Any], json.loads(manifest_row["manifest_json"]))
        budget = cast(dict[str, Any], json.loads(budget_row["receipt_json"]))
        if (
            contract_issues(manifest, "task-capability-manifest-v4.schema.json")
            or content_hash(manifest) != manifest_row["manifest_hash"]
            or contract_issues(budget, "orchestration-task-budget-reservation-v4.schema.json")
            or budget_row["receipt_json"] != canonical_json(budget)
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_PREREQUISITE_INVALID", "prerequisite is invalid"
            )
        exact_fields = {
            "assessment_id": "assessment_id",
            "plan_id": "plan_id",
            "task_id": "task_id",
            "agent_id": "agent_id",
            "capability_manifest_id": "capability_manifest_id",
            "capability_manifest_digest": "capability_manifest_digest",
            "retry_policy_id": "retry_policy_id",
            "retry_policy_digest": "retry_policy_digest",
            "retry_activation_id": "retry_activation_id",
            "retry_activation_digest": "retry_activation_digest",
            "retry_schedule_id": "retry_schedule_id",
            "retry_schedule_digest": "retry_schedule_digest",
            "retry_attempt_id": "retry_attempt_id",
            "retry_attempt_digest": "retry_attempt_digest",
            "attempt_number": "attempt_number",
            "prior_retry_budget_consumption_id": "prior_retry_budget_consumption_id",
            "retry_budget_consumption_id": "retry_budget_consumption_id",
            "approval_consumption_id": "approval_consumption_id",
            "policy_bundle_id": "policy_bundle_id",
            "policy_hash": "policy_hash",
        }
        exact = all(
            budget.get(receipt_field) == document.get(command_field)
            for receipt_field, command_field in exact_fields.items()
        ) and all(
            manifest.get(field) == budget.get(field)
            for field in (
                "assessment_id", "plan_id", "plan_revision", "task_id", "task_revision",
                "agent_id", "policy_bundle_id", "policy_hash", "retry_policy_id",
                "retry_policy_digest", "retry_activation_id", "retry_activation_digest",
                "retry_schedule_id", "retry_schedule_digest", "retry_attempt_id",
                "retry_attempt_digest", "attempt_number", "prior_retry_budget_consumption_id",
                "retry_budget_consumption_id", "approval_consumption_id", "worker_id",
                "worker_version", "lease_generation", "fencing_token", "recovery_generation",
            )
        )
        account = connection.execute(
            "SELECT version FROM orchestration_budget_accounts WHERE account_id=?",
            (budget["account_id"],),
        ).fetchone()
        if (
            not exact
            or manifest["manifest_id"] != document["capability_manifest_id"]
            or manifest_row["manifest_hash"] != document["capability_manifest_digest"][7:]
            or manifest["manifest_revision"] != document["manifest_revision"]
            or budget["reservation_id"] != document["budget_reservation_id"]
            or budget["request_digest"] != document["budget_request_digest"]
            or budget["account_version"] != document["budget_account_version"]
            or budget["plan_revision"] != document["expected_plan_revision"]
            or budget["task_revision"] != document["expected_task_revision"]
            or budget["state"] != "reserved"
            or budget["amounts"]["retries"] != 0
            or account is None
            or account["version"] != document["budget_account_version"]
            or parse_time(manifest["expires_at"]) <= instant
            or parse_time(budget["expires_at"]) <= instant
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_PREREQUISITE_MISMATCH",
                "prerequisite binding mismatches",
            )
        approval = None
        if task["requires_human_approval"]:
            if document["approval_consumption_id"] is None:
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_APPROVAL_REQUIRED", "approval is required"
                )
            approval = connection.execute(
                """SELECT * FROM orchestration_task_approval_consumptions
                WHERE consumption_id=?""",
                (document["approval_consumption_id"],),
            ).fetchone()
            if (
                approval is None
                or approval["assessment_id"] != document["assessment_id"]
                or approval["plan_id"] != document["plan_id"]
                or approval["task_id"] != document["task_id"]
                or approval["policy_bundle_id"] != document["policy_bundle_id"]
                or approval["policy_hash"] != document["policy_hash"]
                or parse_time(approval["approval_expires_at"]) <= instant
            ):
                raise OrchestrationLeaseV3Error(
                    "ORCHESTRATION_LEASE_V3_APPROVAL_INVALID", "approval is invalid"
                )
        elif document["approval_consumption_id"] is not None:
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_APPROVAL_AMBIGUOUS", "approval is not required"
            )
        worker = connection.execute(
            "SELECT * FROM worker_runtime_instances WHERE worker_id=?",
            (document["worker_id"],),
        ).fetchone()
        if (
            worker is None
            or document["worker_id"] != budget["worker_id"]
            or document["expected_worker_version"] != budget["worker_version"]
            or worker["status"] != "running"
            or worker["version"] != document["expected_worker_version"]
            or worker["execution_enabled"] != 0
            or worker["container_id"] is None
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_WORKER_INELIGIBLE", "worker is ineligible"
            )
        return {
            "engagement": engagement,
            "manifest": manifest,
            "budget": budget,
            "approval": approval,
        }

    def _verified_policy(
        self, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        try:
            verified = self.authorization.get_policy(
                document["assessment_id"], document["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_POLICY_INVALID", "policy is invalid"
            ) from error
        if (
            verified["status"] != "active"
            or verified["content_hash"] != document["policy_hash"]
            or parse_time(verified["policy"]["validity"]["not_after"]) <= instant
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_POLICY_STALE", "policy is stale"
            )
        return verified

    def _validate_consumption_replay(
        self,
        connection: sqlite3.Connection,
        receipt: dict[str, Any],
        row: sqlite3.Row,
        instant: datetime,
    ) -> None:
        plan = connection.execute(
            "SELECT state, revision FROM orchestration_plans WHERE plan_id=?",
            (receipt["plan_id"],),
        ).fetchone()
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE plan_id=? AND task_id=?",
            (receipt["plan_id"], receipt["task_id"]),
        ).fetchone()
        worker = connection.execute(
            """SELECT status, version, execution_enabled
            FROM worker_runtime_instances WHERE worker_id=?""",
            (receipt["worker_id"],),
        ).fetchone()
        fence = connection.execute(
            """SELECT current_lease_generation, recovery_generation
            FROM orchestration_task_lease_fences WHERE task_id=?""",
            (receipt["task_id"],),
        ).fetchone()
        engagement = connection.execute(
            "SELECT status, active_policy_id, expires_at FROM engagements WHERE id=?",
            (receipt["assessment_id"],),
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id=1"
        ).fetchone()
        if (
            contract_issues(
                receipt, "orchestration-task-lease-consumption-receipt-v3.schema.json"
            )
            or canonical_json(receipt) != row["receipt_json"]
            or content_hash(receipt) != row["receipt_hash"]
            or plan is None
            or (plan["state"], plan["revision"])
            != ("active", receipt["resulting_plan_revision"])
            or task is None
            or (task["state"], task["revision"])
            != ("running", receipt["resulting_task_revision"])
            or worker is None
            or worker["status"] != "running"
            or worker["version"] != receipt["worker_version"]
            or worker["execution_enabled"] != 0
            or fence is None
            or fence["current_lease_generation"] != receipt["lease_generation"]
            or fence["recovery_generation"] != receipt["recovery_generation"]
            or engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != receipt["policy_bundle_id"]
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_CONSUMPTION_REPLAY_STALE",
                "consumption replay is stale",
            )

    @staticmethod
    def _load_state(row: sqlite3.Row) -> dict[str, Any]:
        state = cast(dict[str, Any], json.loads(row["state_json"]))
        if (
            contract_issues(state, "orchestration-task-lease-state-v3.schema.json")
            or content_hash(state) != row["state_hash"]
            or state["lease_id"] != row["lease_id"]
            or state["lease_version"] != row["lease_version"]
            or state["state"] != row["state"]
        ):
            raise OrchestrationLeaseV3Error(
                "ORCHESTRATION_LEASE_V3_STATE_TAMPERED", "lease state is invalid"
            )
        return state

    @staticmethod
    def _record_event(
        connection: sqlite3.Connection,
        *,
        command_id: str,
        command_digest: str,
        state: dict[str, Any],
        event_type: str,
        previous_version: int,
        reason: str,
        instant: datetime,
    ) -> dict[str, Any]:
        event = {
            "event_id": str(uuid4()),
            "lease_id": state["lease_id"],
            "event_type": event_type,
            "previous_lease_version": previous_version,
            "resulting_lease_version": state["lease_version"],
            "resulting_state": state["state"],
            "lease_generation": state["lease_generation"],
            "fencing_token": state["fencing_token"],
            "recovery_generation": state["recovery_generation"],
            "reason": reason,
            "occurred_at": _timestamp(instant),
            "authority": "none",
            "execution_enabled": False,
        }
        event_hash = content_hash(event)
        connection.execute(
            """INSERT INTO orchestration_task_lease_events_v3 VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
            (
                event["event_id"],
                command_id,
                command_digest,
                state["lease_id"],
                event_type,
                canonical_json(event),
                event_hash,
                event["occurred_at"],
            ),
        )
        audit = append_audit_event(
            connection,
            action=f"orchestration.attempt_three_task_lease_{event_type}",
            subject_type="orchestration_task_lease",
            subject_id=state["lease_id"],
            actor_type="service",
            actor_id="pentai-core",
            data=event,
            occurred_at=event["occurred_at"],
        )
        connection.execute(
            """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
            VALUES (?, 'orchestration_task_lease', ?, ?, ?)""",
            (
                str(uuid4()),
                state["lease_id"],
                f"orchestration.attempt_three_task_lease_{event_type}",
                canonical_json(
                    {
                        "event_hash": audit["event_hash"],
                        "occurred_at": event["occurred_at"],
                        "subject_id": state["lease_id"],
                    }
                ),
            ),
        )
        return event


def _state(
    command: dict[str, Any],
    *,
    lease_id: str,
    request_digest: str,
    lease_generation: int,
    recovery_generation: int,
    acquired_at: str,
    expires_at: str,
    maximum_expires_at: str,
) -> dict[str, Any]:
    state = {
        "schema_version": "3.0.0",
        "lease_id": lease_id,
        "request_id": command["request_id"],
        "request_digest": request_digest,
        "assessment_id": command["assessment_id"],
        "plan_id": command["plan_id"],
        "plan_revision": command["expected_plan_revision"],
        "task_id": command["task_id"],
        "task_revision": command["expected_task_revision"],
        "task_type": "validation",
        "agent_id": command["agent_id"],
        "capability_manifest_id": command["capability_manifest_id"],
        "capability_manifest_digest": command["capability_manifest_digest"],
        "manifest_revision": command["manifest_revision"],
        "budget_reservation_id": command["budget_reservation_id"],
        "budget_request_digest": command["budget_request_digest"],
        "budget_account_version": command["budget_account_version"],
    }
    for field in (
        "retry_policy_id", "retry_policy_digest", "retry_activation_id",
        "retry_activation_digest", "retry_schedule_id", "retry_schedule_digest",
        "retry_attempt_id", "retry_attempt_digest", "attempt_number",
        "prior_retry_budget_consumption_id", "retry_budget_consumption_id",
        "approval_consumption_id", "policy_bundle_id", "policy_hash", "worker_id",
    ):
        state[field] = command[field]
    state.update(
        {
            "worker_version": command["expected_worker_version"],
            "recovery_generation": recovery_generation,
            "lease_generation": lease_generation,
            "fencing_token": lease_generation,
            "lease_version": 1,
            "state": "active",
            "acquired_at": acquired_at,
            "expires_at": expires_at,
            "maximum_expires_at": maximum_expires_at,
            "released_at": None,
            "release_reason": "none",
            "purpose": command["purpose"],
            "authority": "none",
            "execution_enabled": False,
        }
    )
    return state


def _consumption_receipt(
    command: dict[str, Any],
    state: dict[str, Any],
    *,
    consumption_id: str,
    command_digest: str,
    consumed_at: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": "3.0.0",
        "consumption_id": consumption_id,
        "command_id": command["command_id"],
        "command_digest": command_digest,
        "assessment_id": state["assessment_id"],
        "plan_id": state["plan_id"],
        "expected_plan_revision": state["plan_revision"],
        "resulting_plan_revision": state["plan_revision"] + 1,
        "task_id": state["task_id"],
        "expected_task_revision": state["task_revision"],
        "resulting_task_revision": state["task_revision"] + 1,
        "agent_id": state["agent_id"],
    }
    for field in (
        "capability_manifest_id",
        "capability_manifest_digest",
        "manifest_revision",
        "budget_reservation_id",
        "budget_request_digest",
        "budget_account_version",
        "retry_policy_id",
        "retry_policy_digest",
        "retry_activation_id",
        "retry_activation_digest",
        "retry_schedule_id",
        "retry_schedule_digest",
        "retry_attempt_id",
        "retry_attempt_digest",
        "attempt_number",
        "prior_retry_budget_consumption_id",
        "retry_budget_consumption_id",
        "approval_consumption_id",
        "policy_bundle_id",
        "policy_hash",
        "worker_id",
    ):
        receipt[field] = state[field]
    receipt.update(
        {
            "worker_version": state["worker_version"],
            "lease_id": state["lease_id"],
            "consumed_lease_version": state["lease_version"],
            "lease_generation": state["lease_generation"],
            "fencing_token": state["fencing_token"],
            "recovery_generation": state["recovery_generation"],
            "lease_state_digest": command["lease_state_digest"],
            "purpose": command["purpose"],
            "consumed_at": consumed_at,
            "resulting_task_state": "running",
            "authority": "none",
            "execution_enabled": False,
        }
    )
    return receipt


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationLeaseV3Error(
            "ORCHESTRATION_LEASE_V3_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
