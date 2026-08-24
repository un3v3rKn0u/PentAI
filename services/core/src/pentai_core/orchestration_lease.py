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
_NAMESPACE = UUID("b42ef636-65dd-46c0-a042-0aac65361e02")


class OrchestrationLeaseError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationLeaseService:
    """Durable coordination leases that never dispatch work or grant authority."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path: Path = authorization.database_path

    def acquire(
        self, request: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(request)
        if contract_issues(document, _acquire_schema(document)):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_REQUEST_MALFORMED", "lease request is malformed"
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        if requested_at > instant or instant - requested_at > _MAX_REQUEST_AGE:
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_REQUEST_STALE", "lease request is stale"
            )
        request_digest = "sha256:" + content_hash(document)
        lease_id = str(uuid5(_NAMESPACE, "lease:" + document["request_id"]))
        self.authorization._require_storage_safe()
        verified = self._verified_policy(document, instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM orchestration_task_leases WHERE request_id = ?",
                (document["request_id"],),
            ).fetchone():
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_ACQUIRE_REPLAY_DENIED",
                    "lease acquisition token cannot be replayed",
                )
            if connection.execute(
                """SELECT 1 FROM orchestration_task_leases
                WHERE task_id=? AND task_revision=? AND state='active'""",
                (document["task_id"], document["expected_task_revision"]),
            ).fetchone():
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_CONFLICT", "task already has an active lease"
                )
            security = self._validate_current(connection, document, instant)
            fence = connection.execute(
                "SELECT * FROM orchestration_task_lease_fences WHERE task_id = ?",
                (document["task_id"],),
            ).fetchone()
            if fence is None:
                if document["expected_recovery_generation"] != 1:
                    raise OrchestrationLeaseError(
                        "ORCHESTRATION_LEASE_RECOVERY_FENCED", "recovery generation is stale"
                    )
                lease_generation = 1
                recovery_generation = 1
                connection.execute(
                    """INSERT INTO orchestration_task_lease_fences VALUES
                    (?, 1, 1, 1, ?, 'none', 0)""",
                    (document["task_id"], _timestamp(instant)),
                )
            else:
                recovery_generation = int(fence["recovery_generation"])
                if document["expected_recovery_generation"] != recovery_generation:
                    raise OrchestrationLeaseError(
                        "ORCHESTRATION_LEASE_RECOVERY_FENCED", "recovery generation is stale"
                    )
                lease_generation = int(fence["current_lease_generation"]) + 1
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET current_lease_generation = ?, version = version + 1, updated_at = ?
                    WHERE task_id = ? AND version = ?""",
                    (
                        lease_generation,
                        _timestamp(instant),
                        document["task_id"],
                        fence["version"],
                    ),
                )
            fencing_token = lease_generation
            maximum_expiry = min(
                instant + _MAX_LEASE_LIFETIME,
                parse_time(security["manifest"]["expires_at"]),
                parse_time(security["budget"]["expires_at"]),
                parse_time(verified["policy"]["validity"]["not_after"]),
                parse_time(security["engagement"]["expires_at"]),
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
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_EXPIRY_INVALID", "lease validity is empty"
                )
            raw_token = secrets.token_urlsafe(32)
            token_hash = _token_hash(raw_token)
            state = {
                "schema_version": document["schema_version"],
                "lease_id": lease_id,
                "request_id": document["request_id"],
                "assessment_id": document["assessment_id"],
                "plan_id": document["plan_id"],
                "plan_revision": document["expected_plan_revision"],
                "task_id": document["task_id"],
                "task_revision": document["expected_task_revision"],
                "task_type": "validation",
                "agent_id": document["agent_id"],
                "capability_manifest_id": document["capability_manifest_id"],
                "manifest_revision": document["manifest_revision"],
                "budget_reservation_id": document["budget_reservation_id"],
                "budget_account_version": document["budget_account_version"],
                "approval_consumption_id": document["approval_consumption_id"],
                "policy_bundle_id": document["policy_bundle_id"],
                "policy_hash": document["policy_hash"],
                "worker_id": document["worker_id"],
                "worker_version": document["expected_worker_version"],
                "recovery_generation": recovery_generation,
                "lease_generation": lease_generation,
                "fencing_token": fencing_token,
                "lease_version": 1,
                "state": "active",
                "acquired_at": _timestamp(instant),
                "expires_at": _timestamp(expires_at),
                "maximum_expires_at": _timestamp(maximum_expiry),
                "released_at": None,
                "release_reason": "none",
                "purpose": document["purpose"],
                "authority": "none",
                "execution_enabled": False,
            }
            if document["schema_version"] == "2.0.0":
                for field in (
                    "capability_manifest_digest",
                    "budget_request_digest",
                    "retry_activation_id",
                    "retry_activation_digest",
                    "retry_attempt_id",
                    "retry_attempt_digest",
                    "retry_budget_consumption_id",
                ):
                    state[field] = document[field]
            _validate_state(state)
            connection.execute(
                """INSERT INTO orchestration_task_leases(
                lease_id, request_id, request_digest, assessment_id, plan_id, plan_revision,
                task_id, task_revision, task_type, agent_id, capability_manifest_id,
                manifest_revision, budget_reservation_id, budget_account_version,
                approval_consumption_id, policy_bundle_id, policy_hash, worker_id,
                worker_version, token_hash, recovery_generation, lease_generation,
                fencing_token, lease_version, state, acquired_at, expires_at,
                maximum_expires_at, released_at, release_reason, purpose, state_json,
                authority, execution_enabled, capability_manifest_digest,
                budget_request_digest, retry_activation_id, retry_activation_digest,
                retry_attempt_id, retry_attempt_digest, retry_budget_consumption_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'validation', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, 1, 'active', ?, ?, ?, NULL, 'none', ?, ?, 'none', 0,
                ?, ?, ?, ?, ?, ?, ?)""",
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
                    document["manifest_revision"],
                    document["budget_reservation_id"],
                    document["budget_account_version"],
                    document["approval_consumption_id"],
                    document["policy_bundle_id"],
                    document["policy_hash"],
                    document["worker_id"],
                    document["expected_worker_version"],
                    token_hash,
                    recovery_generation,
                    lease_generation,
                    fencing_token,
                    state["acquired_at"],
                    state["expires_at"],
                    state["maximum_expires_at"],
                    document["purpose"],
                    canonical_json(state),
                    document.get("capability_manifest_digest"),
                    document.get("budget_request_digest"),
                    document.get("retry_activation_id"),
                    document.get("retry_activation_digest"),
                    document.get("retry_attempt_id"),
                    document.get("retry_attempt_digest"),
                    document.get("retry_budget_consumption_id"),
                ),
            )
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

    def mutate(
        self, command: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(command)
        if contract_issues(document, "orchestration-task-lease-mutation-v1.schema.json"):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_COMMAND_MALFORMED", "lease command is malformed"
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        if requested_at > instant or instant - requested_at > _MAX_REQUEST_AGE:
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_COMMAND_STALE", "lease command is stale"
            )
        command_digest = "sha256:" + content_hash(document)
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM orchestration_task_leases WHERE lease_id = ?",
                (document["lease_id"],),
            ).fetchone()
            if row is None:
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_MISSING", "lease is missing"
                )
            if not hmac.compare_digest(row["token_hash"], _token_hash(document["lease_token"])):
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_TOKEN_MISMATCH", "lease token mismatches"
                )
            replay = connection.execute(
                "SELECT * FROM orchestration_task_lease_events WHERE command_id = ?",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationLeaseError(
                        "ORCHESTRATION_LEASE_IDENTITY_CONFLICT", "command identity conflicts"
                    )
                event = cast(dict[str, Any], json.loads(replay["event_json"]))
                if row["lease_version"] != event["resulting_lease_version"]:
                    raise OrchestrationLeaseError(
                        "ORCHESTRATION_LEASE_REPLAY_STALE", "command replay is stale"
                    )
                return event
            self._validate_mutation_binding(connection, row, document, instant)
            state = cast(dict[str, Any], json.loads(row["state_json"]))
            previous_version = int(row["lease_version"])
            new_version = previous_version + 1
            if document["operation"] == "renew":
                proposed_expiry = instant + timedelta(seconds=document["lease_seconds"])
                expires_at = min(proposed_expiry, parse_time(row["maximum_expires_at"]))
                if expires_at <= instant or expires_at <= parse_time(row["expires_at"]):
                    raise OrchestrationLeaseError(
                        "ORCHESTRATION_LEASE_RENEWAL_INVALID", "renewal does not extend lease"
                    )
                resulting_state = "active"
                reason = "renewed"
                released_at = None
                state["expires_at"] = _timestamp(expires_at)
            else:
                resulting_state = "released"
                reason = "released"
                released_at = _timestamp(instant)
                state["released_at"] = released_at
                state["release_reason"] = reason
                state["state"] = resulting_state
            state["lease_version"] = new_version
            _validate_state(state)
            connection.execute(
                """UPDATE orchestration_task_leases SET lease_version = ?, state = ?,
                expires_at = ?, released_at = ?, release_reason = ?, state_json = ?
                WHERE lease_id = ? AND lease_version = ? AND state = 'active'""",
                (
                    new_version,
                    resulting_state,
                    state["expires_at"],
                    released_at,
                    reason if resulting_state != "active" else "none",
                    canonical_json(state),
                    document["lease_id"],
                    previous_version,
                ),
            )
            event = self._record_event(
                connection,
                command_id=document["command_id"],
                command_digest=command_digest,
                state=state,
                event_type="renewed" if document["operation"] == "renew" else "released",
                previous_version=previous_version,
                reason=reason,
                instant=instant,
            )
        return event

    def consume(
        self, command: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        """Consume one current lease into running coordination state without dispatch."""
        document = copy.deepcopy(command)
        if contract_issues(
            document, "orchestration-task-lease-consumption-v1.schema.json"
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_CONSUMPTION_MALFORMED",
                "lease consumption is malformed",
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        if requested_at > instant or instant - requested_at > _MAX_REQUEST_AGE:
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_CONSUMPTION_STALE",
                "lease consumption is stale",
            )
        command_digest = "sha256:" + content_hash(document)
        consumption_id = str(uuid5(_NAMESPACE, "consumption:" + document["command_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT command_digest, receipt_json
                FROM orchestration_task_lease_consumptions WHERE command_id = ?""",
                (document["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["command_digest"] != command_digest:
                    raise OrchestrationLeaseError(
                        "ORCHESTRATION_LEASE_CONSUMPTION_IDENTITY_CONFLICT",
                        "consumption identity conflicts",
                    )
                return cast(dict[str, Any], json.loads(replay["receipt_json"]))
            row = connection.execute(
                "SELECT * FROM orchestration_task_leases WHERE lease_id = ?",
                (document["lease_id"],),
            ).fetchone()
            if row is None:
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_MISSING", "lease is missing"
                )
            if json.loads(row["state_json"]).get("schema_version") != "1.0.0":
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_CONSUMPTION_UNSUPPORTED",
                    "retry-bound lease consumption is not implemented",
                )
            if not hmac.compare_digest(
                row["token_hash"], _token_hash(document["lease_token"])
            ):
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_TOKEN_MISMATCH", "lease token mismatches"
                )
            expected = {
                "assessment_id": row["assessment_id"],
                "plan_id": row["plan_id"],
                "expected_plan_revision": row["plan_revision"],
                "task_id": row["task_id"],
                "expected_task_revision": row["task_revision"],
                "agent_id": row["agent_id"],
                "capability_manifest_id": row["capability_manifest_id"],
                "manifest_revision": row["manifest_revision"],
                "budget_reservation_id": row["budget_reservation_id"],
                "budget_account_version": row["budget_account_version"],
                "approval_consumption_id": row["approval_consumption_id"],
                "policy_bundle_id": row["policy_bundle_id"],
                "policy_hash": row["policy_hash"],
                "worker_id": row["worker_id"],
                "expected_worker_version": row["worker_version"],
                "expected_lease_version": row["lease_version"],
                "lease_generation": row["lease_generation"],
                "fencing_token": row["fencing_token"],
                "expected_recovery_generation": row["recovery_generation"],
            }
            if any(document[key] != value for key, value in expected.items()):
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_CONSUMPTION_BINDING_MISMATCH",
                    "lease consumption binding mismatches",
                )
            state = cast(dict[str, Any], json.loads(row["state_json"]))
            state_digest = "sha256:" + content_hash(state)
            if document["lease_state_digest"] != state_digest:
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_STATE_TAMPERED", "lease state digest mismatches"
                )
            self._validate_mutation_binding(connection, row, document, instant)
            receipt = {
                "schema_version": "1.0.0",
                "consumption_id": consumption_id,
                "command_id": document["command_id"],
                "command_digest": command_digest,
                "assessment_id": row["assessment_id"],
                "plan_id": row["plan_id"],
                "expected_plan_revision": row["plan_revision"],
                "resulting_plan_revision": int(row["plan_revision"]) + 1,
                "task_id": row["task_id"],
                "expected_task_revision": row["task_revision"],
                "resulting_task_revision": int(row["task_revision"]) + 1,
                "agent_id": row["agent_id"],
                "capability_manifest_id": row["capability_manifest_id"],
                "manifest_revision": row["manifest_revision"],
                "budget_reservation_id": row["budget_reservation_id"],
                "budget_account_version": row["budget_account_version"],
                "approval_consumption_id": row["approval_consumption_id"],
                "policy_bundle_id": row["policy_bundle_id"],
                "policy_hash": row["policy_hash"],
                "worker_id": row["worker_id"],
                "worker_version": row["worker_version"],
                "lease_id": row["lease_id"],
                "consumed_lease_version": row["lease_version"],
                "resulting_lease_version": int(row["lease_version"]) + 1,
                "lease_generation": row["lease_generation"],
                "fencing_token": row["fencing_token"],
                "recovery_generation": row["recovery_generation"],
                "lease_state_digest": state_digest,
                "purpose": document["purpose"],
                "consumed_at": _timestamp(instant),
                "resulting_task_state": "running",
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(
                receipt,
                "orchestration-task-lease-consumption-receipt-v1.schema.json",
            ):
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_CONSUMPTION_RESULT_INVALID",
                    "lease consumption result is invalid",
                )
            connection.execute(
                """INSERT INTO orchestration_task_lease_consumptions VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                (
                    consumption_id,
                    document["command_id"],
                    command_digest,
                    row["assessment_id"],
                    row["plan_id"],
                    row["plan_revision"],
                    receipt["resulting_plan_revision"],
                    row["task_id"],
                    row["task_revision"],
                    receipt["resulting_task_revision"],
                    row["lease_id"],
                    row["lease_generation"],
                    row["fencing_token"],
                    row["recovery_generation"],
                    canonical_json(receipt),
                    content_hash(receipt),
                    receipt["consumed_at"],
                ),
            )
            connection.execute(
                """UPDATE orchestration_tasks SET state = 'running', revision = revision + 1,
                updated_at = ? WHERE plan_id = ? AND task_id = ? AND state = 'ready'
                AND revision = ?""",
                (
                    receipt["consumed_at"],
                    row["plan_id"],
                    row["task_id"],
                    row["task_revision"],
                ),
            )
            connection.execute(
                """UPDATE orchestration_plans SET revision = revision + 1, updated_at = ?
                WHERE plan_id = ? AND state = 'active' AND revision = ?""",
                (receipt["consumed_at"], row["plan_id"], row["plan_revision"]),
            )
            state["lease_version"] = receipt["resulting_lease_version"]
            state["state"] = "released"
            state["released_at"] = receipt["consumed_at"]
            state["release_reason"] = "released"
            _validate_state(state)
            connection.execute(
                """UPDATE orchestration_task_leases SET lease_version = ?,
                state = 'released', released_at = ?, release_reason = 'released',
                state_json = ? WHERE lease_id = ? AND state = 'active'
                AND lease_version = ?""",
                (
                    state["lease_version"],
                    state["released_at"],
                    canonical_json(state),
                    row["lease_id"],
                    row["lease_version"],
                ),
            )
            self._record_event(
                connection,
                command_id=document["command_id"],
                command_digest=command_digest,
                state=state,
                event_type="released",
                previous_version=int(row["lease_version"]),
                reason="released",
                instant=instant,
            )
            audit = append_audit_event(
                connection,
                action="orchestration.task_lease_consumed",
                subject_type="orchestration_task_lease_consumption",
                subject_id=consumption_id,
                actor_type="service",
                actor_id="pentai-core",
                data=receipt,
                occurred_at=receipt["consumed_at"],
            )
            connection.execute(
                """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type,
                payload_json) VALUES (?, 'orchestration_task_lease_consumption', ?,
                'orchestration.task_lease_consumed', ?)""",
                (
                    str(uuid4()),
                    consumption_id,
                    canonical_json(
                        {
                            "event_hash": audit["event_hash"],
                            "occurred_at": receipt["consumed_at"],
                            "subject_id": consumption_id,
                        }
                    ),
                ),
            )
        return copy.deepcopy(receipt)

    def recover(self, *, now: datetime | None = None) -> tuple[dict[str, Any], ...]:
        instant = _instant(now)
        events: list[dict[str, Any]] = []
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM orchestration_task_leases WHERE state = 'active' ORDER BY lease_id"
            ).fetchall()
            for row in rows:
                state = cast(dict[str, Any], json.loads(row["state_json"]))
                _validate_state(state)
                fence = connection.execute(
                    "SELECT * FROM orchestration_task_lease_fences WHERE task_id = ?",
                    (row["task_id"],),
                ).fetchone()
                if fence is None:
                    raise OrchestrationLeaseError(
                        "ORCHESTRATION_LEASE_RECOVERY_INVALID", "lease fence is missing"
                    )
                recovery_generation = int(fence["recovery_generation"]) + 1
                connection.execute(
                    """UPDATE orchestration_task_lease_fences SET recovery_generation = ?,
                    version = version + 1, updated_at = ? WHERE task_id = ? AND version = ?""",
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
                _validate_state(state)
                connection.execute(
                    """UPDATE orchestration_task_leases SET lease_version = ?,
                    state = ?, released_at = ?, release_reason = ?,
                    state_json = ? WHERE lease_id = ? AND state = 'active'""",
                    (
                        state["lease_version"],
                        state["state"],
                        state["released_at"],
                        state["release_reason"],
                        canonical_json(state),
                        row["lease_id"],
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
                        command_digest="sha256:" + content_hash(
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

    def _verified_policy(
        self, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        try:
            verified = self.authorization.get_policy(
                document["assessment_id"], document["policy_bundle_id"]
            )
        except DomainError as error:
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_POLICY_INVALID", "policy is invalid"
            ) from error
        if (
            verified["status"] != "active"
            or verified["content_hash"] != document["policy_hash"]
            or parse_time(verified["policy"]["validity"]["not_after"]) <= instant
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_POLICY_STALE", "policy is stale"
            )
        return verified

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> dict[str, Any]:
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ?", (document["assessment_id"],)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id = 1"
        ).fetchone()
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id = ?", (document["plan_id"],)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id = ? AND task_id = ?",
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
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_SAFETY_DENIED", "assessment safety denies"
            )
        if (
            plan is None
            or plan["assessment_id"] != document["assessment_id"]
            or plan["state"] != "active"
            or plan["revision"] != document["expected_plan_revision"]
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_PLAN_FENCED", "plan is not current"
            )
        if (
            task is None
            or task["assessment_id"] != document["assessment_id"]
            or task["state"] != "ready"
            or task["revision"] != document["expected_task_revision"]
            or task["task_type"] != "validation"
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_TASK_FENCED", "task is not ready"
            )
        manifest_row = connection.execute(
            "SELECT * FROM task_capability_manifests WHERE manifest_id = ?",
            (document["capability_manifest_id"],),
        ).fetchone()
        budget_row = connection.execute(
            "SELECT * FROM orchestration_task_budget_reservations WHERE reservation_id = ?",
            (document["budget_reservation_id"],),
        ).fetchone()
        if manifest_row is None or budget_row is None:
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_PREREQUISITE_MISSING", "lease prerequisite is missing"
            )
        manifest = json.loads(manifest_row["manifest_json"])
        budget = json.loads(budget_row["receipt_json"])
        account = connection.execute(
            "SELECT version FROM orchestration_budget_accounts WHERE account_id=?",
            (budget_row["account_id"],),
        ).fetchone()
        retry_bound = document.get("schema_version") == "2.0.0"
        expected_manifest_version = "3.0.0" if retry_bound else "2.0.0"
        expected_budget_version = "3.0.0" if retry_bound else "2.0.0"
        if (
            manifest.get("schema_version") != expected_manifest_version
            or manifest.get("task_state") != "ready"
            or contract_issues(
                manifest,
                f"task-capability-manifest-v{3 if retry_bound else 2}.schema.json",
            )
            or content_hash(manifest) != manifest_row["manifest_hash"]
            or budget.get("schema_version") != expected_budget_version
            or budget.get("task_state") != "ready"
            or contract_issues(
                budget,
                f"orchestration-task-budget-reservation-v{3 if retry_bound else 2}.schema.json",
            )
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_PREREQUISITE_INVALID", "lease prerequisite is invalid"
            )
        exact = (
            manifest["assessment_id"] == document["assessment_id"]
            and manifest["plan_id"] == document["plan_id"]
            and manifest["plan_revision"] == document["expected_plan_revision"]
            and manifest["task_id"] == document["task_id"]
            and manifest["task_revision"] == document["expected_task_revision"]
            and manifest["agent_id"] == document["agent_id"]
            and manifest["policy_bundle_id"] == document["policy_bundle_id"]
            and manifest["policy_hash"] == document["policy_hash"]
            and budget["assessment_id"] == document["assessment_id"]
            and budget["plan_id"] == document["plan_id"]
            and budget["plan_revision"] == document["expected_plan_revision"]
            and budget["task_id"] == document["task_id"]
            and budget["task_revision"] == document["expected_task_revision"]
            and budget["agent_id"] == document["agent_id"]
            and budget["capability_manifest_id"] == document["capability_manifest_id"]
            and budget["manifest_revision"] == document["manifest_revision"]
            and budget["account_version"] == document["budget_account_version"]
            and budget["policy_bundle_id"] == document["policy_bundle_id"]
            and budget["policy_hash"] == document["policy_hash"]
            and budget_row["reservation_id"] == budget["reservation_id"]
            and budget_row["account_id"] == budget["account_id"]
            and budget_row["account_version"] == budget["account_version"]
            and budget_row["assessment_id"] == budget["assessment_id"]
            and budget_row["plan_id"] == budget["plan_id"]
            and budget_row["plan_revision"] == budget["plan_revision"]
            and budget_row["task_id"] == budget["task_id"]
            and budget_row["task_revision"] == budget["task_revision"]
            and budget_row["agent_id"] == budget["agent_id"]
            and budget_row["capability_manifest_id"]
            == budget["capability_manifest_id"]
            and budget_row["manifest_revision"] == budget["manifest_revision"]
            and budget_row["policy_bundle_id"] == budget["policy_bundle_id"]
            and budget_row["policy_hash"] == budget["policy_hash"]
            and budget_row["purpose"] == budget["purpose"]
            and json.loads(budget_row["amounts_json"]) == budget["amounts"]
            and budget_row["state"] == budget["state"]
            and budget_row["created_at"] == budget["created_at"]
            and budget_row["expires_at"] == budget["expires_at"]
            and budget_row["task_state"] == budget["task_state"]
            and account is not None
            and account["version"] == budget["account_version"]
        )
        if retry_bound:
            exact = exact and (
                manifest_row["manifest_hash"]
                == document["capability_manifest_digest"][7:]
                and budget["capability_manifest_digest"]
                == document["capability_manifest_digest"]
                and budget["request_digest"] == document["budget_request_digest"]
                and manifest["retry_activation_id"] == document["retry_activation_id"]
                and manifest["retry_activation_digest"]
                == document["retry_activation_digest"]
                and manifest["retry_attempt_id"] == document["retry_attempt_id"]
                and manifest["retry_attempt_digest"] == document["retry_attempt_digest"]
                and manifest["retry_budget_consumption_id"]
                == document["retry_budget_consumption_id"]
                and budget["retry_activation_id"] == document["retry_activation_id"]
                and budget["retry_activation_digest"]
                == document["retry_activation_digest"]
                and budget["retry_attempt_id"] == document["retry_attempt_id"]
                and budget["retry_attempt_digest"] == document["retry_attempt_digest"]
                and budget["retry_budget_consumption_id"]
                == document["retry_budget_consumption_id"]
                and budget_row["capability_manifest_digest"]
                == document["capability_manifest_digest"]
                and budget_row["retry_activation_id"] == document["retry_activation_id"]
                and budget_row["retry_attempt_id"] == document["retry_attempt_id"]
                and budget_row["retry_budget_consumption_id"]
                == document["retry_budget_consumption_id"]
            )
        if not exact or budget["state"] != "reserved":
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_PREREQUISITE_MISMATCH",
                "lease prerequisite binding mismatches",
            )
        if (
            parse_time(manifest["expires_at"]) <= instant
            or parse_time(budget["expires_at"]) <= instant
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_PREREQUISITE_STALE", "lease prerequisite is stale"
            )
        approval = None
        if task["requires_human_approval"]:
            if document["approval_consumption_id"] is None:
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_APPROVAL_REQUIRED", "approval consumption is required"
                )
            approval = connection.execute(
                "SELECT * FROM orchestration_task_approval_consumptions WHERE consumption_id = ?",
                (document["approval_consumption_id"],),
            ).fetchone()
            if (
                approval is None
                or approval["assessment_id"] != document["assessment_id"]
                or approval["plan_id"] != document["plan_id"]
                or approval["task_id"] != document["task_id"]
                or approval["resulting_task_revision"] != document["expected_task_revision"]
                or approval["policy_bundle_id"] != document["policy_bundle_id"]
                or approval["policy_hash"] != document["policy_hash"]
                or parse_time(approval["approval_expires_at"]) <= instant
            ):
                raise OrchestrationLeaseError(
                    "ORCHESTRATION_LEASE_APPROVAL_INVALID", "approval consumption is invalid"
                )
        elif document["approval_consumption_id"] is not None:
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_APPROVAL_AMBIGUOUS", "approval is not required"
            )
        worker = connection.execute(
            "SELECT * FROM worker_runtime_instances WHERE worker_id = ?",
            (document["worker_id"],),
        ).fetchone()
        if (
            worker is None
            or worker["status"] != "running"
            or worker["version"] != document["expected_worker_version"]
            or worker["execution_enabled"] != 0
            or worker["container_id"] is None
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_WORKER_INELIGIBLE", "worker registry identity is ineligible"
            )
        return {
            "engagement": engagement,
            "manifest": manifest,
            "budget": budget,
            "approval": approval,
        }

    def _validate_mutation_binding(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        document: dict[str, Any],
        instant: datetime,
    ) -> None:
        if (
            row["state"] != "active"
            or parse_time(row["expires_at"]) <= instant
            or row["worker_id"] != document["worker_id"]
            or row["worker_version"] != document["expected_worker_version"]
            or row["lease_version"] != document["expected_lease_version"]
            or row["lease_generation"] != document["lease_generation"]
            or row["fencing_token"] != document["fencing_token"]
            or row["recovery_generation"] != document["expected_recovery_generation"]
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_FENCED", "lease holder is stale"
            )
        acquire_binding = {
            "schema_version": json.loads(row["state_json"])["schema_version"],
            "assessment_id": row["assessment_id"],
            "plan_id": row["plan_id"],
            "expected_plan_revision": row["plan_revision"],
            "task_id": row["task_id"],
            "expected_task_revision": row["task_revision"],
            "agent_id": row["agent_id"],
            "capability_manifest_id": row["capability_manifest_id"],
            "manifest_revision": row["manifest_revision"],
            "budget_reservation_id": row["budget_reservation_id"],
            "budget_account_version": row["budget_account_version"],
            "approval_consumption_id": row["approval_consumption_id"],
            "policy_bundle_id": row["policy_bundle_id"],
            "policy_hash": row["policy_hash"],
            "worker_id": row["worker_id"],
            "expected_worker_version": row["worker_version"],
        }
        for field in (
            "capability_manifest_digest",
            "budget_request_digest",
            "retry_activation_id",
            "retry_activation_digest",
            "retry_attempt_id",
            "retry_attempt_digest",
            "retry_budget_consumption_id",
        ):
            if row[field] is not None:
                acquire_binding[field] = row[field]
        self._verified_policy(acquire_binding, instant)
        self._validate_current(connection, acquire_binding, instant)
        fence = connection.execute(
            "SELECT * FROM orchestration_task_lease_fences WHERE task_id = ?",
            (row["task_id"],),
        ).fetchone()
        if (
            fence is None
            or fence["current_lease_generation"] != row["lease_generation"]
            or fence["recovery_generation"] != row["recovery_generation"]
        ):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_FENCED", "lease generation is stale"
            )

    def _record_event(
        self,
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
            "schema_version": "1.0.0",
            "event_id": str(uuid5(_NAMESPACE, f"event:{command_id}")),
            "command_id": command_id,
            "lease_id": state["lease_id"],
            "event_type": event_type,
            "lease_generation": state["lease_generation"],
            "fencing_token": state["fencing_token"],
            "previous_lease_version": previous_version,
            "resulting_lease_version": state["lease_version"],
            "worker_id": state["worker_id"],
            "worker_version": state["worker_version"],
            "recovery_generation": state["recovery_generation"],
            "occurred_at": _timestamp(instant),
            "resulting_state": state["state"],
            "expires_at": state["expires_at"],
            "reason": reason,
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(event, "orchestration-task-lease-event-v1.schema.json"):
            raise OrchestrationLeaseError(
                "ORCHESTRATION_LEASE_EVENT_INVALID", "lease event is invalid"
            )
        connection.execute(
            """INSERT INTO orchestration_task_lease_events VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
            (
                event["event_id"],
                command_id,
                command_digest,
                state["lease_id"],
                event_type,
                canonical_json(event),
                content_hash(event),
                event["occurred_at"],
            ),
        )
        audit = append_audit_event(
            connection,
            action=f"orchestration.task_lease_{event_type}",
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
                f"orchestration.task_lease_{event_type}",
                canonical_json(
                    {
                        "event_hash": audit["event_hash"],
                        "occurred_at": event["occurred_at"],
                        "subject_id": state["lease_id"],
                    }
                ),
            ),
        )
        return copy.deepcopy(event)


def _validate_state(state: dict[str, Any]) -> None:
    version = state.get("schema_version")
    schema = (
        "orchestration-task-lease-state-v1.schema.json"
        if version == "1.0.0"
        else "orchestration-task-lease-state-v2.schema.json"
        if version == "2.0.0"
        else None
    )
    if schema is None or contract_issues(state, schema):
        raise OrchestrationLeaseError(
            "ORCHESTRATION_LEASE_STATE_INVALID", "lease state is invalid"
        )


def _acquire_schema(document: dict[str, Any]) -> str:
    version = document.get("schema_version")
    if version == "1.0.0":
        return "orchestration-task-lease-acquire-v1.schema.json"
    if version == "2.0.0":
        return "orchestration-task-lease-acquire-v2.schema.json"
    raise OrchestrationLeaseError(
        "ORCHESTRATION_LEASE_REQUEST_MALFORMED", "lease request version is unsupported"
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise OrchestrationLeaseError("ORCHESTRATION_LEASE_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
