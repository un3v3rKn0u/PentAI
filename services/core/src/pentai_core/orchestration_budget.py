from __future__ import annotations

import copy
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4, uuid5

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.ai_provider_config import (
    ProviderConfigurationError,
    ProviderPolicy,
    validate_provider_configuration,
)
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.database import transaction
from pentai_core.orchestration_retry_manifest import (
    OrchestrationRetryManifestError,
    OrchestrationRetryManifestService,
)

_FIELDS = (
    "input_tokens",
    "output_tokens",
    "requests",
    "cost_microusd",
    "runtime_seconds",
    "retries",
)
_CONFIGURATION_FIELDS = {
    "input_tokens": "max_input_tokens",
    "output_tokens": "max_output_tokens",
    "requests": "max_requests",
    "cost_microusd": "max_cost_microusd",
    "runtime_seconds": "max_runtime_seconds",
}
_MAX_REQUEST_AGE = timedelta(minutes=1)
_MAX_RESERVATION_LIFETIME = timedelta(minutes=5)
_NAMESPACE = UUID("9135e73b-702e-4dc6-a7bf-1b4d289ca1ca")


class OrchestrationBudgetError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OrchestrationBudgetService:
    """Durable non-authoritative budget ceilings for one orchestration task."""

    def __init__(self, authorization: AuthorizationService) -> None:
        self.authorization = authorization
        self.database_path = authorization.database_path

    def activate_account(
        self,
        *,
        assessment_id: str,
        policy_bundle_id: str,
        policy_hash: str,
        configuration: dict[str, Any],
        provider_policy: ProviderPolicy,
        maximum_retries: int,
        maximum_task_amounts: dict[str, int] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = _instant(now)
        try:
            validate_provider_configuration(configuration, policy=provider_policy, now=instant)
        except ProviderConfigurationError as error:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_CONFIGURATION_INVALID",
                "provider configuration is invalid",
            ) from error
        if not isinstance(maximum_retries, int) or isinstance(maximum_retries, bool):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_CEILING_INVALID", "retry ceiling is invalid"
            )
        if maximum_retries < 0 or maximum_retries > 100:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_CEILING_INVALID", "retry ceiling is invalid"
            )
        verified = self._verified_policy(assessment_id, policy_bundle_id, policy_hash, instant)
        assessment_ceilings = {
            field: (
                maximum_retries
                if field == "retries"
                else configuration["budgets"][_CONFIGURATION_FIELDS[field]]
            )
            for field in _FIELDS
        }
        task_ceilings = copy.deepcopy(maximum_task_amounts or assessment_ceilings)
        if set(task_ceilings) != set(_FIELDS) or any(
            not isinstance(task_ceilings[field], int)
            or isinstance(task_ceilings[field], bool)
            or task_ceilings[field] < 0
            or task_ceilings[field] > assessment_ceilings[field]
            for field in _FIELDS
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_CEILING_INVALID", "task ceilings are invalid"
            )
        ceilings = {"assessment": assessment_ceilings, "per_task": task_ceilings}
        account_id = str(
            uuid5(
                _NAMESPACE,
                ":".join(
                    (
                        assessment_id,
                        str(configuration["configuration_id"]),
                        provider_policy.registry_id,
                        str(provider_policy.registry_revision),
                        policy_bundle_id,
                        policy_hash,
                    )
                ),
            )
        )
        configuration_hash = content_hash(configuration)
        created_at = _timestamp(instant)
        expires_at = _timestamp(
            min(
                parse_time(configuration["expires_at"]),
                provider_policy.registry_expires_at,
                parse_time(verified["policy"]["validity"]["not_after"]),
            )
        )
        account = {
            "account_id": account_id,
            "assessment_id": assessment_id,
            "configuration_id": configuration["configuration_id"],
            "configuration_hash": configuration_hash,
            "registry_id": provider_policy.registry_id,
            "registry_revision": provider_policy.registry_revision,
            "policy_bundle_id": policy_bundle_id,
            "policy_hash": policy_hash,
            "ceilings": ceilings,
            "version": 1,
            "created_at": created_at,
            "expires_at": expires_at,
            "authority": "none",
            "execution_enabled": False,
        }
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_assessment_policy(
                connection, assessment_id, policy_bundle_id, policy_hash, instant
            )
            existing = connection.execute(
                "SELECT * FROM orchestration_budget_accounts WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["configuration_hash"] != configuration_hash
                    or json.loads(existing["ceilings_json"]) != ceilings
                    or existing["policy_bundle_id"] != policy_bundle_id
                    or existing["policy_hash"] != policy_hash
                    or existing["expires_at"] != expires_at
                ):
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_ACCOUNT_CONFLICT", "account identity conflicts"
                    )
                return self._account_document(existing)
            connection.execute(
                """INSERT INTO orchestration_budget_accounts VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'none', 0)""",
                (
                    account_id,
                    assessment_id,
                    configuration["configuration_id"],
                    configuration_hash,
                    provider_policy.registry_id,
                    provider_policy.registry_revision,
                    policy_bundle_id,
                    policy_hash,
                    canonical_json(ceilings),
                    created_at,
                    expires_at,
                ),
            )
            _audit(connection, "orchestration.budget_account_activated", account_id, account)
        return copy.deepcopy(account)

    def reserve(
        self, request: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        document = copy.deepcopy(request)
        request_schema = _request_schema(document)
        if contract_issues(document, request_schema):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REQUEST_MALFORMED", "budget request is malformed"
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        expires_at = parse_time(document["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > _MAX_REQUEST_AGE
            or expires_at <= instant
            or expires_at <= requested_at
            or expires_at - requested_at > _MAX_RESERVATION_LIFETIME
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REQUEST_STALE", "budget request is stale"
            )
        if not any(document["amounts"][field] > 0 for field in _FIELDS):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_AMOUNT_INVALID", "budget request is empty"
            )
        request_digest = "sha256:" + content_hash(document)
        reservation_id = str(uuid5(_NAMESPACE, "reservation:" + document["request_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT receipt_json, request_digest
                FROM orchestration_task_budget_reservations WHERE request_id = ?""",
                (document["request_id"],),
            ).fetchone()
            if replay is not None:
                if replay["request_digest"] != request_digest:
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_IDENTITY_CONFLICT", "request identity conflicts"
                    )
                receipt = cast(dict[str, Any], json.loads(replay["receipt_json"]))
                if receipt.get("schema_version") == "3.0.0":
                    self._validate_reservation_replay(connection, receipt, instant)
                else:
                    self._validate_current(connection, document, instant)
                return receipt
            if document["schema_version"] == "3.0.0":
                current = connection.execute(
                    "SELECT version FROM orchestration_budget_accounts WHERE account_id=?",
                    (document["account_id"],),
                ).fetchone()
                if (
                    current is not None
                    and current["version"] != document["expected_account_version"]
                ):
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_VERSION_STALE", "account version is stale"
                    )
            account, manifest = self._validate_current(connection, document, instant)
            if account["version"] != document["expected_account_version"]:
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_VERSION_STALE", "account version is stale"
                )
            if expires_at > parse_time(account["expires_at"]):
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_REQUEST_STALE", "reservation outlives account"
                )
            used, task_used = self._used_capacity(
                connection, document["account_id"], document["task_id"]
            )
            ceilings = json.loads(account["ceilings_json"])
            for field in _FIELDS:
                if (
                    used[field] + document["amounts"][field]
                    > ceilings["assessment"][field]
                ):
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_EXCEEDED", f"{field} budget is exhausted"
                    )
                if (
                    task_used[field] + document["amounts"][field]
                    > ceilings["per_task"][field]
                ):
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_TASK_BUDGET_EXCEEDED",
                        f"{field} task budget is exhausted",
                    )
            account_version = int(account["version"]) + 1
            receipt = {
                "schema_version": document["schema_version"],
                "reservation_id": reservation_id,
                "request_id": document["request_id"],
                "request_digest": request_digest,
                "account_id": document["account_id"],
                "account_version": account_version,
                "assessment_id": document["assessment_id"],
                "plan_id": document["plan_id"],
                "plan_revision": document["expected_plan_revision"],
                "task_id": document["task_id"],
                "task_revision": document["expected_task_revision"],
                "agent_id": document["agent_id"],
                "capability_manifest_id": document["capability_manifest_id"],
                "manifest_revision": document["expected_manifest_revision"],
                "policy_bundle_id": document["policy_bundle_id"],
                "policy_hash": document["policy_hash"],
                "purpose": document["purpose"],
                "amounts": document["amounts"],
                "state": "reserved",
                "created_at": document["requested_at"],
                "expires_at": document["expires_at"],
                "released_at": None,
                "release_reason": "none",
                "authority": "none",
                "execution_enabled": False,
            }
            if document["schema_version"] in {"2.0.0", "3.0.0"}:
                receipt["task_state"] = document["task_state"]
            if document["schema_version"] == "3.0.0":
                for field in (
                    "capability_manifest_digest",
                    "retry_activation_id",
                    "retry_activation_digest",
                    "retry_attempt_id",
                    "retry_attempt_digest",
                    "retry_budget_consumption_id",
                ):
                    receipt[field] = document[field]
            if contract_issues(receipt, _reservation_schema(receipt)):
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_RESULT_INVALID", "budget receipt is invalid"
                )
            connection.execute(
                "UPDATE orchestration_budget_accounts SET version = ? WHERE account_id = ?",
                (account_version, document["account_id"]),
            )
            connection.execute(
                """INSERT INTO orchestration_task_budget_reservations(
                reservation_id, request_id, request_digest, account_id, account_version,
                assessment_id, plan_id, plan_revision, task_id, task_revision, agent_id,
                capability_manifest_id, manifest_revision, policy_bundle_id, policy_hash,
                purpose, amounts_json, state, created_at, expires_at, released_at,
                release_reason, receipt_json, authority, execution_enabled, task_state,
                capability_manifest_digest, retry_activation_id, retry_activation_digest,
                retry_attempt_id, retry_attempt_digest, retry_budget_consumption_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved',
                ?, ?, NULL, 'none', ?, 'none', 0, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    reservation_id,
                    document["request_id"],
                    request_digest,
                    document["account_id"],
                    account_version,
                    document["assessment_id"],
                    document["plan_id"],
                    document["expected_plan_revision"],
                    document["task_id"],
                    document["expected_task_revision"],
                    document["agent_id"],
                    document["capability_manifest_id"],
                    document["expected_manifest_revision"],
                    document["policy_bundle_id"],
                    document["policy_hash"],
                    document["purpose"],
                    canonical_json(document["amounts"]),
                    document["requested_at"],
                    document["expires_at"],
                    canonical_json(receipt),
                    document.get("task_state", "running"),
                    document.get("capability_manifest_digest"),
                    document.get("retry_activation_id"),
                    document.get("retry_activation_digest"),
                    document.get("retry_attempt_id"),
                    document.get("retry_attempt_digest"),
                    document.get("retry_budget_consumption_id"),
                ),
            )
            _audit(
                connection,
                "orchestration.task_budget_reserved",
                reservation_id,
                _audit_data(receipt, manifest),
            )
        return copy.deepcopy(receipt)

    def reserve_v4(
        self, request: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        """Reserve existing provider-resource capacity for exact attempt-three readiness."""
        document = copy.deepcopy(request)
        if contract_issues(document, "orchestration-task-budget-request-v4.schema.json"):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REQUEST_MALFORMED", "budget request is malformed"
            )
        instant = _instant(now)
        requested_at = parse_time(document["requested_at"])
        expires_at = parse_time(document["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > _MAX_REQUEST_AGE
            or expires_at <= instant
            or expires_at <= requested_at
            or expires_at - requested_at > _MAX_RESERVATION_LIFETIME
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REQUEST_STALE", "budget request is stale"
            )
        if document["amounts"]["retries"] != 0 or not any(
            document["amounts"][field] > 0 for field in _FIELDS if field != "retries"
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_AMOUNT_INVALID", "budget request is empty or retry-shaped"
            )
        request_digest = "sha256:" + content_hash(document)
        reservation_id = str(uuid5(_NAMESPACE, "reservation-v4:" + document["request_id"]))
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                "SELECT * FROM orchestration_task_budget_reservations_v4 WHERE request_id=?",
                (document["request_id"],),
            ).fetchone()
            if replay is not None:
                if replay["request_digest"] != request_digest:
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_IDENTITY_CONFLICT", "request identity conflicts"
                    )
                receipt = cast(dict[str, Any], json.loads(replay["receipt_json"]))
                self._validate_reservation_replay_v4(connection, receipt, instant)
                return copy.deepcopy(receipt)

            current = connection.execute(
                "SELECT version FROM orchestration_budget_accounts WHERE account_id=?",
                (document["account_id"],),
            ).fetchone()
            if current is not None and current["version"] != document["expected_account_version"]:
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_VERSION_STALE", "account version is stale"
                )
            account, manifest = self._validate_current_v4(connection, document, instant)
            if account["version"] != document["expected_account_version"]:
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_VERSION_STALE", "account version is stale"
                )
            lineage_expires_at = min(
                parse_time(account["expires_at"]), parse_time(manifest["expires_at"])
            )
            if expires_at > lineage_expires_at:
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_REQUEST_STALE", "reservation outlives its lineage"
                )
            used, task_used = self._used_capacity(
                connection, document["account_id"], document["task_id"]
            )
            ceilings = json.loads(account["ceilings_json"])
            for field in _FIELDS:
                if used[field] + document["amounts"][field] > ceilings["assessment"][field]:
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_EXCEEDED", f"{field} budget is exhausted"
                    )
                if task_used[field] + document["amounts"][field] > ceilings["per_task"][field]:
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_TASK_BUDGET_EXCEEDED", f"{field} task budget is exhausted"
                    )
            account_version = int(account["version"]) + 1
            receipt = {
                "schema_version": "4.0.0",
                "reservation_id": reservation_id,
                "request_id": document["request_id"],
                "request_digest": request_digest,
                "account_id": document["account_id"],
                "account_version": account_version,
                "assessment_id": manifest["assessment_id"],
                "plan_id": manifest["plan_id"],
                "plan_revision": manifest["plan_revision"],
                "task_id": manifest["task_id"],
                "task_revision": manifest["task_revision"],
                "task_state": "ready",
                "agent_id": manifest["agent_id"],
                "capability_manifest_id": manifest["manifest_id"],
                "capability_manifest_digest": document["capability_manifest_digest"],
                "manifest_revision": manifest["manifest_revision"],
                **{
                    field: manifest[field]
                    for field in (
                        "retry_policy_id", "retry_policy_digest", "retry_activation_id",
                        "retry_activation_digest", "retry_schedule_id", "retry_schedule_digest",
                        "retry_attempt_id", "retry_attempt_digest", "attempt_number",
                        "prior_retry_budget_consumption_id", "retry_budget_consumption_id",
                        "approval_consumption_id", "worker_id", "worker_version",
                        "lease_generation", "fencing_token", "recovery_generation",
                    )
                },
                "policy_bundle_id": manifest["policy_bundle_id"],
                "policy_hash": manifest["policy_hash"],
                "purpose": document["purpose"],
                "amounts": document["amounts"],
                "state": "reserved",
                "created_at": document["requested_at"],
                "expires_at": document["expires_at"],
                "released_at": None,
                "release_reason": "none",
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(receipt, "orchestration-task-budget-reservation-v4.schema.json"):
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_RESULT_INVALID", "budget receipt is invalid"
                )
            connection.execute(
                "UPDATE orchestration_budget_accounts SET version=? WHERE account_id=?",
                (account_version, document["account_id"]),
            )
            try:
                connection.execute(
                    """INSERT INTO orchestration_task_budget_reservations_v4 (
                    reservation_id, request_id, request_digest, account_id, account_version,
                    assessment_id, plan_id, plan_revision, task_id, task_revision, agent_id,
                    capability_manifest_id, retry_activation_id, retry_attempt_id,
                    policy_bundle_id, policy_hash, purpose, amounts_json, state, created_at,
                    expires_at, released_at, release_reason, receipt_json, authority,
                    execution_enabled) VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?,
                    NULL, 'none', ?, 'none', 0)""",
                    (
                        reservation_id, document["request_id"], request_digest,
                        document["account_id"], account_version, manifest["assessment_id"],
                        manifest["plan_id"], manifest["plan_revision"], manifest["task_id"],
                        manifest["task_revision"], manifest["agent_id"], manifest["manifest_id"],
                        manifest["retry_activation_id"], manifest["retry_attempt_id"],
                        manifest["policy_bundle_id"], manifest["policy_hash"], document["purpose"],
                        canonical_json(document["amounts"]), document["requested_at"],
                        document["expires_at"], canonical_json(receipt),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_CONFLICT", "budget reservation conflicts"
                ) from error
            _audit(
                connection,
                "orchestration.attempt_three_task_budget_reserved",
                reservation_id,
                _audit_data(receipt, manifest),
            )
        return copy.deepcopy(receipt)

    def _validate_current_v4(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> tuple[sqlite3.Row, dict[str, Any]]:
        self._validate_assessment_policy(
            connection, document["assessment_id"], document["policy_bundle_id"],
            document["policy_hash"], instant
        )
        account = connection.execute(
            "SELECT * FROM orchestration_budget_accounts WHERE account_id=?",
            (document["account_id"],),
        ).fetchone()
        if account is None:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_ACCOUNT_MISSING", "account is missing"
            )
        if (
            account["assessment_id"] != document["assessment_id"]
            or account["policy_bundle_id"] != document["policy_bundle_id"]
            or account["policy_hash"] != document["policy_hash"]
            or parse_time(account["expires_at"]) <= instant
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_ACCOUNT_MISMATCH", "account binding mismatches"
            )
        row = connection.execute(
            "SELECT * FROM task_capability_manifests_v4 WHERE manifest_id=?",
            (document["capability_manifest_id"],),
        ).fetchone()
        if row is None:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_MANIFEST_MISSING", "manifest is missing"
            )
        try:
            manifest = OrchestrationRetryManifestService._load_manifest_v4(row)
            activation, schedule, agent_id = OrchestrationRetryManifestService(
                self.authorization
            )._load_activation_v2(connection, {
                "retry_activation_id": document["retry_activation_id"],
                "retry_activation_digest": document["retry_activation_digest"],
                "assessment_id": document["assessment_id"],
                "plan_id": document["plan_id"],
                "expected_plan_revision": document["expected_plan_revision"],
                "task_id": document["task_id"],
                "expected_task_revision": document["expected_task_revision"],
                "policy_bundle_id": document["policy_bundle_id"],
                "policy_hash": document["policy_hash"],
                "agent_id": document["agent_id"],
            }, instant)
            OrchestrationRetryManifestService._validate_replay_v4(
                connection, manifest, activation, schedule, instant
            )
        except OrchestrationRetryManifestError as error:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_RETRY_INVALID", "retry lineage is invalid"
            ) from error
        if (
            row["manifest_hash"] != document["capability_manifest_digest"][7:]
            or manifest["manifest_revision"] != document["expected_manifest_revision"]
            or manifest["agent_id"] != agent_id
            or manifest["retry_attempt_id"] != document["retry_attempt_id"]
            or manifest["retry_attempt_digest"] != document["retry_attempt_digest"]
            or manifest["attempt_number"] != 3
            or manifest["task_state"] != "ready"
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_RETRY_MISMATCH", "retry binding mismatches"
            )
        return account, manifest

    def _validate_reservation_replay_v4(
        self, connection: sqlite3.Connection, receipt: dict[str, Any], instant: datetime
    ) -> None:
        row = connection.execute(
            "SELECT * FROM orchestration_task_budget_reservations_v4 WHERE reservation_id=?",
            (receipt.get("reservation_id"),),
        ).fetchone()
        account = connection.execute(
            "SELECT * FROM orchestration_budget_accounts WHERE account_id=?",
            (receipt.get("account_id"),),
        ).fetchone()
        manifest_row = connection.execute(
            "SELECT * FROM task_capability_manifests_v4 WHERE manifest_id=?",
            (receipt.get("capability_manifest_id"),),
        ).fetchone()
        try:
            self._validate_assessment_policy(
                connection, receipt["assessment_id"], receipt["policy_bundle_id"],
                receipt["policy_hash"], instant
            )
            manifest = (
                OrchestrationRetryManifestService._load_manifest_v4(manifest_row)
                if manifest_row is not None else None
            )
        except (KeyError, OrchestrationBudgetError, OrchestrationRetryManifestError) as error:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REPLAY_FENCED", "reservation replay is fenced"
            ) from error
        plan = connection.execute(
            "SELECT state, revision FROM orchestration_plans WHERE plan_id=?",
            (receipt.get("plan_id"),),
        ).fetchone()
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE task_id=?",
            (receipt.get("task_id"),),
        ).fetchone()
        worker = connection.execute(
            "SELECT status, version FROM worker_runtime_instances WHERE worker_id=?",
            (receipt.get("worker_id"),),
        ).fetchone()
        fence = connection.execute(
            """SELECT current_lease_generation, recovery_generation
            FROM orchestration_task_lease_fences WHERE task_id=?""",
            (receipt.get("task_id"),),
        ).fetchone()
        lease = connection.execute(
            """SELECT 1 FROM orchestration_task_leases
            WHERE task_id=? AND lease_generation=? AND fencing_token=? AND worker_id=?""",
            (
                receipt.get("task_id"), receipt.get("lease_generation"),
                receipt.get("fencing_token"), receipt.get("worker_id"),
            ),
        ).fetchone()
        approval_valid = True
        if receipt.get("approval_consumption_id") is not None:
            approval = connection.execute(
                """SELECT approval_expires_at FROM orchestration_task_approval_consumptions
                WHERE consumption_id=?""",
                (receipt["approval_consumption_id"],),
            ).fetchone()
            approval_valid = (
                approval is not None and parse_time(approval["approval_expires_at"]) > instant
            )
        manifest_matches = manifest is not None and all(
            receipt.get(field) == manifest.get(field)
            for field in (
                "assessment_id", "plan_id", "plan_revision", "task_id", "task_revision",
                "task_state", "agent_id", "policy_bundle_id", "policy_hash",
                "retry_policy_id", "retry_policy_digest", "retry_activation_id",
                "retry_activation_digest", "retry_schedule_id", "retry_schedule_digest",
                "retry_attempt_id", "retry_attempt_digest", "attempt_number",
                "prior_retry_budget_consumption_id", "retry_budget_consumption_id",
                "approval_consumption_id", "worker_id", "worker_version",
                "lease_generation", "fencing_token", "recovery_generation",
            )
        )
        if (
            contract_issues(receipt, "orchestration-task-budget-reservation-v4.schema.json")
            or row is None or row["receipt_json"] != canonical_json(receipt)
            or row["account_version"] != receipt["account_version"]
            or row["assessment_id"] != receipt["assessment_id"]
            or row["plan_id"] != receipt["plan_id"]
            or row["plan_revision"] != receipt["plan_revision"]
            or row["task_id"] != receipt["task_id"]
            or row["task_revision"] != receipt["task_revision"]
            or row["agent_id"] != receipt["agent_id"]
            or row["capability_manifest_id"] != receipt["capability_manifest_id"]
            or row["retry_activation_id"] != receipt["retry_activation_id"]
            or row["retry_attempt_id"] != receipt["retry_attempt_id"]
            or json.loads(row["amounts_json"]) != receipt["amounts"]
            or row["state"] != "reserved" or parse_time(row["expires_at"]) <= instant
            or account is None or account["version"] != receipt["account_version"]
            or parse_time(account["expires_at"]) <= instant
            or manifest is None
            or not manifest_matches
            or manifest_row["manifest_hash"]
            != receipt["capability_manifest_digest"][7:]
            or parse_time(manifest["expires_at"]) <= instant
            or plan is None or tuple(plan) != ("active", receipt["plan_revision"])
            or task is None or tuple(task) != ("ready", receipt["task_revision"])
            or worker is None
            or tuple(worker) != ("running", receipt["worker_version"])
            or fence is None
            or fence["current_lease_generation"] != receipt["lease_generation"]
            or fence["recovery_generation"] != receipt["recovery_generation"]
            or lease is None
            or not approval_valid
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REPLAY_FENCED", "reservation replay is fenced"
            )

    def recover_v4(self, *, now: datetime | None = None) -> tuple[dict[str, Any], ...]:
        """Release stale attempt-three reservations without restoring retry capacity."""
        instant = _instant(now)
        released: list[dict[str, Any]] = []
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT * FROM orchestration_task_budget_reservations_v4
                WHERE state='reserved' ORDER BY reservation_id"""
            ).fetchall()
            for row in rows:
                receipt = cast(dict[str, Any], json.loads(row["receipt_json"]))
                reason = "expired" if parse_time(row["expires_at"]) <= instant else None
                if reason is None:
                    try:
                        self._validate_reservation_replay_v4(connection, receipt, instant)
                    except OrchestrationBudgetError:
                        task = connection.execute(
                            "SELECT state FROM orchestration_tasks WHERE task_id=?",
                            (row["task_id"],),
                        ).fetchone()
                        reason = (
                            "cancelled"
                            if task is not None
                            and task["state"] in {"cancelling", "cancelled", "succeeded", "failed"}
                            else "recovery"
                        )
                if reason is None:
                    continue
                account = connection.execute(
                    "SELECT version FROM orchestration_budget_accounts WHERE account_id=?",
                    (row["account_id"],),
                ).fetchone()
                if account is None:
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_RECOVERY_INVALID", "account is missing"
                    )
                version = int(account["version"]) + 1
                receipt["account_version"] = version
                receipt["state"] = "released"
                receipt["released_at"] = _timestamp(instant)
                receipt["release_reason"] = reason
                if contract_issues(
                    receipt, "orchestration-task-budget-reservation-v4.schema.json"
                ):
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_RECOVERY_INVALID", "reservation is invalid"
                    )
                connection.execute(
                    "UPDATE orchestration_budget_accounts SET version=? WHERE account_id=?",
                    (version, row["account_id"]),
                )
                connection.execute(
                    """UPDATE orchestration_task_budget_reservations_v4
                    SET account_version=?, state='released', released_at=?, release_reason=?,
                    receipt_json=? WHERE reservation_id=? AND state='reserved'""",
                    (
                        version, receipt["released_at"], reason, canonical_json(receipt),
                        row["reservation_id"],
                    ),
                )
                _audit(
                    connection, "orchestration.attempt_three_task_budget_released",
                    row["reservation_id"], receipt
                )
                released.append(copy.deepcopy(receipt))
        return tuple(released)

    @staticmethod
    def _used_capacity(
        connection: sqlite3.Connection, account_id: str, task_id: str
    ) -> tuple[dict[str, int], dict[str, int]]:
        used = {field: 0 for field in _FIELDS}
        task_used = {field: 0 for field in _FIELDS}
        rows = connection.execute(
            """SELECT r.task_id, r.amounts_json, r.state,
            (SELECT COALESCE(SUM(c1.consumed_retry_units), 0)
             FROM orchestration_retry_budget_consumptions c1
             WHERE c1.budget_reservation_id = r.reservation_id)
            + (SELECT COALESCE(SUM(c2.consumed_retry_units), 0)
               FROM orchestration_retry_budget_consumptions_v2 c2
               WHERE c2.capacity_budget_reservation_id = r.reservation_id) AS consumed_retries
            FROM orchestration_task_budget_reservations r WHERE r.account_id=?
            GROUP BY r.reservation_id, r.task_id, r.amounts_json, r.state
            UNION ALL
            SELECT task_id, amounts_json, state, 0
            FROM orchestration_task_budget_reservations_v4 WHERE account_id=?""",
            (account_id, account_id),
        ).fetchall()
        for row in rows:
            amounts = json.loads(row["amounts_json"])
            for field in _FIELDS:
                amount = (
                    amounts[field] if row["state"] == "reserved"
                    else row["consumed_retries"] if field == "retries" else 0
                )
                used[field] += amount
                if row["task_id"] == task_id:
                    task_used[field] += amount
        return used, task_used

    def recover(self, *, now: datetime | None = None) -> tuple[dict[str, Any], ...]:
        instant = _instant(now)
        released: list[dict[str, Any]] = []
        self.authorization._require_storage_safe()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT * FROM orchestration_task_budget_reservations
                WHERE state = 'reserved' ORDER BY reservation_id"""
            ).fetchall()
            for row in rows:
                receipt = json.loads(row["receipt_json"])
                try:
                    receipt_schema = _reservation_schema(receipt)
                except OrchestrationBudgetError as error:
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_RECOVERY_INVALID", "reservation is invalid"
                    ) from error
                if (
                    contract_issues(receipt, receipt_schema)
                    or receipt["reservation_id"] != row["reservation_id"]
                    or receipt["request_id"] != row["request_id"]
                    or receipt["request_digest"] != row["request_digest"]
                    or receipt["account_id"] != row["account_id"]
                    or receipt["state"] != "reserved"
                    or receipt["amounts"] != json.loads(row["amounts_json"])
                    or receipt.get("task_state", "running") != row["task_state"]
                ):
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_RECOVERY_INVALID", "reservation is invalid"
                    )
                reason = "expired" if parse_time(row["expires_at"]) <= instant else None
                if reason is None:
                    task = connection.execute(
                        "SELECT state FROM orchestration_tasks WHERE task_id = ?",
                        (row["task_id"],),
                    ).fetchone()
                    try:
                        self._validate_current(connection, _request_from_receipt(receipt), instant)
                    except OrchestrationBudgetError:
                        reason = (
                            "cancelled"
                            if task is not None
                            and task["state"]
                            in {"cancelling", "cancelled", "succeeded", "failed"}
                            else "recovery"
                        )
                if reason is None:
                    continue
                account = connection.execute(
                    "SELECT version FROM orchestration_budget_accounts WHERE account_id = ?",
                    (row["account_id"],),
                ).fetchone()
                if account is None:
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_RECOVERY_INVALID", "account is missing"
                    )
                new_version = int(account["version"]) + 1
                receipt["account_version"] = new_version
                receipt["state"] = "released"
                receipt["released_at"] = _timestamp(instant)
                receipt["release_reason"] = reason
                if contract_issues(receipt, _reservation_schema(receipt)):
                    raise OrchestrationBudgetError(
                        "ORCHESTRATION_BUDGET_RECOVERY_INVALID", "release receipt is invalid"
                    )
                connection.execute(
                    "UPDATE orchestration_budget_accounts SET version = ? WHERE account_id = ?",
                    (new_version, row["account_id"]),
                )
                connection.execute(
                    """UPDATE orchestration_task_budget_reservations SET account_version = ?,
                    state = 'released', released_at = ?, release_reason = ?, receipt_json = ?
                    WHERE reservation_id = ? AND state = 'reserved'""",
                    (
                        new_version,
                        receipt["released_at"],
                        reason,
                        canonical_json(receipt),
                        row["reservation_id"],
                    ),
                )
                _audit(
                    connection,
                    "orchestration.task_budget_released",
                    row["reservation_id"],
                    receipt,
                )
                released.append(copy.deepcopy(receipt))
        return tuple(released)

    def _verified_policy(
        self, assessment_id: str, policy_bundle_id: str, policy_hash: str, instant: datetime
    ) -> dict[str, Any]:
        try:
            verified = self.authorization.get_policy(assessment_id, policy_bundle_id)
        except DomainError as error:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_POLICY_INVALID", "policy is invalid"
            ) from error
        if (
            verified["status"] != "active"
            or verified["content_hash"] != policy_hash
            or parse_time(verified["policy"]["validity"]["not_after"]) <= instant
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_POLICY_STALE", "policy is stale"
            )
        return verified

    @staticmethod
    def _validate_assessment_policy(
        connection: sqlite3.Connection,
        assessment_id: str,
        policy_bundle_id: str,
        policy_hash: str,
        instant: datetime,
    ) -> None:
        engagement = connection.execute(
            "SELECT * FROM engagements WHERE id = ?", (assessment_id,)
        ).fetchone()
        safety = connection.execute(
            "SELECT global_status FROM safety_state WHERE singleton_id = 1"
        ).fetchone()
        policy = connection.execute(
            "SELECT * FROM policy_bundles WHERE id = ? AND engagement_id = ?",
            (policy_bundle_id, assessment_id),
        ).fetchone()
        if (
            engagement is None
            or engagement["status"] != "active"
            or engagement["active_policy_id"] != policy_bundle_id
            or parse_time(engagement["expires_at"]) <= instant
            or safety is None
            or safety["global_status"] != "active"
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_SAFETY_DENIED", "assessment safety denies"
            )
        if (
            policy is None
            or policy["content_hash"] != policy_hash
            or policy["activated_at"] is None
            or policy["revoked_at"] is not None
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_POLICY_STALE", "policy is stale"
            )

    def _validate_current(
        self, connection: sqlite3.Connection, document: dict[str, Any], instant: datetime
    ) -> tuple[sqlite3.Row, dict[str, Any]]:
        self._validate_assessment_policy(
            connection,
            document["assessment_id"],
            document["policy_bundle_id"],
            document["policy_hash"],
            instant,
        )
        account = connection.execute(
            "SELECT * FROM orchestration_budget_accounts WHERE account_id = ?",
            (document["account_id"],),
        ).fetchone()
        if account is None:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_ACCOUNT_MISSING", "account is missing"
            )
        if (
            account["assessment_id"] != document["assessment_id"]
            or account["policy_bundle_id"] != document["policy_bundle_id"]
            or account["policy_hash"] != document["policy_hash"]
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_ACCOUNT_MISMATCH", "account binding mismatches"
            )
        if parse_time(account["expires_at"]) <= instant:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_ACCOUNT_STALE", "account is stale"
            )
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id = ?", (document["plan_id"],)
        ).fetchone()
        task = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id = ? AND task_id = ?",
            (document["plan_id"], document["task_id"]),
        ).fetchone()
        if plan is None or plan["assessment_id"] != document["assessment_id"]:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_PLAN_MISMATCH", "plan binding mismatches"
            )
        if plan["state"] != "active" or plan["revision"] != document["expected_plan_revision"]:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_PLAN_FENCED", "plan is not current"
            )
        if task is None or task["assessment_id"] != document["assessment_id"]:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_TASK_MISMATCH", "task binding mismatches"
            )
        expected_task_state = document.get("task_state", "running")
        if (
            task["state"] != expected_task_state
            or expected_task_state not in {"ready", "running"}
            or task["task_type"] != "validation"
            or task["revision"] != document["expected_task_revision"]
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_TASK_FENCED", "task is not current"
            )
        manifest_row = connection.execute(
            """SELECT manifest_json, manifest_hash FROM task_capability_manifests
            WHERE manifest_id = ? AND manifest_revision = ?""",
            (document["capability_manifest_id"], document["expected_manifest_revision"]),
        ).fetchone()
        if manifest_row is None:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_MANIFEST_MISSING", "manifest is missing"
            )
        manifest = json.loads(manifest_row["manifest_json"])
        if (
            content_hash(manifest) != manifest_row["manifest_hash"]
            or contract_issues(manifest, _manifest_schema(manifest))
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_MANIFEST_INVALID", "manifest is invalid"
            )
        if document["schema_version"] == "3.0.0":
            if (
                manifest_row["manifest_hash"] != document["capability_manifest_digest"][7:]
                or manifest["schema_version"] != "3.0.0"
                or manifest["retry_activation_id"] != document["retry_activation_id"]
                or manifest["retry_activation_digest"] != document["retry_activation_digest"]
                or manifest["retry_attempt_id"] != document["retry_attempt_id"]
                or manifest["retry_attempt_digest"] != document["retry_attempt_digest"]
                or manifest["retry_budget_consumption_id"]
                != document["retry_budget_consumption_id"]
            ):
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_RETRY_MISMATCH", "retry binding mismatches"
                )
            retry_manifests = OrchestrationRetryManifestService(self.authorization)
            try:
                activation = retry_manifests._load_activation(
                    connection,
                    activation_id=document["retry_activation_id"],
                    activation_digest=document["retry_activation_digest"],
                    assessment_id=document["assessment_id"],
                    plan_id=document["plan_id"],
                    plan_revision=document["expected_plan_revision"],
                    task_id=document["task_id"],
                    task_revision=document["expected_task_revision"],
                    policy_bundle_id=document["policy_bundle_id"],
                    policy_hash=document["policy_hash"],
                    instant=instant,
                )
                retry_manifests._validate_replay(connection, manifest, activation, instant)
            except OrchestrationRetryManifestError as error:
                raise OrchestrationBudgetError(
                    "ORCHESTRATION_BUDGET_RETRY_INVALID", "retry lineage is invalid"
                ) from error
        if (
            manifest["assessment_id"] != document["assessment_id"]
            or manifest["plan_id"] != document["plan_id"]
            or manifest["plan_revision"] != document["expected_plan_revision"]
            or manifest["task_id"] != document["task_id"]
            or manifest["task_revision"] != document["expected_task_revision"]
            or manifest.get("task_state", "running") != expected_task_state
            or manifest["agent_id"] != document["agent_id"]
            or manifest["policy_bundle_id"] != document["policy_bundle_id"]
            or manifest["policy_hash"] != document["policy_hash"]
            or parse_time(manifest["expires_at"]) <= instant
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_MANIFEST_MISMATCH", "manifest binding mismatches"
            )
        return account, manifest

    def _validate_reservation_replay(
        self, connection: sqlite3.Connection, receipt: dict[str, Any], instant: datetime
    ) -> None:
        try:
            schema = _reservation_schema(receipt)
        except OrchestrationBudgetError as error:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REPLAY_FENCED", "reservation replay is invalid"
            ) from error
        row = connection.execute(
            "SELECT * FROM orchestration_task_budget_reservations WHERE reservation_id=?",
            (receipt.get("reservation_id"),),
        ).fetchone()
        account = connection.execute(
            "SELECT * FROM orchestration_budget_accounts WHERE account_id=?",
            (receipt.get("account_id"),),
        ).fetchone()
        plan = connection.execute(
            "SELECT state, revision FROM orchestration_plans WHERE plan_id=?",
            (receipt.get("plan_id"),),
        ).fetchone()
        task = connection.execute(
            "SELECT state, revision FROM orchestration_tasks WHERE plan_id=? AND task_id=?",
            (receipt.get("plan_id"), receipt.get("task_id")),
        ).fetchone()
        manifest = connection.execute(
            "SELECT manifest_hash, expires_at FROM task_capability_manifests WHERE manifest_id=?",
            (receipt.get("capability_manifest_id"),),
        ).fetchone()
        try:
            self._validate_assessment_policy(
                connection,
                receipt["assessment_id"],
                receipt["policy_bundle_id"],
                receipt["policy_hash"],
                instant,
            )
        except (KeyError, OrchestrationBudgetError) as error:
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REPLAY_FENCED", "reservation replay is fenced"
            ) from error
        if (
            contract_issues(receipt, schema)
            or row is None
            or row["receipt_json"] != canonical_json(receipt)
            or row["state"] != "reserved"
            or parse_time(row["expires_at"]) <= instant
            or account is None
            or parse_time(account["expires_at"]) <= instant
            or plan is None
            or tuple(plan) != ("active", receipt["plan_revision"])
            or task is None
            or tuple(task) != (receipt.get("task_state", "running"), receipt["task_revision"])
            or manifest is None
            or parse_time(manifest["expires_at"]) <= instant
            or (
                "capability_manifest_digest" in receipt
                and manifest["manifest_hash"] != receipt["capability_manifest_digest"][7:]
            )
        ):
            raise OrchestrationBudgetError(
                "ORCHESTRATION_BUDGET_REPLAY_FENCED", "reservation replay is fenced"
            )

    @staticmethod
    def _account_document(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "account_id": row["account_id"],
            "assessment_id": row["assessment_id"],
            "configuration_id": row["configuration_id"],
            "configuration_hash": row["configuration_hash"],
            "registry_id": row["registry_id"],
            "registry_revision": row["registry_revision"],
            "policy_bundle_id": row["policy_bundle_id"],
            "policy_hash": row["policy_hash"],
            "ceilings": json.loads(row["ceilings_json"]),
            "version": row["version"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "authority": "none",
            "execution_enabled": False,
        }


def _request_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    request = {
        "account_id": receipt["account_id"],
        "assessment_id": receipt["assessment_id"],
        "plan_id": receipt["plan_id"],
        "expected_plan_revision": receipt["plan_revision"],
        "task_id": receipt["task_id"],
        "expected_task_revision": receipt["task_revision"],
        **({"task_state": receipt["task_state"]} if "task_state" in receipt else {}),
        "agent_id": receipt["agent_id"],
        "capability_manifest_id": receipt["capability_manifest_id"],
        "expected_manifest_revision": receipt["manifest_revision"],
        "policy_bundle_id": receipt["policy_bundle_id"],
        "policy_hash": receipt["policy_hash"],
    }
    for field in (
        "capability_manifest_digest",
        "retry_activation_id",
        "retry_activation_digest",
        "retry_attempt_id",
        "retry_attempt_digest",
        "retry_budget_consumption_id",
    ):
        if field in receipt:
            request[field] = receipt[field]
    return request


def _audit_data(receipt: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "assessment_id": receipt["assessment_id"],
        "plan_id": receipt["plan_id"],
        "task_id": receipt["task_id"],
        "manifest_id": manifest["manifest_id"],
        "account_id": receipt["account_id"],
        "account_version": receipt["account_version"],
        "amounts": receipt["amounts"],
        "created_at": receipt["created_at"],
        "authority": "none",
        "execution_enabled": False,
    }


def _audit(
    connection: sqlite3.Connection, action: str, subject_id: str, data: dict[str, Any]
) -> None:
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else None
    occurred_at = data.get("released_at") or data.get("created_at") or _timestamp(datetime.now(UTC))
    event = {
        "event_id": str(uuid4()),
        "occurred_at": occurred_at,
        "actor_type": "service",
        "actor_id": "pentai-core",
        "action": action,
        "subject_type": "orchestration_task_budget",
        "subject_id": subject_id,
        "data": data,
        "previous_hash": previous_hash,
    }
    event_hash = content_hash(event)
    connection.execute(
        """INSERT INTO audit_events(event_id, occurred_at, actor_type, actor_id, action,
        subject_type, subject_id, data_json, previous_hash, event_hash)
        VALUES (?, ?, 'service', 'pentai-core', ?, 'orchestration_task_budget', ?, ?, ?, ?)""",
        (
            event["event_id"],
            occurred_at,
            action,
            subject_id,
            canonical_json(data),
            previous_hash,
            event_hash,
        ),
    )
    connection.execute(
        """INSERT INTO outbox(id, aggregate_type, aggregate_id, event_type, payload_json)
        VALUES (?, 'orchestration_task_budget', ?, ?, ?)""",
        (
            str(uuid4()),
            subject_id,
            action,
            canonical_json(
                {"event_hash": event_hash, "occurred_at": occurred_at, "subject_id": subject_id}
            ),
        ),
    )


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise OrchestrationBudgetError(
            "ORCHESTRATION_BUDGET_CLOCK_INVALID", "clock is invalid"
        )
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _request_schema(document: dict[str, Any]) -> str:
    version = document.get("schema_version")
    if version == "1.0.0":
        return "orchestration-task-budget-request-v1.schema.json"
    if version == "2.0.0":
        return "orchestration-task-budget-request-v2.schema.json"
    if version == "3.0.0":
        return "orchestration-task-budget-request-v3.schema.json"
    raise OrchestrationBudgetError(
        "ORCHESTRATION_BUDGET_REQUEST_MALFORMED", "budget request version is unsupported"
    )


def _reservation_schema(document: dict[str, Any]) -> str:
    version = document.get("schema_version")
    if version == "1.0.0":
        return "orchestration-task-budget-reservation-v1.schema.json"
    if version == "2.0.0":
        return "orchestration-task-budget-reservation-v2.schema.json"
    if version == "3.0.0":
        return "orchestration-task-budget-reservation-v3.schema.json"
    raise OrchestrationBudgetError(
        "ORCHESTRATION_BUDGET_RESULT_INVALID", "budget receipt version is unsupported"
    )


def _manifest_schema(document: dict[str, Any]) -> str:
    version = document.get("schema_version")
    if version == "1.0.0":
        return "task-capability-manifest-v1.schema.json"
    if version == "2.0.0":
        return "task-capability-manifest-v2.schema.json"
    if version == "3.0.0":
        return "task-capability-manifest-v3.schema.json"
    raise OrchestrationBudgetError(
        "ORCHESTRATION_BUDGET_MANIFEST_INVALID", "manifest version is unsupported"
    )
