from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues, parse_time

from pentai_core.ai_provider_config import ProviderPolicy, validate_provider_configuration


class AIBudgetError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_FIELDS = ("input_tokens", "output_tokens", "requests", "cost_microusd", "runtime_seconds")
_CONFIGURATION_FIELDS = {
    "input_tokens": "max_input_tokens",
    "output_tokens": "max_output_tokens",
    "requests": "max_requests",
    "cost_microusd": "max_cost_microusd",
    "runtime_seconds": "max_runtime_seconds",
}
_MAX_RESERVATION_LIFETIME = timedelta(minutes=5)
_MAX_REQUEST_AGE = timedelta(minutes=1)


class AIBudgetLedger:
    """Thread-safe, non-executing budget reservations for one provider configuration."""

    def __init__(
        self,
        *,
        configuration: dict[str, Any],
        policy: ProviderPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._configuration = copy.deepcopy(configuration)
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = RLock()
        self._version = 0
        self._records: dict[str, dict[str, Any]] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._used = {field: 0 for field in _FIELDS}
        validate_provider_configuration(self._configuration, policy=policy, now=self._now())

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def reserve(self, request: dict[str, Any]) -> dict[str, Any]:
        if contract_issues(request, "ai-budget-reservation-request-v1.schema.json"):
            raise AIBudgetError("AI_BUDGET_REQUEST_MALFORMED", "budget request is malformed")
        fingerprint = _fingerprint(request)
        with self._lock:
            existing = self._idempotency.get(request["idempotency_key"])
            if existing is not None:
                existing_fingerprint, reservation_id = existing
                if existing_fingerprint != fingerprint:
                    raise AIBudgetError(
                        "AI_BUDGET_IDEMPOTENCY_CONFLICT", "idempotency key conflicts"
                    )
                return copy.deepcopy(self._records[reservation_id])
            instant = self._now()
            self._validate_current_authority(request, now=instant)
            if request["expected_ledger_version"] != self._version:
                raise AIBudgetError("AI_BUDGET_VERSION_STALE", "ledger version is stale")
            requested_at = parse_time(request["requested_at"])
            expires_at = parse_time(request["expires_at"])
            if requested_at > instant or instant - requested_at > _MAX_REQUEST_AGE:
                raise AIBudgetError("AI_BUDGET_REQUEST_STALE", "budget request is stale")
            if (
                expires_at <= instant
                or expires_at <= requested_at
                or expires_at - requested_at > _MAX_RESERVATION_LIFETIME
                or expires_at > parse_time(self._configuration["expires_at"])
            ):
                raise AIBudgetError("AI_BUDGET_REQUEST_STALE", "reservation lifetime is invalid")
            amounts = request["amounts"]
            if not any(amounts[field] > 0 for field in _FIELDS):
                raise AIBudgetError("AI_BUDGET_AMOUNT_INVALID", "reservation is empty")
            ceilings = self._configuration["budgets"]
            for field in _FIELDS:
                if self._used[field] + amounts[field] > ceilings[_CONFIGURATION_FIELDS[field]]:
                    raise AIBudgetError("AI_BUDGET_EXCEEDED", f"{field} budget is exhausted")
            self._version += 1
            reservation_id = str(uuid4())
            record: dict[str, Any] = {
                "schema_version": "1.0.0",
                "reservation_id": reservation_id,
                "configuration_id": request["configuration_id"],
                "registry_id": request["registry_id"],
                "registry_revision": request["registry_revision"],
                "idempotency_key": request["idempotency_key"],
                "request_fingerprint": fingerprint,
                "ledger_version": self._version,
                "state": "reserved",
                "amounts": copy.deepcopy(amounts),
                "created_at": request["requested_at"],
                "expires_at": request["expires_at"],
                "finalized_at": None,
                "execution_enabled": False,
            }
            if contract_issues(record, "ai-budget-reservation-v1.schema.json"):
                raise AIBudgetError("AI_BUDGET_RECORD_INVALID", "budget record is invalid")
            for field in _FIELDS:
                self._used[field] += amounts[field]
            self._records[reservation_id] = record
            self._idempotency[request["idempotency_key"]] = (fingerprint, reservation_id)
            return copy.deepcopy(record)

    def commit(self, reservation_id: str, *, expected_version: int) -> dict[str, Any]:
        return self._finalize(
            reservation_id, expected_version=expected_version, target_state="committed"
        )

    def release(self, reservation_id: str, *, expected_version: int) -> dict[str, Any]:
        return self._finalize(
            reservation_id, expected_version=expected_version, target_state="released"
        )

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(
                copy.deepcopy(record)
                for record in sorted(
                    self._records.values(), key=lambda item: item["reservation_id"]
                )
            )

    @classmethod
    def recover(
        cls,
        records: Iterable[dict[str, Any]],
        *,
        configuration: dict[str, Any],
        policy: ProviderPolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> AIBudgetLedger:
        ledger = cls(configuration=configuration, policy=policy, clock=clock)
        instant = ledger._now()
        seen_versions: set[int] = set()
        expired_reservations: list[str] = []
        for source in records:
            record = copy.deepcopy(source)
            if contract_issues(record, "ai-budget-reservation-v1.schema.json"):
                raise AIBudgetError("AI_BUDGET_RECOVERY_INVALID", "recovery record is invalid")
            ledger._validate_record_authority(record)
            if (
                record["reservation_id"] in ledger._records
                or record["idempotency_key"] in ledger._idempotency
                or record["ledger_version"] in seen_versions
            ):
                raise AIBudgetError("AI_BUDGET_RECOVERY_AMBIGUOUS", "recovery is ambiguous")
            seen_versions.add(record["ledger_version"])
            is_expired = (
                record["state"] == "reserved" and parse_time(record["expires_at"]) <= instant
            )
            if record["state"] != "released" and not is_expired:
                for field in _FIELDS:
                    ledger._used[field] += record["amounts"][field]
                    ceiling = configuration["budgets"][_CONFIGURATION_FIELDS[field]]
                    if ledger._used[field] > ceiling:
                        raise AIBudgetError(
                            "AI_BUDGET_RECOVERY_EXCEEDED", "recovery exceeds budget"
                        )
            ledger._records[record["reservation_id"]] = record
            ledger._idempotency[record["idempotency_key"]] = (
                record["request_fingerprint"],
                record["reservation_id"],
            )
            ledger._version = max(ledger._version, record["ledger_version"])
            if is_expired:
                expired_reservations.append(record["reservation_id"])
        for reservation_id in sorted(expired_reservations):
            ledger._version += 1
            record = copy.deepcopy(ledger._records[reservation_id])
            record["ledger_version"] = ledger._version
            record["state"] = "released"
            record["finalized_at"] = _timestamp(instant)
            ledger._records[reservation_id] = record
        return ledger

    def _finalize(
        self, reservation_id: str, *, expected_version: int, target_state: str
    ) -> dict[str, Any]:
        with self._lock:
            record = self._records.get(reservation_id)
            if record is None:
                raise AIBudgetError("AI_BUDGET_RESERVATION_UNKNOWN", "reservation is unknown")
            if record["state"] == target_state:
                return copy.deepcopy(record)
            if record["state"] != "reserved":
                raise AIBudgetError("AI_BUDGET_STATE_CONFLICT", "reservation is finalized")
            if expected_version != self._version:
                raise AIBudgetError("AI_BUDGET_VERSION_STALE", "ledger version is stale")
            instant = self._now()
            validate_provider_configuration(self._configuration, policy=self._policy, now=instant)
            if target_state == "committed" and parse_time(record["expires_at"]) <= instant:
                raise AIBudgetError("AI_BUDGET_RESERVATION_EXPIRED", "reservation has expired")
            self._version += 1
            updated = copy.deepcopy(record)
            updated["ledger_version"] = self._version
            updated["state"] = target_state
            updated["finalized_at"] = _timestamp(instant)
            if target_state == "released":
                for field in _FIELDS:
                    self._used[field] -= updated["amounts"][field]
            self._records[reservation_id] = updated
            return copy.deepcopy(updated)

    def _validate_current_authority(self, request: dict[str, Any], *, now: datetime) -> None:
        validate_provider_configuration(self._configuration, policy=self._policy, now=now)
        if (
            request["configuration_id"] != self._configuration["configuration_id"]
            or request["registry_id"] != self._policy.registry_id
            or request["registry_revision"] != self._policy.registry_revision
        ):
            raise AIBudgetError("AI_BUDGET_AUTHORITY_MISMATCH", "budget authority mismatches")

    def _validate_record_authority(self, record: dict[str, Any]) -> None:
        if (
            record["configuration_id"] != self._configuration["configuration_id"]
            or record["registry_id"] != self._policy.registry_id
            or record["registry_revision"] != self._policy.registry_revision
        ):
            raise AIBudgetError("AI_BUDGET_RECOVERY_MISMATCH", "recovery authority mismatches")
        created_at = parse_time(record["created_at"])
        expires_at = parse_time(record["expires_at"])
        finalized_at = (
            parse_time(record["finalized_at"]) if record["finalized_at"] is not None else None
        )
        if (
            expires_at <= created_at
            or expires_at - created_at > _MAX_RESERVATION_LIFETIME
            or expires_at > parse_time(self._configuration["expires_at"])
            or not any(record["amounts"][field] > 0 for field in _FIELDS)
            or (finalized_at is not None and finalized_at < created_at)
        ):
            raise AIBudgetError("AI_BUDGET_RECOVERY_INVALID", "recovery record is invalid")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise AIBudgetError("AI_BUDGET_CLOCK_INVALID", "clock is invalid")
        return value.astimezone(UTC)


def _fingerprint(request: dict[str, Any]) -> str:
    replay = copy.deepcopy(request)
    replay.pop("expected_ledger_version", None)
    encoded = json.dumps(replay, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
