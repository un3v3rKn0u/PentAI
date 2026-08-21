from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues, parse_time

MAX_OUTPUT_BYTES = 32_768
MAX_NESTING_DEPTH = 6
MAX_OBSERVATIONS = 32
REPAIR_LIFETIME = timedelta(minutes=1)
RESPONSE_TYPE = "candidate_observation"
_REPAIRABLE = {"AI_OUTPUT_MALFORMED", "AI_OUTPUT_SCHEMA_INVALID"}


class StructuredOutputError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DuplicateKeyError(ValueError):
    pass


class _NonFiniteNumberError(ValueError):
    pass


class StructuredOutputParser:
    """Strictly parse one non-authoritative output type with one bounded repair."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._consumed_repairs: set[str] = set()
        self._lock = RLock()

    def parse_direct(self, raw: object) -> dict[str, Any]:
        payload, failure = _decode_candidate(raw)
        if failure is not None:
            return _result(raw, attempt_count=1, failure_code=failure)
        return _result(raw, attempt_count=1, payload=payload, parse_path="direct")

    def build_repair_request(self, initial_raw: object) -> dict[str, Any]:
        payload, failure = _decode_candidate(initial_raw)
        if payload is not None or failure not in _REPAIRABLE:
            raise StructuredOutputError(
                "AI_OUTPUT_REPAIR_FORBIDDEN", "output is not eligible for repair"
            )
        instant = self._now()
        request = {
            "schema_version": "1.0.0",
            "repair_id": str(uuid4()),
            "response_type": RESPONSE_TYPE,
            "initial_output_sha256": _digest(initial_raw),
            "initial_failure_code": failure,
            "attempt_number": 2,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "max_nesting_depth": MAX_NESTING_DEPTH,
            "max_observations": MAX_OBSERVATIONS,
            "issued_at": _timestamp(instant),
            "expires_at": _timestamp(instant + REPAIR_LIFETIME),
            "execution_enabled": False,
        }
        if contract_issues(request, "ai-output-repair-request-v1.schema.json"):
            raise StructuredOutputError(
                "AI_OUTPUT_REPAIR_REQUEST_INVALID", "repair request is invalid"
            )
        return request

    def parse_repair(
        self,
        *,
        initial_raw: object,
        repair_request: dict[str, Any],
        repaired_raw: object,
    ) -> dict[str, Any]:
        failure = self._validate_repair_request(initial_raw, repair_request)
        if failure is not None:
            return _result(repaired_raw, attempt_count=2, failure_code=failure)
        payload, repair_failure = _decode_candidate(repaired_raw)
        if repair_failure is not None:
            return _result(
                repaired_raw,
                attempt_count=2,
                failure_code="AI_OUTPUT_REPAIR_EXHAUSTED",
            )
        return _result(repaired_raw, attempt_count=2, payload=payload, parse_path="repaired")

    def _validate_repair_request(
        self, initial_raw: object, repair_request: dict[str, Any]
    ) -> str | None:
        if contract_issues(repair_request, "ai-output-repair-request-v1.schema.json"):
            return "AI_OUTPUT_REPAIR_REQUEST_INVALID"
        initial_payload, initial_failure = _decode_candidate(initial_raw)
        if initial_payload is not None or initial_failure not in _REPAIRABLE:
            return "AI_OUTPUT_REPAIR_FORBIDDEN"
        if (
            repair_request["initial_output_sha256"] != _digest(initial_raw)
            or repair_request["initial_failure_code"] != initial_failure
        ):
            return "AI_OUTPUT_REPAIR_BINDING_MISMATCH"
        instant = self._now()
        issued_at = parse_time(repair_request["issued_at"])
        expires_at = parse_time(repair_request["expires_at"])
        if (
            issued_at > instant
            or expires_at <= instant
            or expires_at <= issued_at
            or expires_at - issued_at > REPAIR_LIFETIME
        ):
            return "AI_OUTPUT_REPAIR_STALE"
        with self._lock:
            repair_id = repair_request["repair_id"]
            if repair_id in self._consumed_repairs:
                return "AI_OUTPUT_REPAIR_REPLAYED"
            self._consumed_repairs.add(repair_id)
        return None

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise StructuredOutputError("AI_OUTPUT_CLOCK_INVALID", "clock is invalid")
        return value.astimezone(UTC)


def _decode_candidate(raw: object) -> tuple[dict[str, Any] | None, str | None]:
    if type(raw) is not bytes:
        return None, "AI_OUTPUT_INPUT_TYPE_INVALID"
    if len(raw) > MAX_OUTPUT_BYTES:
        return None, "AI_OUTPUT_TOO_LARGE"
    if not raw.strip():
        return None, "AI_OUTPUT_EMPTY"
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, "AI_OUTPUT_INVALID_ENCODING"
    try:
        candidate = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_finite,
        )
    except _DuplicateKeyError:
        return None, "AI_OUTPUT_DUPLICATE_KEY"
    except _NonFiniteNumberError:
        return None, "AI_OUTPUT_NON_FINITE_NUMBER"
    except (ValueError, RecursionError):
        return None, "AI_OUTPUT_MALFORMED"
    if not isinstance(candidate, dict):
        return None, "AI_OUTPUT_SCHEMA_INVALID"
    if "operation" in candidate:
        return None, "AI_OUTPUT_OPERATION_UNSUPPORTED"
    if "schema_version" in candidate and candidate["schema_version"] != "1.0.0":
        return None, "AI_OUTPUT_VERSION_UNSUPPORTED"
    if "response_type" in candidate and candidate["response_type"] != RESPONSE_TYPE:
        return None, "AI_OUTPUT_TYPE_UNSUPPORTED"
    try:
        depth = _nesting_depth(candidate)
    except RecursionError:
        return None, "AI_OUTPUT_DEPTH_EXCEEDED"
    if depth > MAX_NESTING_DEPTH:
        return None, "AI_OUTPUT_DEPTH_EXCEEDED"
    if contract_issues(candidate, "ai-candidate-observation-v1.schema.json"):
        return None, "AI_OUTPUT_SCHEMA_INVALID"
    return copy.deepcopy(candidate), None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise _NonFiniteNumberError(value)


def _nesting_depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_nesting_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_nesting_depth(item) for item in value), default=0)
    return 0


def _result(
    raw: object,
    *,
    attempt_count: int,
    payload: dict[str, Any] | None = None,
    parse_path: str = "none",
    failure_code: str | None = None,
) -> dict[str, Any]:
    result = {
        "schema_version": "1.0.0",
        "response_type": RESPONSE_TYPE,
        "outcome": "accepted" if payload is not None else "denied",
        "parse_path": parse_path,
        "attempt_count": attempt_count,
        "output_sha256": _digest(raw),
        "payload": copy.deepcopy(payload),
        "failure_code": failure_code,
        "execution_enabled": False,
    }
    if contract_issues(result, "ai-structured-output-result-v1.schema.json"):
        raise StructuredOutputError("AI_OUTPUT_RESULT_INVALID", "parse result is invalid")
    return result


def _digest(raw: object) -> str:
    if type(raw) is bytes:
        encoded = raw
    else:
        encoded = f"invalid-type:{type(raw).__module__}.{type(raw).__qualname__}".encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
