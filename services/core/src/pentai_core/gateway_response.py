from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from pentai_policy.document import parse_time


class GatewayResponseError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class GatewayResponseMeasurement:
    outcome: str
    observed_response_bytes: int
    retained_response_bytes: int
    completed_at: datetime


@dataclass(frozen=True)
class BoundedGatewayResponse:
    body: bytes
    measurement: GatewayResponseMeasurement


def read_bounded_response(
    chunks: Iterable[bytes],
    *,
    maximum_response_bytes: int,
    deadline_at: str,
    clock: Callable[[], datetime] | None = None,
) -> BoundedGatewayResponse:
    if not 1 <= maximum_response_bytes <= 2_147_483_647:
        raise GatewayResponseError("RESPONSE_LIMIT_INVALID", "response limit is invalid")
    try:
        deadline = parse_time(deadline_at)
    except (TypeError, ValueError) as exc:
        raise GatewayResponseError("DEADLINE_INVALID", "response deadline is invalid") from exc
    current_time = clock or (lambda: datetime.now(UTC))
    last_seen: datetime | None = None

    def read_time() -> datetime:
        nonlocal last_seen
        value = _trusted_time(current_time)
        if last_seen is not None and value < last_seen:
            raise GatewayResponseError("CLOCK_UNTRUSTED", "response clock moved backward")
        last_seen = value
        return value

    retained = bytearray()
    observed = 0
    for chunk in chunks:
        now = read_time()
        if now >= deadline:
            return _result("deadline_exceeded", retained, observed, now)
        if not isinstance(chunk, bytes) or not chunk:
            raise GatewayResponseError("RESPONSE_CHUNK_INVALID", "response chunk is invalid")
        remaining = maximum_response_bytes - len(retained)
        if len(chunk) > remaining:
            retained.extend(chunk[:remaining])
            observed += remaining + 1
            completed_at = read_time()
            outcome = (
                "deadline_exceeded"
                if completed_at >= deadline
                else "response_limit_exceeded"
            )
            return _result(outcome, retained, observed, completed_at)
        retained.extend(chunk)
        observed += len(chunk)
    completed_at = read_time()
    outcome = "deadline_exceeded" if completed_at >= deadline else "completed"
    return _result(outcome, retained, observed, completed_at)


def _result(
    outcome: str, retained: bytearray, observed: int, completed_at: datetime
) -> BoundedGatewayResponse:
    measurement = GatewayResponseMeasurement(
        outcome=outcome,
        observed_response_bytes=observed,
        retained_response_bytes=len(retained),
        completed_at=completed_at,
    )
    return BoundedGatewayResponse(bytes(retained), measurement)


def _trusted_time(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GatewayResponseError("CLOCK_UNTRUSTED", "response clock is untrusted")
    return value
