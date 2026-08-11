from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pentai_core.gateway_response import GatewayResponseError, read_bounded_response


class SequenceClock:
    def __init__(self, *values: datetime) -> None:
        self._values = iter(values)

    def __call__(self) -> datetime:
        return next(self._values)


def stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def test_response_reader_retains_only_the_hard_limit_plus_one_proof_byte() -> None:
    instant = datetime.now(UTC)
    result = read_bounded_response(
        (b"abc", b"defgh"),
        maximum_response_bytes=5,
        deadline_at=stamp(instant + timedelta(seconds=5)),
        clock=lambda: instant,
    )

    assert result.body == b"abcde"
    assert result.measurement.outcome == "response_limit_exceeded"
    assert result.measurement.observed_response_bytes == 6
    assert result.measurement.retained_response_bytes == 5


def test_response_reader_stops_before_consuming_a_chunk_at_the_deadline() -> None:
    instant = datetime.now(UTC)
    consumed = 0

    def chunks():
        nonlocal consumed
        consumed += 1
        yield b"first"
        consumed += 1
        yield b"second"

    result = read_bounded_response(
        chunks(),
        maximum_response_bytes=100,
        deadline_at=stamp(instant + timedelta(seconds=1)),
        clock=SequenceClock(instant, instant + timedelta(seconds=1)),
    )

    assert result.body == b"first"
    assert result.measurement.outcome == "deadline_exceeded"
    assert consumed == 2


@pytest.mark.parametrize("chunk", [b"", bytearray(b"not-bytes"), "text"])
def test_response_reader_rejects_ambiguous_chunks(chunk: object) -> None:
    instant = datetime.now(UTC)
    with pytest.raises(GatewayResponseError, match="response chunk is invalid"):
        read_bounded_response(
            (chunk,),  # type: ignore[arg-type]
            maximum_response_bytes=10,
            deadline_at=stamp(instant + timedelta(seconds=1)),
            clock=lambda: instant,
        )


def test_response_reader_rejects_a_naive_clock() -> None:
    instant = datetime.now(UTC)
    with pytest.raises(GatewayResponseError, match="response clock is untrusted"):
        read_bounded_response(
            (b"data",),
            maximum_response_bytes=10,
            deadline_at=stamp(instant + timedelta(seconds=1)),
            clock=lambda: datetime.now(),
        )


def test_response_reader_rejects_clock_rollback() -> None:
    instant = datetime.now(UTC)
    with pytest.raises(GatewayResponseError, match="response clock moved backward"):
        read_bounded_response(
            (b"first", b"second"),
            maximum_response_bytes=20,
            deadline_at=stamp(instant + timedelta(seconds=2)),
            clock=SequenceClock(instant, instant - timedelta(milliseconds=1)),
        )


@given(st.binary(max_size=256), st.integers(min_value=1, max_value=128))
def test_response_reader_never_retains_or_observes_beyond_its_bound(
    payload: bytes, limit: int
) -> None:
    instant = datetime.now(UTC)
    result = read_bounded_response(
        (payload,) if payload else (),
        maximum_response_bytes=limit,
        deadline_at=stamp(instant + timedelta(seconds=1)),
        clock=lambda: instant,
    )

    assert result.body == payload[:limit]
    assert result.measurement.retained_response_bytes == min(len(payload), limit)
    assert result.measurement.observed_response_bytes == min(len(payload), limit + 1)
    assert result.measurement.outcome == (
        "completed" if len(payload) <= limit else "response_limit_exceeded"
    )
