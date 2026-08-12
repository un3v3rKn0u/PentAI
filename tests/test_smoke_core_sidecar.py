from __future__ import annotations

import subprocess

from scripts.smoke_core_sidecar import communicate_bounded


class StubProcess:
    def __init__(self, outcomes: list[tuple[bytes, bytes] | subprocess.TimeoutExpired]) -> None:
        self._outcomes = iter(outcomes)
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def communicate(
        self, input: bytes | None = None, timeout: float | None = None
    ) -> tuple[bytes, bytes]:
        outcome = next(self._outcomes)
        if isinstance(outcome, subprocess.TimeoutExpired):
            raise outcome
        self.returncode = -9 if self.killed else (-15 if self.terminated else 1)
        return outcome

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_communicate_bounded_returns_normal_process_output() -> None:
    process = StubProcess([(b"stdout", b"stderr")])

    result = communicate_bounded(process, process_input=b"input", timeout=10)

    assert result.returncode == 1
    assert result.stdout == b"stdout"
    assert result.stderr == b"stderr"
    assert result.timed_out is False
    assert result.forced_kill is False
    assert process.terminated is False
    assert process.killed is False


def test_communicate_bounded_terminates_process_after_timeout() -> None:
    process = StubProcess(
        [subprocess.TimeoutExpired("sidecar", 10), (b"terminated", b"")]
    )

    result = communicate_bounded(process, process_input=b"input", timeout=10)

    assert result.returncode == -15
    assert result.stdout == b"terminated"
    assert result.timed_out is True
    assert result.forced_kill is False
    assert process.terminated is True
    assert process.killed is False


def test_communicate_bounded_kills_process_that_ignores_termination() -> None:
    process = StubProcess(
        [
            subprocess.TimeoutExpired("sidecar", 10),
            subprocess.TimeoutExpired("sidecar", 5),
            (b"killed", b"diagnostic"),
        ]
    )

    result = communicate_bounded(process, process_input=b"input", timeout=10)

    assert result.returncode == -9
    assert result.stdout == b"killed"
    assert result.stderr == b"diagnostic"
    assert result.timed_out is True
    assert result.forced_kill is True
    assert process.terminated is True
    assert process.killed is True
