from __future__ import annotations

import subprocess

from scripts.retry_transient_command import run_with_retry


def completed(returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["example"], returncode, stdout="", stderr=stderr)


def test_retries_a_transient_network_failure_until_success() -> None:
    results = iter([completed(1, "io: Peer disconnected"), completed(0)])
    delays: list[float] = []

    status = run_with_retry(
        ["example"],
        attempts=3,
        base_delay=2,
        runner=lambda *args, **kwargs: next(results),
        sleeper=delays.append,
    )

    assert status == 0
    assert delays == [2]


def test_does_not_retry_a_non_network_failure() -> None:
    calls = 0

    def fail(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return completed(2, "application compilation failed")

    status = run_with_retry(
        ["example"], attempts=3, base_delay=2, runner=fail, sleeper=lambda _: None
    )

    assert status == 2
    assert calls == 1


def test_stops_after_the_retry_limit() -> None:
    calls = 0

    def disconnect(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return completed(1, "connection reset by peer")

    status = run_with_retry(
        ["example"], attempts=3, base_delay=1, runner=disconnect, sleeper=lambda _: None
    )

    assert status == 1
    assert calls == 3


def test_uses_the_windows_shell_for_command_shims() -> None:
    received_shell: list[bool] = []

    def succeed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        received_shell.append(bool(kwargs["shell"]))
        return completed(0)

    status = run_with_retry(
        ["pnpm", "exec", "tauri"],
        attempts=1,
        base_delay=0,
        runner=succeed,
        use_shell=True,
    )

    assert status == 0
    assert received_shell == [True]
