from __future__ import annotations

import io
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import smoke_desktop_bundle


def process_with_waits(*outcomes: object) -> Mock:
    process = Mock(spec=subprocess.Popen)
    process.pid = 123
    process.returncode = None

    def wait(*, timeout: float) -> int:
        outcome = outcomes[wait.calls]
        wait.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, int)
        process.returncode = outcome
        return outcome

    wait.calls = 0  # type: ignore[attr-defined]
    process.wait.side_effect = wait
    return process


def test_run_bootstrap_returns_completed_output(monkeypatch: pytest.MonkeyPatch) -> None:
    process = process_with_waits(0)
    popen = Mock(return_value=process)
    output = io.BytesIO(b"stdoutstderr")
    monkeypatch.setattr(smoke_desktop_bundle.subprocess, "Popen", popen)
    monkeypatch.setattr(smoke_desktop_bundle, "process_group_options", lambda: {})
    monkeypatch.setattr(smoke_desktop_bundle.tempfile, "TemporaryFile", lambda: output)

    completed = smoke_desktop_bundle.run_bootstrap(Path("desktop"))

    assert completed.returncode == 0
    assert completed.stdout == b"stdoutstderr"
    assert completed.stderr == b""
    process.wait.assert_called_once_with(timeout=smoke_desktop_bundle.BOOTSTRAP_TIMEOUT_SECONDS)
    assert popen.call_args.kwargs["stdout"] is output
    assert popen.call_args.kwargs["stderr"] is subprocess.STDOUT


def test_run_bootstrap_terminates_process_tree_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = process_with_waits(
        subprocess.TimeoutExpired("desktop", 30),
        -9,
    )
    terminate = Mock()
    output = io.BytesIO(b"stopped diagnostic")
    monkeypatch.setattr(smoke_desktop_bundle.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(smoke_desktop_bundle, "process_group_options", lambda: {})
    monkeypatch.setattr(smoke_desktop_bundle, "terminate_process_tree", terminate)
    monkeypatch.setattr(smoke_desktop_bundle.tempfile, "TemporaryFile", lambda: output)

    with pytest.raises(
        RuntimeError,
        match=(
            rf"timed out after {smoke_desktop_bundle.BOOTSTRAP_TIMEOUT_SECONDS} "
            r"seconds: stopped diagnostic"
        ),
    ):
        smoke_desktop_bundle.run_bootstrap(Path("desktop"))

    terminate.assert_called_once_with(process)
    assert process.wait.call_args_list[-1].kwargs == {
        "timeout": smoke_desktop_bundle.SHUTDOWN_TIMEOUT_SECONDS
    }


def test_windows_process_tree_uses_taskkill(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(pid=456)
    run = Mock()
    monkeypatch.setattr(smoke_desktop_bundle.sys, "platform", "win32")
    monkeypatch.setattr(smoke_desktop_bundle.subprocess, "run", run)

    smoke_desktop_bundle.terminate_process_tree(process)

    assert run.call_args.args[0] == ["taskkill", "/PID", "456", "/T", "/F"]
    assert run.call_args.kwargs["timeout"] == smoke_desktop_bundle.SHUTDOWN_TIMEOUT_SECONDS


def test_posix_process_tree_kills_the_process_group(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(pid=789)
    killpg = Mock()
    monkeypatch.setattr(smoke_desktop_bundle.sys, "platform", "linux")
    monkeypatch.setattr(smoke_desktop_bundle.os, "killpg", killpg)

    smoke_desktop_bundle.terminate_process_tree(process)

    killpg.assert_called_once_with(789, smoke_desktop_bundle.signal.SIGKILL)
