from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import smoke_desktop_bundle


def process_with_communications(*outcomes: object) -> Mock:
    process = Mock(spec=subprocess.Popen)
    process.pid = 123
    process.returncode = None

    def communicate(*, timeout: float) -> tuple[bytes, bytes]:
        outcome = outcomes[communicate.calls]
        communicate.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        process.returncode = 0
        assert isinstance(outcome, tuple)
        return outcome

    communicate.calls = 0  # type: ignore[attr-defined]
    process.communicate.side_effect = communicate
    return process


def test_run_bootstrap_returns_completed_output(monkeypatch: pytest.MonkeyPatch) -> None:
    process = process_with_communications((b"stdout", b"stderr"))
    popen = Mock(return_value=process)
    monkeypatch.setattr(smoke_desktop_bundle.subprocess, "Popen", popen)
    monkeypatch.setattr(smoke_desktop_bundle, "process_group_options", lambda: {})

    completed = smoke_desktop_bundle.run_bootstrap(Path("desktop"))

    assert completed.returncode == 0
    assert completed.stdout == b"stdout"
    assert completed.stderr == b"stderr"
    process.communicate.assert_called_once_with(
        timeout=smoke_desktop_bundle.BOOTSTRAP_TIMEOUT_SECONDS
    )


def test_run_bootstrap_terminates_process_tree_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = process_with_communications(
        subprocess.TimeoutExpired("desktop", 30),
        (b"stopped", b"diagnostic"),
    )
    terminate = Mock()
    monkeypatch.setattr(smoke_desktop_bundle.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(smoke_desktop_bundle, "process_group_options", lambda: {})
    monkeypatch.setattr(smoke_desktop_bundle, "terminate_process_tree", terminate)

    with pytest.raises(RuntimeError, match="timed out after 30 seconds: stoppeddiagnostic"):
        smoke_desktop_bundle.run_bootstrap(Path("desktop"))

    terminate.assert_called_once_with(process)
    assert process.communicate.call_args_list[-1].kwargs == {
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
