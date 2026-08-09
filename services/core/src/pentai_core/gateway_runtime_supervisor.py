from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread, current_thread
from typing import Any, Protocol

from pentai_core.database import transaction


class GatewayRuntimeLifecycleControl(Protocol):
    def recover(self) -> int: ...

    def check_all(self) -> int: ...


class RuntimeSupervisorControl(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def status(self) -> dict[str, object]: ...


@dataclass(frozen=True)
class SupervisorSnapshot:
    status: str
    reason_code: str | None
    recovered_instances: int
    watchdog_running: bool
    execution_enabled: bool = False

    def document(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "recovered_instances": self.recovered_instances,
            "watchdog_running": self.watchdog_running,
            "execution_enabled": self.execution_enabled,
        }


class GatewayRuntimeSupervisor:
    def __init__(
        self,
        *,
        lifecycle: GatewayRuntimeLifecycleControl,
        pause_safety: Callable[[str], Any],
        interval_seconds: float = 5,
        join_timeout_seconds: float = 2,
    ) -> None:
        if not 0.1 <= interval_seconds <= 10:
            raise ValueError("runtime watchdog interval is invalid")
        if not 0.1 <= join_timeout_seconds <= 10:
            raise ValueError("runtime watchdog join timeout is invalid")
        self._lifecycle = lifecycle
        self._pause_safety = pause_safety
        self._interval_seconds = interval_seconds
        self._join_timeout_seconds = join_timeout_seconds
        self._stop = Event()
        self._lock = Lock()
        self._thread: Thread | None = None
        self._snapshot = SupervisorSnapshot("stopped", None, 0, False)

    def start(self) -> None:
        with self._lock:
            if self._snapshot.status not in {"stopped"}:
                return
            self._snapshot = SupervisorSnapshot("recovering", None, 0, False)
        try:
            recovered = self._lifecycle.recover()
        except Exception:
            self._degrade("GATEWAY_RUNTIME_RECOVERY_FAILED")
            return
        self._stop.clear()
        thread = Thread(
            target=self._watch,
            name="pentai-gateway-runtime-watchdog",
            daemon=True,
        )
        with self._lock:
            self._thread = thread
            self._snapshot = SupervisorSnapshot("ready", None, recovered, True)
        thread.start()

    def stop(self) -> None:
        with self._lock:
            if self._snapshot.status == "stopped":
                return
            thread = self._thread
        self._stop.set()
        if thread is not None and thread is not current_thread():
            thread.join(timeout=self._join_timeout_seconds)
            if thread.is_alive():
                self._degrade("GATEWAY_WATCHDOG_STOP_TIMEOUT")
                return
        try:
            recovered = self._lifecycle.recover()
        except Exception:
            self._degrade("GATEWAY_RUNTIME_SHUTDOWN_FAILED")
            return
        with self._lock:
            self._thread = None
            self._snapshot = SupervisorSnapshot("stopped", None, recovered, False)

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._snapshot.document()

    def _watch(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            try:
                self._lifecycle.check_all()
            except Exception:
                self._degrade("GATEWAY_WATCHDOG_FAILED")
                self._stop.set()
                return

    def _degrade(self, reason_code: str) -> None:
        try:
            self._pause_safety(reason_code)
        except Exception:
            reason_code = "GATEWAY_SAFETY_PAUSE_FAILED"
        with self._lock:
            self._snapshot = SupervisorSnapshot("degraded", reason_code, 0, False)


class UnconfiguredGatewayRuntimeSupervisor:
    def __init__(
        self, *, database_path: Path, pause_safety: Callable[[str], Any]
    ) -> None:
        self._database_path = database_path
        self._pause_safety = pause_safety
        self._snapshot = SupervisorSnapshot("stopped", None, 0, False)

    def start(self) -> None:
        try:
            with transaction(self._database_path) as connection:
                active = connection.execute(
                    """SELECT COUNT(*) FROM gateway_runtime_instances
                    WHERE status IN ('launching', 'running')
                       OR (status = 'failed' AND container_id IS NOT NULL)"""
                ).fetchone()[0]
        except (sqlite3.Error, TypeError):
            active = 1
        if active:
            try:
                self._pause_safety("GATEWAY_RUNTIME_SUPERVISOR_UNAVAILABLE")
                reason = "GATEWAY_RUNTIME_SUPERVISOR_UNAVAILABLE"
            except Exception:
                reason = "GATEWAY_SAFETY_PAUSE_FAILED"
            self._snapshot = SupervisorSnapshot("degraded", reason, 0, False)
        else:
            self._snapshot = SupervisorSnapshot("disabled", None, 0, False)

    def stop(self) -> None:
        return

    def status(self) -> dict[str, object]:
        return self._snapshot.document()
