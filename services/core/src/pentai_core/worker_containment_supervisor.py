from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread, current_thread
from typing import Protocol

from pentai_core.database import transaction
from pentai_core.worker_containment import validate_worker_containment_attestation

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class WorkerAttestor(Protocol):
    def measure(self) -> dict[str, object]: ...


@dataclass(frozen=True)
class WorkerContainmentBinding:
    worker_id: str
    runtime_instance_id: str
    worker_gateway_network_id: str


class WorkerContainmentMonitor(Protocol):
    def check_all(self) -> int: ...


class WorkerSupervisorControl(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def status(self) -> dict[str, object]: ...


class RegisteredWorkerContainmentMonitor:
    def __init__(
        self,
        *,
        bindings: Callable[[], tuple[WorkerContainmentBinding, ...]],
        attestor_for: Callable[[WorkerContainmentBinding], WorkerAttestor],
    ) -> None:
        self._bindings = bindings
        self._attestor_for = attestor_for

    def check_all(self) -> int:
        bindings = self._bindings()
        worker_ids = [binding.worker_id for binding in bindings]
        if len(worker_ids) != len(set(worker_ids)) or any(
            not _IDENTIFIER.fullmatch(value)
            for binding in bindings
            for value in (
                binding.worker_id,
                binding.runtime_instance_id,
                binding.worker_gateway_network_id,
            )
        ):
            raise ValueError("worker containment binding is invalid")
        for binding in bindings:
            attestation = self._attestor_for(binding).measure()
            validate_worker_containment_attestation(attestation)
            if (
                attestation.get("runtime_instance_id") != binding.runtime_instance_id
                or attestation.get("worker_gateway_network_id")
                != binding.worker_gateway_network_id
            ):
                raise ValueError("worker containment identity changed")
        return len(bindings)


@dataclass(frozen=True)
class WorkerContainmentSnapshot:
    status: str
    reason_code: str | None
    monitored_workers: int
    watchdog_running: bool

    def document(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "monitored_workers": self.monitored_workers,
            "watchdog_running": self.watchdog_running,
            "execution_enabled": False,
        }


class WorkerContainmentSupervisor:
    def __init__(
        self,
        *,
        monitor: WorkerContainmentMonitor,
        pause_safety: Callable[[str], object],
        terminate_workers: Callable[[str], object],
        recover_workers: Callable[[], object] | None = None,
        interval_seconds: float = 5,
        join_timeout_seconds: float = 2,
    ) -> None:
        if not 0.1 <= interval_seconds <= 10:
            raise ValueError("worker watchdog interval is invalid")
        if not 0.1 <= join_timeout_seconds <= 10:
            raise ValueError("worker watchdog join timeout is invalid")
        self._monitor = monitor
        self._pause_safety = pause_safety
        self._terminate_workers = terminate_workers
        self._recover_workers = recover_workers or (lambda: None)
        self._interval_seconds = interval_seconds
        self._join_timeout_seconds = join_timeout_seconds
        self._stop = Event()
        self._lock = Lock()
        self._thread: Thread | None = None
        self._snapshot = WorkerContainmentSnapshot("stopped", None, 0, False)

    def start(self) -> None:
        with self._lock:
            if self._snapshot.status != "stopped":
                return
            self._snapshot = WorkerContainmentSnapshot("starting", None, 0, False)
        try:
            self._recover_workers()
            monitored = self._monitor.check_all()
        except Exception:
            self._degrade("WORKER_CONTAINMENT_STARTUP_FAILED")
            return
        self._stop.clear()
        thread = Thread(
            target=self._watch,
            name="pentai-worker-containment-watchdog",
            daemon=True,
        )
        with self._lock:
            self._thread = thread
            self._snapshot = WorkerContainmentSnapshot("ready", None, monitored, True)
        thread.start()

    def stop(self) -> None:
        with self._lock:
            if self._snapshot.status == "stopped":
                return
            thread = self._thread
        self._stop.set()
        if thread is not None and thread is not current_thread():
            thread.join(self._join_timeout_seconds)
            if thread.is_alive():
                self._degrade("WORKER_CONTAINMENT_STOP_TIMEOUT")
                return
        with self._lock:
            self._thread = None
            if self._snapshot.status != "degraded":
                self._snapshot = WorkerContainmentSnapshot(
                    "stopped", None, self._snapshot.monitored_workers, False
                )

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._snapshot.document()

    def _watch(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            try:
                monitored = self._monitor.check_all()
            except Exception:
                self._degrade("WORKER_CONTAINMENT_WATCHDOG_FAILED")
                self._stop.set()
                return
            with self._lock:
                if self._stop.is_set():
                    return
                self._snapshot = WorkerContainmentSnapshot("ready", None, monitored, True)

    def _degrade(self, reason_code: str) -> None:
        try:
            self._pause_safety(reason_code)
        except Exception:
            reason_code = "WORKER_SAFETY_PAUSE_FAILED"
        try:
            self._terminate_workers(reason_code)
        except Exception:
            reason_code = "WORKER_TERMINATION_FAILED"
        with self._lock:
            self._thread = None
            self._snapshot = WorkerContainmentSnapshot("degraded", reason_code, 0, False)


class UnconfiguredWorkerContainmentSupervisor:
    def __init__(
        self, *, database_path: Path, pause_safety: Callable[[str], object]
    ) -> None:
        self._database_path = database_path
        self._pause_safety = pause_safety
        self._snapshot = WorkerContainmentSnapshot("stopped", None, 0, False)

    def start(self) -> None:
        try:
            with transaction(self._database_path) as connection:
                active = connection.execute(
                    """SELECT COUNT(*) FROM worker_runtime_instances
                    WHERE status IN ('launching', 'running', 'termination_requested', 'failed')"""
                ).fetchone()[0]
        except (sqlite3.Error, TypeError):
            active = 1
        if active:
            reason = "WORKER_SUPERVISION_UNAVAILABLE"
            try:
                self._pause_safety(reason)
            except Exception:
                reason = "WORKER_SAFETY_PAUSE_FAILED"
            self._snapshot = WorkerContainmentSnapshot("degraded", reason, 0, False)
        else:
            self._snapshot = WorkerContainmentSnapshot("disabled", None, 0, False)

    def stop(self) -> None:
        return

    def status(self) -> dict[str, object]:
        return self._snapshot.document()
