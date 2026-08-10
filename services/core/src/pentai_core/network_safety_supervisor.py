from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Event, Lock, Thread
from typing import Any, Protocol


class NetworkSafetySupervisorControl(Protocol):
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def status(self) -> dict[str, object]: ...


class NetworkIdentityMonitor(Protocol):
    def check_all(self) -> int: ...


class NetworkIdentityControl(Protocol):
    def network_authority_assessments(self) -> tuple[str, ...]: ...

    def verify_network_identity(
        self, engagement_id: str, *, attestor: Any, attestor_id: str
    ) -> dict[str, Any]: ...


class AuthorizationNetworkIdentityMonitor:
    def __init__(
        self,
        *,
        control: NetworkIdentityControl,
        attestor_for: Callable[[str], Any],
        attestor_id: str,
    ) -> None:
        if not attestor_id.strip():
            raise ValueError("network attestor identity is required")
        self._control = control
        self._attestor_for = attestor_for
        self._attestor_id = attestor_id.strip()

    def check_all(self) -> int:
        assessment_ids = self._control.network_authority_assessments()
        for assessment_id in assessment_ids:
            self._control.verify_network_identity(
                assessment_id,
                attestor=self._attestor_for(assessment_id),
                attestor_id=self._attestor_id,
            )
        return len(assessment_ids)


@dataclass(frozen=True)
class NetworkSafetySnapshot:
    status: str
    reason_code: str | None
    monitored_assessments: int
    watchdog_running: bool

    def document(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "monitored_assessments": self.monitored_assessments,
            "watchdog_running": self.watchdog_running,
            "execution_enabled": False,
        }


class NetworkSafetySupervisor:
    def __init__(
        self,
        *,
        monitor: NetworkIdentityMonitor,
        pause_safety: Callable[[str], Any],
        interval_seconds: float = 5,
        join_timeout_seconds: float = 2,
    ) -> None:
        if not 0.1 <= interval_seconds <= 10:
            raise ValueError("network watchdog interval must be 0.1–10 seconds")
        if not 0.1 <= join_timeout_seconds <= 10:
            raise ValueError("network watchdog join timeout must be 0.1–10 seconds")
        self._monitor = monitor
        self._pause_safety = pause_safety
        self._interval_seconds = interval_seconds
        self._join_timeout_seconds = join_timeout_seconds
        self._stop = Event()
        self._lock = Lock()
        self._thread: Thread | None = None
        self._snapshot = NetworkSafetySnapshot("stopped", None, 0, False)

    def start(self) -> None:
        with self._lock:
            if self._thread is not None or self._snapshot.status == "degraded":
                return
            try:
                monitored = self._monitor.check_all()
            except Exception:
                self._degrade("NETWORK_IDENTITY_STARTUP_FAILED")
                return
            self._stop.clear()
            self._snapshot = NetworkSafetySnapshot("ready", None, monitored, True)
            self._thread = Thread(
                target=self._watchdog,
                name="pentai-network-safety-watchdog",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                if self._snapshot.status != "degraded":
                    self._snapshot = NetworkSafetySnapshot("stopped", None, 0, False)
                return
            self._stop.set()
        thread.join(self._join_timeout_seconds)
        with self._lock:
            if thread.is_alive():
                self._thread = None
                self._degrade("NETWORK_WATCHDOG_STOP_TIMEOUT")
                return
            self._thread = None
            if self._snapshot.status != "degraded":
                self._snapshot = NetworkSafetySnapshot(
                    "stopped", None, self._snapshot.monitored_assessments, False
                )

    def status(self) -> dict[str, object]:
        with self._lock:
            return self._snapshot.document()

    def _watchdog(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            try:
                monitored = self._monitor.check_all()
            except Exception:
                with self._lock:
                    self._degrade("NETWORK_IDENTITY_WATCHDOG_FAILED")
                return
            with self._lock:
                if self._stop.is_set():
                    return
                self._snapshot = NetworkSafetySnapshot("ready", None, monitored, True)

    def _degrade(self, reason: str) -> None:
        try:
            self._pause_safety(reason)
        except Exception:
            reason = "NETWORK_SAFETY_PAUSE_FAILED"
        self._snapshot = NetworkSafetySnapshot(
            "degraded", reason, self._snapshot.monitored_assessments, False
        )


class UnconfiguredNetworkSafetySupervisor:
    def __init__(
        self,
        *,
        authority_exists: Callable[[], bool],
        pause_safety: Callable[[str], Any],
    ) -> None:
        self._authority_exists = authority_exists
        self._pause_safety = pause_safety
        self._reason: str | None = None

    def start(self) -> None:
        self.status()

    def stop(self) -> None:
        return

    def status(self) -> dict[str, object]:
        if self._reason is not None:
            return NetworkSafetySnapshot("degraded", self._reason, 0, False).document()
        try:
            authority_exists = self._authority_exists()
        except Exception:
            authority_exists = True
            self._reason = "NETWORK_IDENTITY_MONITOR_STATE_FAILED"
        if authority_exists:
            reason = self._reason or "NETWORK_IDENTITY_MONITOR_UNAVAILABLE"
            try:
                self._pause_safety(reason)
            except Exception:
                reason = "NETWORK_SAFETY_PAUSE_FAILED"
            self._reason = reason
            return NetworkSafetySnapshot("degraded", reason, 0, False).document()
        return NetworkSafetySnapshot("disabled", None, 0, False).document()
