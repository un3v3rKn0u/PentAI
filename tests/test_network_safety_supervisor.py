from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from threading import Event

from pentai_core.network_safety_supervisor import (
    AuthorizationNetworkIdentityMonitor,
    NetworkSafetySupervisor,
    UnconfiguredNetworkSafetySupervisor,
)


@dataclass
class FixtureMonitor:
    monitored: int = 1
    fail: bool = False
    calls: int = 0
    checked: Event = field(default_factory=Event)

    def check_all(self) -> int:
        self.calls += 1
        self.checked.set()
        if self.fail:
            raise RuntimeError("sensitive fixture detail")
        return self.monitored


@dataclass
class BlockingMonitor(FixtureMonitor):
    release: Event = field(default_factory=Event)

    def check_all(self) -> int:
        self.calls += 1
        if self.calls > 1:
            self.checked.set()
            self.release.wait(1)
        return self.monitored


class NetworkSafetySupervisorTests(unittest.TestCase):
    def test_initial_check_precedes_ready_and_watchdog_repeats(self) -> None:
        monitor = FixtureMonitor(monitored=2)
        pauses: list[str] = []
        supervisor = NetworkSafetySupervisor(
            monitor=monitor,
            pause_safety=pauses.append,
            interval_seconds=0.1,
            join_timeout_seconds=1,
        )
        supervisor.start()
        self.assertEqual(
            supervisor.status(),
            {
                "status": "ready",
                "reason_code": None,
                "monitored_assessments": 2,
                "watchdog_running": True,
                "execution_enabled": False,
            },
        )
        self.assertEqual(monitor.calls, 1)
        monitor.checked.clear()
        self.assertTrue(monitor.checked.wait(1))
        self.assertGreaterEqual(monitor.calls, 2)
        supervisor.stop()
        self.assertEqual(supervisor.status()["status"], "stopped")
        self.assertEqual(pauses, [])

    def test_startup_and_watchdog_failure_pause_with_fixed_diagnostics(self) -> None:
        startup_monitor = FixtureMonitor(fail=True)
        startup_pauses: list[str] = []
        startup = NetworkSafetySupervisor(
            monitor=startup_monitor,
            pause_safety=startup_pauses.append,
        )
        startup.start()
        self.assertEqual(startup.status()["reason_code"], "NETWORK_IDENTITY_STARTUP_FAILED")
        self.assertEqual(startup_pauses, ["NETWORK_IDENTITY_STARTUP_FAILED"])

        watchdog_monitor = FixtureMonitor()
        watchdog_pauses: list[str] = []
        watchdog = NetworkSafetySupervisor(
            monitor=watchdog_monitor,
            pause_safety=watchdog_pauses.append,
            interval_seconds=0.1,
        )
        watchdog.start()
        watchdog_monitor.fail = True
        watchdog_monitor.checked.clear()
        self.assertTrue(watchdog_monitor.checked.wait(1))
        self.assertEqual(
            watchdog.status()["reason_code"], "NETWORK_IDENTITY_WATCHDOG_FAILED"
        )
        self.assertEqual(watchdog_pauses, ["NETWORK_IDENTITY_WATCHDOG_FAILED"])

    def test_failed_pause_and_join_timeout_remain_degraded(self) -> None:
        failed_pause = NetworkSafetySupervisor(
            monitor=FixtureMonitor(fail=True),
            pause_safety=lambda _reason: (_ for _ in ()).throw(RuntimeError("private")),
        )
        failed_pause.start()
        self.assertEqual(failed_pause.status()["reason_code"], "NETWORK_SAFETY_PAUSE_FAILED")

        monitor = BlockingMonitor()
        pauses: list[str] = []
        timeout = NetworkSafetySupervisor(
            monitor=monitor,
            pause_safety=pauses.append,
            interval_seconds=0.1,
            join_timeout_seconds=0.1,
        )
        timeout.start()
        self.assertTrue(monitor.checked.wait(1))
        timeout.stop()
        self.assertEqual(timeout.status()["reason_code"], "NETWORK_WATCHDOG_STOP_TIMEOUT")
        monitor.release.set()

    def test_unconfigured_monitor_latches_degraded_when_authority_exists(self) -> None:
        authority = True
        pauses: list[str] = []

        def pause(reason: str) -> None:
            nonlocal authority
            pauses.append(reason)
            authority = False

        supervisor = UnconfiguredNetworkSafetySupervisor(
            authority_exists=lambda: authority,
            pause_safety=pause,
        )
        supervisor.start()
        self.assertEqual(
            supervisor.status()["reason_code"], "NETWORK_IDENTITY_MONITOR_UNAVAILABLE"
        )
        self.assertEqual(pauses, ["NETWORK_IDENTITY_MONITOR_UNAVAILABLE"])

    def test_unconfigured_monitor_is_disabled_without_network_authority(self) -> None:
        supervisor = UnconfiguredNetworkSafetySupervisor(
            authority_exists=lambda: False,
            pause_safety=lambda _reason: self.fail("pause should not be called"),
        )
        supervisor.start()
        self.assertEqual(supervisor.status()["status"], "disabled")

    def test_unconfigured_monitor_state_failure_is_fail_closed(self) -> None:
        pauses: list[str] = []
        supervisor = UnconfiguredNetworkSafetySupervisor(
            authority_exists=lambda: (_ for _ in ()).throw(RuntimeError("private")),
            pause_safety=pauses.append,
        )
        supervisor.start()
        self.assertEqual(
            supervisor.status()["reason_code"], "NETWORK_IDENTITY_MONITOR_STATE_FAILED"
        )
        self.assertEqual(pauses, ["NETWORK_IDENTITY_MONITOR_STATE_FAILED"])

    def test_authorization_adapter_checks_each_assessment(self) -> None:
        class Control:
            def __init__(self) -> None:
                self.checked: list[tuple[str, object, str]] = []

            def network_authority_assessments(self) -> tuple[str, ...]:
                return ("assessment-a", "assessment-b")

            def verify_network_identity(
                self, engagement_id: str, *, attestor: object, attestor_id: str
            ) -> dict[str, object]:
                self.checked.append((engagement_id, attestor, attestor_id))
                return {}

        control = Control()
        monitor = AuthorizationNetworkIdentityMonitor(
            control=control,
            attestor_for=lambda assessment_id: f"attestor:{assessment_id}",
            attestor_id="network-monitor",
        )
        self.assertEqual(monitor.check_all(), 2)
        self.assertEqual(
            control.checked,
            [
                ("assessment-a", "attestor:assessment-a", "network-monitor"),
                ("assessment-b", "attestor:assessment-b", "network-monitor"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
