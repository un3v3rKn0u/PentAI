from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

from pentai_core.clock_health import ClockHealthMonitor
from pentai_core.gateway_runtime_supervisor import (
    GatewayRuntimeSupervisor,
    UnconfiguredGatewayRuntimeSupervisor,
)
from pentai_core.migrate import migrate


@dataclass
class FixtureLifecycle:
    recovered: int = 0
    fail_recovery: bool = False
    fail_check: bool = False
    recover_calls: int = 0
    check_calls: int = 0
    checked: Event = field(default_factory=Event)

    def recover(self) -> int:
        self.recover_calls += 1
        if self.fail_recovery:
            raise RuntimeError("synthetic recovery failure")
        return self.recovered

    def check_all(self) -> int:
        self.check_calls += 1
        self.checked.set()
        if self.fail_check:
            raise RuntimeError("synthetic watchdog failure")
        return 0


@dataclass
class BlockingLifecycle(FixtureLifecycle):
    release: Event = field(default_factory=Event)

    def check_all(self) -> int:
        self.check_calls += 1
        self.checked.set()
        self.release.wait(1)
        return 0


@dataclass
class FixtureClockHealth:
    fail: bool = False
    checks: int = 0
    checked: Event = field(default_factory=Event)

    def check(self) -> None:
        self.checks += 1
        self.checked.set()
        if self.fail:
            raise RuntimeError("synthetic clock failure")


class GatewayRuntimeSupervisorTests(unittest.TestCase):
    def test_recovery_completes_before_watchdog_becomes_ready(self) -> None:
        lifecycle = FixtureLifecycle(recovered=2)
        pauses: list[str] = []
        supervisor = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
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
                "recovered_instances": 2,
                "watchdog_running": True,
                "execution_enabled": False,
            },
        )
        self.assertEqual(lifecycle.recover_calls, 1)
        supervisor.stop()
        self.assertEqual(supervisor.status()["status"], "stopped")
        self.assertEqual(lifecycle.recover_calls, 2)
        supervisor.stop()
        self.assertEqual(lifecycle.recover_calls, 2)
        self.assertEqual(pauses, [])

    def test_recovery_failure_is_degraded_and_pauses_safety(self) -> None:
        lifecycle = FixtureLifecycle(fail_recovery=True)
        pauses: list[str] = []
        supervisor = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
            pause_safety=pauses.append,
            interval_seconds=0.1,
        )
        supervisor.start()
        self.assertEqual(supervisor.status()["status"], "degraded")
        self.assertEqual(
            supervisor.status()["reason_code"], "GATEWAY_RUNTIME_RECOVERY_FAILED"
        )
        self.assertEqual(pauses, ["GATEWAY_RUNTIME_RECOVERY_FAILED"])

    def test_watchdog_failure_degrades_without_automatic_restart(self) -> None:
        lifecycle = FixtureLifecycle(fail_check=True)
        pauses: list[str] = []
        supervisor = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
            pause_safety=pauses.append,
            interval_seconds=0.1,
        )
        supervisor.start()
        self.assertTrue(lifecycle.checked.wait(1))
        self.assertEqual(supervisor.status()["status"], "degraded")
        self.assertEqual(supervisor.status()["reason_code"], "GATEWAY_WATCHDOG_FAILED")
        supervisor.start()
        self.assertEqual(lifecycle.recover_calls, 1)
        supervisor.stop()

    def test_clock_health_failure_pauses_before_recovery_or_runtime_check(self) -> None:
        lifecycle = FixtureLifecycle()
        clock_health = FixtureClockHealth(fail=True)
        pauses: list[str] = []
        startup = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
            pause_safety=pauses.append,
            clock_health=clock_health,
            interval_seconds=0.1,
        )
        startup.start()
        self.assertEqual(lifecycle.recover_calls, 0)
        self.assertEqual(pauses, ["GATEWAY_CLOCK_STARTUP_FAILED"])

        lifecycle = FixtureLifecycle()
        clock_health = FixtureClockHealth()
        pauses = []
        watchdog = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
            pause_safety=pauses.append,
            clock_health=clock_health,
            interval_seconds=0.1,
        )
        watchdog.start()
        clock_health.checked.clear()
        clock_health.fail = True
        self.assertTrue(clock_health.checked.wait(1))
        self.assertEqual(lifecycle.check_calls, 0)
        self.assertEqual(pauses, ["GATEWAY_CLOCK_WATCHDOG_FAILED"])

    def test_clock_health_detects_rollback_and_elapsed_time_divergence(self) -> None:
        wall = datetime(2030, 1, 1, tzinfo=UTC)
        monotonic = 100.0
        monitor = ClockHealthMonitor(
            wall_clock=lambda: wall,
            monotonic_clock=lambda: monotonic,
            max_drift_seconds=0.5,
        )
        monitor.check()
        wall += timedelta(seconds=1)
        monotonic += 1
        monitor.check()
        wall -= timedelta(seconds=2)
        monotonic += 1
        with self.assertRaises(RuntimeError):
            monitor.check()

        wall = datetime(2030, 1, 1, tzinfo=UTC)
        monotonic = 100.0
        divergent = ClockHealthMonitor(
            wall_clock=lambda: wall,
            monotonic_clock=lambda: monotonic,
            max_drift_seconds=0.5,
        )
        divergent.check()
        wall += timedelta(seconds=5)
        monotonic += 1
        with self.assertRaises(RuntimeError):
            divergent.check()

    def test_shutdown_cleanup_failure_remains_degraded(self) -> None:
        lifecycle = FixtureLifecycle()
        pauses: list[str] = []
        supervisor = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
            pause_safety=pauses.append,
            interval_seconds=0.1,
        )
        supervisor.start()
        lifecycle.fail_recovery = True
        supervisor.stop()
        self.assertEqual(supervisor.status()["status"], "degraded")
        self.assertEqual(
            supervisor.status()["reason_code"], "GATEWAY_RUNTIME_SHUTDOWN_FAILED"
        )
        self.assertEqual(pauses, ["GATEWAY_RUNTIME_SHUTDOWN_FAILED"])

    def test_watchdog_join_timeout_remains_degraded(self) -> None:
        lifecycle = BlockingLifecycle()
        pauses: list[str] = []
        supervisor = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
            pause_safety=pauses.append,
            interval_seconds=0.1,
            join_timeout_seconds=0.1,
        )
        supervisor.start()
        self.assertTrue(lifecycle.checked.wait(1))
        supervisor.stop()
        self.assertEqual(supervisor.status()["status"], "degraded")
        self.assertEqual(
            supervisor.status()["reason_code"], "GATEWAY_WATCHDOG_STOP_TIMEOUT"
        )
        self.assertEqual(pauses, ["GATEWAY_WATCHDOG_STOP_TIMEOUT"])
        lifecycle.release.set()

    def test_failed_safety_pause_is_reported_without_exception_details(self) -> None:
        lifecycle = FixtureLifecycle(fail_recovery=True)

        def fail_pause(_reason: str) -> None:
            raise RuntimeError("sensitive synthetic detail")

        supervisor = GatewayRuntimeSupervisor(
            lifecycle=lifecycle,
            pause_safety=fail_pause,
            interval_seconds=0.1,
        )
        supervisor.start()
        self.assertEqual(
            supervisor.status(),
            {
                "status": "degraded",
                "reason_code": "GATEWAY_SAFETY_PAUSE_FAILED",
                "recovered_instances": 0,
                "watchdog_running": False,
                "execution_enabled": False,
            },
        )

    def test_missing_supervisor_denies_when_durable_runtime_may_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("PRAGMA foreign_keys = OFF")
                connection.execute(
                    """INSERT INTO gateway_runtime_instances(
                    runtime_id, session_id, containment_attestation_id, oci_runtime,
                    oci_runtime_instance_id, gateway_network_id, image_digest, container_id,
                    status, created_at, execution_enabled
                    ) VALUES ('runtime-1', 'session-1', 'attestation-1', 'podman',
                    'oci-1', 'network-1', ?, ?, 'running', '2026-08-09T00:00:00Z', 0)""",
                    ("sha256:" + "a" * 64, "b" * 64),
                )
            pauses: list[str] = []
            supervisor = UnconfiguredGatewayRuntimeSupervisor(
                database_path=database, pause_safety=pauses.append
            )
            supervisor.start()
            self.assertEqual(supervisor.status()["status"], "degraded")
            self.assertEqual(pauses, ["GATEWAY_RUNTIME_SUPERVISOR_UNAVAILABLE"])

    def test_missing_supervisor_is_disabled_when_no_runtime_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            supervisor = UnconfiguredGatewayRuntimeSupervisor(
                database_path=database, pause_safety=lambda _reason: None
            )
            supervisor.start()
            self.assertEqual(supervisor.status()["status"], "disabled")
            self.assertFalse(supervisor.status()["execution_enabled"])


if __name__ == "__main__":
    unittest.main()
