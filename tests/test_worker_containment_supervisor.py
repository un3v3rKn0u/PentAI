from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import uuid4

from pentai_core.worker_containment_supervisor import (
    AttachmentAwareWorkerContainmentMonitor,
    RegisteredWorkerContainmentMonitor,
    WorkerContainmentBinding,
    WorkerContainmentSupervisor,
    WorkerSupervisionBinding,
)


def attestation(
    *, runtime_id: str = "fixture:runtime", network_id: str = "fixture:worker-network"
) -> dict[str, object]:
    observed = datetime.now(UTC)
    return {
        "schema_version": "2.0.0",
        "attestation_id": str(uuid4()),
        "runtime": "podman",
        "runtime_instance_id": runtime_id,
        "network_role": "worker_gateway",
        "rootless": True,
        "read_only_root": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "host_pid_disabled": True,
        "host_ipc_disabled": True,
        "host_network_disabled": True,
        "runtime_socket_mounted": False,
        "resource_limits_supported": True,
        "temporary_mounts_only": True,
        "worker_gateway_network_id": network_id,
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "expires_at": (observed + timedelta(seconds=30)).isoformat().replace(
            "+00:00", "Z"
        ),
    }


@dataclass
class FixtureAttestor:
    document: dict[str, object]

    def measure(self) -> dict[str, object]:
        return self.document


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
            raise RuntimeError("sensitive synthetic detail")
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


class WorkerContainmentSupervisorTests(unittest.TestCase):
    def test_attachment_aware_monitor_selects_exact_topology_after_attachment(self) -> None:
        pre = WorkerSupervisionBinding(
            "fixture:pre", "fixture:runtime", "fixture:worker-network",
            "a" * 64, "sha256:" + "b" * 64, None, None,
        )
        attached = WorkerSupervisionBinding(
            "fixture:attached", "fixture:runtime", "fixture:worker-network",
            "c" * 64, "sha256:" + "d" * 64, "e" * 64, "attached",
        )
        events: list[tuple[str, str]] = []
        monitor = AttachmentAwareWorkerContainmentMonitor(
            bindings=lambda: (pre, attached),
            pre_attachment_attestor_for=lambda binding: (
                events.append(("pre", binding.worker_id))
                or FixtureAttestor(attestation())
            ),
            verify_worker=lambda binding: events.append(("worker", binding.worker_id)),
            verify_attachment=lambda binding: events.append(("attached", binding.worker_id)),
        )
        self.assertEqual(monitor.check_all(), 2)
        self.assertEqual(
            events,
            [
                ("worker", "fixture:pre"),
                ("pre", "fixture:pre"),
                ("worker", "fixture:attached"),
                ("attached", "fixture:attached"),
            ],
        )

    def test_attachment_aware_monitor_denies_uncertain_attachment_state(self) -> None:
        binding = WorkerSupervisionBinding(
            "fixture:worker", "fixture:runtime", "fixture:worker-network",
            "a" * 64, "sha256:" + "b" * 64, "c" * 64, "prepared",
        )
        monitor = AttachmentAwareWorkerContainmentMonitor(
            bindings=lambda: (binding,),
            pre_attachment_attestor_for=lambda _binding: FixtureAttestor(attestation()),
            verify_worker=lambda _binding: None,
            verify_attachment=lambda _binding: None,
        )
        with self.assertRaisesRegex(ValueError, "unsafe"):
            monitor.check_all()

    def test_registered_monitor_remeasures_exact_worker_identities(self) -> None:
        binding = WorkerContainmentBinding(
            "fixture:worker", "fixture:runtime", "fixture:worker-network"
        )
        requested: list[WorkerContainmentBinding] = []
        monitor = RegisteredWorkerContainmentMonitor(
            bindings=lambda: (binding,),
            attestor_for=lambda value: (
                requested.append(value) or FixtureAttestor(attestation())
            ),
        )
        self.assertEqual(monitor.check_all(), 1)
        self.assertEqual(requested, [binding])

    def test_registered_monitor_denies_identity_drift_and_ambiguous_bindings(self) -> None:
        binding = WorkerContainmentBinding(
            "fixture:worker", "fixture:runtime", "fixture:worker-network"
        )
        cases = (
            ((binding,), attestation(runtime_id="fixture:changed-runtime")),
            ((binding,), attestation(network_id="fixture:changed-network")),
            ((binding, binding), attestation()),
            (
                (
                    WorkerContainmentBinding(
                        "--worker", "fixture:runtime", "fixture:worker-network"
                    ),
                ),
                attestation(),
            ),
        )
        for bindings, document in cases:
            with self.subTest(bindings=bindings), self.assertRaises(ValueError):
                RegisteredWorkerContainmentMonitor(
                    bindings=lambda bindings=bindings: bindings,
                    attestor_for=lambda _binding, document=document: FixtureAttestor(
                        document
                    ),
                ).check_all()

    def test_startup_check_precedes_ready_and_watchdog_repeats(self) -> None:
        monitor = FixtureMonitor(monitored=2)
        pauses: list[str] = []
        terminations: list[str] = []
        supervisor = WorkerContainmentSupervisor(
            monitor=monitor,
            pause_safety=pauses.append,
            terminate_workers=terminations.append,
            interval_seconds=0.1,
            join_timeout_seconds=1,
        )
        supervisor.start()
        self.assertEqual(
            supervisor.status(),
            {
                "status": "ready",
                "reason_code": None,
                "monitored_workers": 2,
                "watchdog_running": True,
                "execution_enabled": False,
            },
        )
        self.assertEqual(monitor.calls, 1)
        monitor.checked.clear()
        self.assertTrue(monitor.checked.wait(1))
        supervisor.stop()
        self.assertEqual(supervisor.status()["status"], "stopped")
        self.assertEqual((pauses, terminations), ([], []))

    def test_startup_recovery_precedes_initial_containment_check(self) -> None:
        events: list[str] = []

        class OrderedMonitor(FixtureMonitor):
            def check_all(self) -> int:
                events.append("check")
                return super().check_all()

        supervisor = WorkerContainmentSupervisor(
            monitor=OrderedMonitor(),
            pause_safety=lambda _reason: None,
            terminate_workers=lambda _reason: None,
            recover_workers=lambda: events.append("recover"),
            interval_seconds=1,
        )
        supervisor.start()
        supervisor.stop()
        self.assertEqual(events[:2], ["recover", "check"])

    def test_startup_or_watchdog_drift_pauses_and_terminates_workers(self) -> None:
        for startup in (True, False):
            monitor = FixtureMonitor(fail=startup)
            events: list[tuple[str, str]] = []
            terminated = Event()

            def terminate(
                reason: str,
                events: list[tuple[str, str]] = events,
                terminated: Event = terminated,
            ) -> None:
                events.append(("terminate", reason))
                terminated.set()

            supervisor = WorkerContainmentSupervisor(
                monitor=monitor,
                pause_safety=lambda reason, events=events: events.append(("pause", reason)),
                terminate_workers=terminate,
                interval_seconds=0.1,
            )
            supervisor.start()
            if not startup:
                monitor.fail = True
                monitor.checked.clear()
                self.assertTrue(monitor.checked.wait(1))
            self.assertTrue(terminated.wait(1))
            expected = (
                "WORKER_CONTAINMENT_STARTUP_FAILED"
                if startup
                else "WORKER_CONTAINMENT_WATCHDOG_FAILED"
            )
            self.assertEqual(supervisor.status()["reason_code"], expected)
            self.assertEqual(events, [("pause", expected), ("terminate", expected)])

    def test_control_failure_and_join_timeout_remain_degraded(self) -> None:
        failed_pause = WorkerContainmentSupervisor(
            monitor=FixtureMonitor(fail=True),
            pause_safety=lambda _reason: (_ for _ in ()).throw(RuntimeError("private")),
            terminate_workers=lambda _reason: None,
        )
        failed_pause.start()
        self.assertEqual(
            failed_pause.status()["reason_code"], "WORKER_SAFETY_PAUSE_FAILED"
        )

        failed_termination = WorkerContainmentSupervisor(
            monitor=FixtureMonitor(fail=True),
            pause_safety=lambda _reason: None,
            terminate_workers=lambda _reason: (_ for _ in ()).throw(
                RuntimeError("private")
            ),
        )
        failed_termination.start()
        self.assertEqual(
            failed_termination.status()["reason_code"], "WORKER_TERMINATION_FAILED"
        )

        monitor = BlockingMonitor()
        terminations: list[str] = []
        timeout = WorkerContainmentSupervisor(
            monitor=monitor,
            pause_safety=lambda _reason: None,
            terminate_workers=terminations.append,
            interval_seconds=0.1,
            join_timeout_seconds=0.1,
        )
        timeout.start()
        monitor.checked.clear()
        self.assertTrue(monitor.checked.wait(1))
        timeout.stop()
        self.assertEqual(
            timeout.status()["reason_code"], "WORKER_CONTAINMENT_STOP_TIMEOUT"
        )
        self.assertEqual(terminations, ["WORKER_CONTAINMENT_STOP_TIMEOUT"])
        monitor.release.set()


if __name__ == "__main__":
    unittest.main()
