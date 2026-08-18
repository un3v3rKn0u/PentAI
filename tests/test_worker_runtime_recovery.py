from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pentai_core.migrate import migrate
from pentai_core.worker_runtime_recovery import WorkerRecoveryError, WorkerRuntimeRecovery
from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry

NOW = datetime(2026, 8, 18, 12, tzinfo=UTC)
IMAGE = "sha256:" + "a" * 64
CONTAINER = "b" * 64


def containment(*, runtime_id: str = "fixture:runtime") -> dict[str, object]:
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
        "worker_gateway_network_id": f"{runtime_id}:network",
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(seconds=29)).isoformat().replace("+00:00", "Z"),
    }


@dataclass
class Controller:
    discovered: str | None = None
    fail_ownership: bool = False
    fail_termination: bool = False
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def discover_owned(self, worker_id: str) -> str | None:
        self.calls.append(("discover", worker_id))
        return self.discovered

    def verify_ownership(self, worker_id: str, container_id: str) -> None:
        self.calls.append(("verify", worker_id, container_id))
        if self.fail_ownership:
            raise RuntimeError("synthetic private detail")

    def terminate(self, container_id: str) -> None:
        self.calls.append(("terminate", container_id))
        if self.fail_termination:
            raise RuntimeError("synthetic private detail")


class WorkerRuntimeRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.registry = DurableWorkerRuntimeRegistry(
            database_path=self.database, clock=lambda: NOW
        )
        self.controller = Controller()
        self.runtimes: list[str] = []
        self.recovery = WorkerRuntimeRecovery(
            registry=self.registry,
            controller_for=lambda runtime: self.runtimes.append(runtime) or self.controller,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def register(self, worker_id: str = "fixture:worker") -> None:
        self.registry.register_launch_intent(
            worker_id=worker_id,
            containment=containment(runtime_id=f"{worker_id}:runtime"),
            image_digest=IMAGE,
        )

    def status(self, worker_id: str = "fixture:worker") -> tuple[str, int, str | None]:
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute(
                """SELECT status, version, container_id FROM worker_runtime_instances
                WHERE worker_id = ?""",
                (worker_id,),
            ).fetchone()
        assert row is not None
        return str(row[0]), int(row[1]), row[2]

    def test_pre_effect_intent_without_container_finalizes_without_oci_removal(self) -> None:
        self.register()
        self.assertEqual(self.recovery.recover_all(), 1)
        self.assertEqual(self.status(), ("terminated", 3, None))
        self.assertEqual(self.controller.calls, [("discover", "fixture:worker")])
        self.assertEqual(self.runtimes, ["podman"])
        self.assertEqual(self.recovery.recover_all(), 0)

    def test_crash_gap_discovery_persists_ownership_before_bounded_termination(self) -> None:
        self.register()
        self.controller.discovered = CONTAINER
        self.assertEqual(self.recovery.recover_all(), 1)
        self.assertEqual(self.status(), ("terminated", 3, CONTAINER))
        self.assertEqual(
            self.controller.calls,
            [
                ("discover", "fixture:worker"),
                ("verify", "fixture:worker", CONTAINER),
                ("terminate", CONTAINER),
            ],
        )

    def test_running_and_interrupted_termination_resume_without_discovery(self) -> None:
        self.register()
        self.registry.mark_running(worker_id="fixture:worker", container_id=CONTAINER)
        candidate = self.registry.recovery_candidates()[0]
        requested = self.registry.request_termination(
            worker_id="fixture:worker",
            expected_version=int(candidate["version"]),
            reason="watchdog drift",
        )
        self.assertEqual(requested["status"], "termination_requested")
        self.assertEqual(self.recovery.recover_all(), 1)
        self.assertEqual(self.status(), ("terminated", 4, CONTAINER))
        self.assertEqual(self.controller.calls[0][0], "verify")

    def test_failure_is_durable_retryable_and_does_not_leak_diagnostics(self) -> None:
        self.register()
        self.registry.mark_running(worker_id="fixture:worker", container_id=CONTAINER)
        self.controller.fail_termination = True
        with self.assertRaises(WorkerRecoveryError) as raised:
            self.recovery.recover_all()
        self.assertEqual(raised.exception.code, "WORKER_RECOVERY_INCOMPLETE")
        self.assertNotIn("private", str(raised.exception))
        self.assertEqual(self.status()[0], "failed")

        self.controller.fail_termination = False
        self.assertEqual(self.recovery.recover_all(), 1)
        self.assertEqual(self.status()[0], "terminated")

    def test_recovery_attempts_remaining_workers_after_one_failure(self) -> None:
        self.register("fixture:worker-a")
        self.register("fixture:worker-b")
        first = Controller(discovered="b" * 64, fail_ownership=True)
        second = Controller(discovered="c" * 64)
        controllers = iter((first, second))
        recovery = WorkerRuntimeRecovery(
            registry=self.registry,
            controller_for=lambda _runtime: next(controllers),
        )
        with self.assertRaises(WorkerRecoveryError):
            recovery.recover_all()
        self.assertEqual(self.status("fixture:worker-a")[0], "failed")
        self.assertEqual(self.status("fixture:worker-b")[0], "terminated")

    def test_targeted_termination_does_not_sweep_an_unrelated_worker(self) -> None:
        self.register("fixture:worker-a")
        self.register("fixture:worker-b")
        self.recovery.terminate_worker("fixture:worker-a", "launch did not complete")

        self.assertEqual(self.status("fixture:worker-a")[0], "terminated")
        self.assertEqual(self.status("fixture:worker-b")[0], "launching")
        with self.assertRaises(WorkerRecoveryError) as raised:
            self.recovery.terminate_worker("fixture:missing", "launch did not complete")
        self.assertEqual(raised.exception.code, "WORKER_RECOVERY_INVALID")


if __name__ == "__main__":
    unittest.main()
