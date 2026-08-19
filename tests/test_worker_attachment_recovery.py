from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pentai_core.migrate import migrate
from pentai_core.worker_attachment_recovery import (
    WorkerAttachmentRecovery,
    WorkerAttachmentRecoveryError,
)
from pentai_core.worker_attachment_registry import DurableWorkerAttachmentRegistry
from pentai_core.worker_runtime_recovery import WorkerRuntimeRecovery
from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry

NOW = datetime(2026, 8, 19, 17, tzinfo=UTC)
IMAGE = "sha256:" + "a" * 64
GATEWAY = "c" * 64


def containment(worker_id: str) -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "attestation_id": str(uuid4()),
        "runtime": "podman",
        "runtime_instance_id": f"{worker_id}:runtime",
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
        "worker_gateway_network_id": f"{worker_id}:network",
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(seconds=29)).isoformat().replace("+00:00", "Z"),
    }


@dataclass
class Controller:
    fail: bool = False
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def discover_owned(self, worker_id: str) -> str | None:
        self.calls.append(("discover", worker_id))
        return None

    def verify_ownership(self, worker_id: str, container_id: str) -> None:
        self.calls.append(("verify", worker_id, container_id))

    def terminate(self, container_id: str) -> None:
        self.calls.append(("terminate", container_id))
        if self.fail:
            raise RuntimeError("private cleanup detail")


class WorkerAttachmentRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.runtime = DurableWorkerRuntimeRegistry(
            database_path=self.database, clock=lambda: NOW
        )
        self.attachments = DurableWorkerAttachmentRegistry(
            database_path=self.database, clock=lambda: NOW
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def register(self, worker_id: str, container_id: str) -> dict[str, object]:
        evidence = containment(worker_id)
        self.runtime.register_launch_intent(
            worker_id=worker_id, containment=evidence, image_digest=IMAGE
        )
        running = self.runtime.mark_running(
            worker_id=worker_id, container_id=container_id
        )
        return self.attachments.prepare(
            worker_id=worker_id,
            expected_runtime_version=int(running["version"]),
            containment=containment(worker_id),
            gateway_container_id=GATEWAY,
        )

    def recovery(
        self, controller_for: Callable[[str], Controller]
    ) -> WorkerAttachmentRecovery:
        runtime_recovery = WorkerRuntimeRecovery(
            registry=self.runtime, controller_for=controller_for
        )
        return WorkerAttachmentRecovery(
            registry=self.attachments, runtime_recovery=runtime_recovery
        )

    def test_prepared_attachment_fails_then_terminates_and_resolves(self) -> None:
        worker = "fixture:worker"
        container = "b" * 64
        self.register(worker, container)
        controller = Controller()

        self.assertEqual(self.recovery(lambda _runtime: controller).recover_all(), 1)
        self.assertEqual(
            controller.calls,
            [("verify", worker, container), ("terminate", container)],
        )
        self.assertEqual(self.attachments.recovery_candidates(), ())
        self.assertEqual(self.runtime.recovery_candidates(), ())
        self.assertEqual(self.recovery(lambda _runtime: controller).recover_all(), 0)

    def test_already_terminated_failed_attachment_resolves_without_second_oci_effect(self) -> None:
        worker = "fixture:worker"
        container = "b" * 64
        prepared = self.register(worker, container)
        failed = self.attachments.mark_failed(
            worker_id=worker,
            expected_version=int(prepared["version"]),
            reason="prior cleanup",
        )
        controller = Controller()
        runtime_recovery = WorkerRuntimeRecovery(
            registry=self.runtime, controller_for=lambda _runtime: controller
        )
        runtime_recovery.terminate_worker(worker, "prior cleanup")
        controller.calls.clear()

        recovery = WorkerAttachmentRecovery(
            registry=self.attachments, runtime_recovery=runtime_recovery
        )
        self.assertEqual(recovery.recover_all(), 1)
        self.assertEqual(controller.calls, [])
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(self.attachments.recovery_candidates(), ())

    def test_failure_does_not_hide_remaining_attachment_and_stays_retryable(self) -> None:
        workers = (("fixture:worker-a", "b" * 64), ("fixture:worker-b", "d" * 64))
        for worker, container in workers:
            self.register(worker, container)
        first = Controller(fail=True)
        second = Controller()
        controllers = iter((first, second))
        recovery = self.recovery(lambda _runtime: next(controllers))

        with self.assertRaises(WorkerAttachmentRecoveryError) as raised:
            recovery.recover_all()
        self.assertEqual(raised.exception.code, "WORKER_ATTACHMENT_RECOVERY_INCOMPLETE")
        self.assertNotIn("private", str(raised.exception))
        remaining = self.attachments.recovery_candidates()
        self.assertEqual([item["worker_id"] for item in remaining], ["fixture:worker-a"])
        self.assertEqual(remaining[0]["status"], "failed")
        self.assertTrue(second.calls)


if __name__ == "__main__":
    unittest.main()
