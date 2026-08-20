from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pentai_core.migrate import migrate
from pentai_core.worker_attachment_registry import DurableWorkerAttachmentRegistry
from pentai_core.worker_runtime_launch import (
    PodmanDirectWorkerGatewayLaunchCoordinator,
    WorkerLaunchError,
    WorkerRuntimeLaunchCoordinator,
)
from pentai_core.worker_runtime_recovery import WorkerRuntimeRecovery
from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry

NOW = datetime(2026, 8, 18, 15, tzinfo=UTC)
IMAGE = "sha256:" + "a" * 64
CONTAINER = "b" * 64
WORKER = "fixture:worker"
GATEWAY = "c" * 64
NETWORK_NAME = "pentai-worker-gateway"


def containment() -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "attestation_id": str(uuid4()),
        "runtime": "podman",
        "runtime_instance_id": "fixture:runtime",
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
        "worker_gateway_network_id": "fixture:worker-network",
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(seconds=29)).isoformat().replace("+00:00", "Z"),
    }


@dataclass
class Attestor:
    document: object = field(default_factory=containment)
    error: Exception | None = None
    calls: int = 0

    def measure(self) -> dict[str, object]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.document  # type: ignore[return-value]


@dataclass
class Controller:
    events: list[str]
    fail_at: str | None = None
    fail_termination: bool = False
    discovered: str | None = CONTAINER

    def launch(self, worker_id: str, image_digest: str) -> str:
        self.events.append("launch")
        if self.fail_at == "launch":
            raise RuntimeError("private launch detail")
        return CONTAINER

    def verify(self, worker_id: str, container_id: str, image_digest: str) -> None:
        self.events.append("verify")
        if self.fail_at == "verify":
            raise RuntimeError("private inspection detail")

    def launch_attached(self, worker_id: str, image_digest: str, *, network_id: str) -> str:
        self.events.append("launch_attached")
        if self.fail_at == "launch":
            raise RuntimeError("private launch detail")
        return CONTAINER

    def verify_attached(
        self,
        worker_id: str,
        container_id: str,
        image_digest: str,
        *,
        network_name: str,
        network_id: str,
    ) -> None:
        self.events.append("verify_attached")
        if self.fail_at == "verify":
            raise RuntimeError("private inspection detail")

    def discover_owned(self, worker_id: str) -> str | None:
        self.events.append("discover")
        return self.discovered

    def verify_ownership(self, worker_id: str, container_id: str) -> None:
        self.events.append("verify_ownership")

    def terminate(self, container_id: str) -> None:
        self.events.append("terminate")
        if self.fail_termination:
            raise RuntimeError("private termination detail")


@dataclass
class Topology:
    events: list[str]
    fail: bool = False

    def verify_attached(self, **kwargs: str) -> object:
        self.events.append("verify_topology")
        if self.fail:
            raise RuntimeError("private topology detail")
        return {}


class WorkerRuntimeLaunchCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.registry = DurableWorkerRuntimeRegistry(
            database_path=self.database, clock=lambda: NOW
        )
        self.attachments = DurableWorkerAttachmentRegistry(
            database_path=self.database, clock=lambda: NOW
        )
        self.events: list[str] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def coordinator(
        self, controller: Controller, attestor: Attestor | None = None
    ) -> WorkerRuntimeLaunchCoordinator:
        recovery = WorkerRuntimeRecovery(
            registry=self.registry, controller_for=lambda _runtime: controller
        )
        return WorkerRuntimeLaunchCoordinator(
            registry=self.registry,
            controller=controller,
            recovery=recovery,
            attestor=attestor or Attestor(),
        )

    def test_persists_before_effect_then_verifies_and_activates_sentinel(self) -> None:
        controller = Controller(self.events)
        original_register = self.registry.register_launch_intent

        def register(**kwargs: object) -> dict[str, object]:
            self.events.append("persist")
            return original_register(**kwargs)  # type: ignore[arg-type]

        self.registry.register_launch_intent = register  # type: ignore[method-assign]
        running = self.coordinator(controller).launch(worker_id=WORKER, image_digest=IMAGE)

        self.assertEqual(self.events, ["persist", "launch", "verify"])
        self.assertEqual(running["status"], "running")
        self.assertEqual(running["container_id"], CONTAINER)
        self.assertFalse(running["execution_enabled"])

    def test_attestation_or_registration_denial_has_no_runtime_effect(self) -> None:
        for attestor in (Attestor(document=[]), Attestor(error=RuntimeError("private"))):
            with self.subTest(document=attestor.document):
                controller = Controller([])
                with self.assertRaises(WorkerLaunchError) as raised:
                    self.coordinator(controller, attestor).launch(
                        worker_id=WORKER, image_digest=IMAGE
                    )
                self.assertEqual(raised.exception.code, "WORKER_LAUNCH_DENIED")
                self.assertNotIn("private", str(raised.exception))
                self.assertEqual(controller.events, [])

    def test_partial_launch_is_discovered_and_removed_before_fixed_failure(self) -> None:
        controller = Controller(self.events, fail_at="verify")
        with self.assertRaises(WorkerLaunchError) as raised:
            self.coordinator(controller).launch(worker_id=WORKER, image_digest=IMAGE)

        self.assertEqual(raised.exception.code, "WORKER_LAUNCH_FAILED")
        self.assertNotIn("private", str(raised.exception))
        self.assertEqual(
            self.events,
            ["launch", "verify", "discover", "verify_ownership", "terminate"],
        )
        self.assertEqual(self.registry.recovery_candidates(), ())

    def test_cleanup_failure_remains_durable_and_has_fixed_diagnostic(self) -> None:
        controller = Controller(self.events, fail_at="verify", fail_termination=True)
        with self.assertRaises(WorkerLaunchError) as raised:
            self.coordinator(controller).launch(worker_id=WORKER, image_digest=IMAGE)

        self.assertEqual(raised.exception.code, "WORKER_LAUNCH_CLEANUP_FAILED")
        self.assertNotIn("private", str(raised.exception))
        candidate = self.registry.recovery_candidates()[0]
        self.assertEqual(candidate["status"], "failed")
        self.assertEqual(candidate["container_id"], CONTAINER)

    def direct_coordinator(
        self, controller: Controller, topology: Topology | None = None
    ) -> PodmanDirectWorkerGatewayLaunchCoordinator:
        return PodmanDirectWorkerGatewayLaunchCoordinator(
            runtime_registry=self.registry,
            attachment_registry=self.attachments,
            controller=controller,
            topology=topology or Topology(self.events),
            recovery=WorkerRuntimeRecovery(
                registry=self.registry, controller_for=lambda _runtime: controller
            ),
            attestor=Attestor(),
            network_name=NETWORK_NAME,
        )

    def test_podman_direct_launch_persists_intent_then_verifies_before_attachment(self) -> None:
        controller = Controller(self.events)
        original_register = self.registry.register_direct_attachment_intent
        original_record = self.attachments.record_direct_attached

        def register(**kwargs: object) -> dict[str, object]:
            self.events.append("persist_intent")
            return original_register(**kwargs)  # type: ignore[arg-type]

        def record(**kwargs: object) -> dict[str, object]:
            self.events.append("record_attached")
            return original_record(**kwargs)  # type: ignore[arg-type]

        self.registry.register_direct_attachment_intent = register  # type: ignore[method-assign]
        self.attachments.record_direct_attached = record  # type: ignore[method-assign]
        attached = self.direct_coordinator(controller).launch(
            worker_id=WORKER, image_digest=IMAGE, gateway_container_id=GATEWAY
        )

        self.assertEqual(
            self.events,
            [
                "persist_intent",
                "launch_attached",
                "verify_attached",
                "verify_topology",
                "record_attached",
            ],
        )
        self.assertEqual(attached["status"], "attached")
        self.assertFalse(attached["execution_enabled"])

    def test_podman_direct_topology_failure_removes_exact_owned_worker(self) -> None:
        controller = Controller(self.events)
        with self.assertRaises(WorkerLaunchError) as raised:
            self.direct_coordinator(controller, Topology(self.events, fail=True)).launch(
                worker_id=WORKER, image_digest=IMAGE, gateway_container_id=GATEWAY
            )
        self.assertEqual(raised.exception.code, "WORKER_LAUNCH_FAILED")
        self.assertNotIn("private", str(raised.exception))
        self.assertEqual(self.events[-3:], ["discover", "verify_ownership", "terminate"])


if __name__ == "__main__":
    unittest.main()
