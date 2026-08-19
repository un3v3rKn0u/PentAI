from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pentai_core.migrate import migrate
from pentai_core.runtime_snapshot_collector import CommandResult
from pentai_core.worker_attachment_registry import DurableWorkerAttachmentRegistry
from pentai_core.worker_gateway_attachment import (
    OciWorkerGatewayConnector,
    WorkerGatewayAttachmentCoordinator,
    WorkerGatewayAttachmentError,
)
from pentai_core.worker_runtime_recovery import WorkerRuntimeRecovery
from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry

NOW = datetime(2026, 8, 19, 14, tzinfo=UTC)
IMAGE = "sha256:" + "a" * 64
WORKER = "fixture:worker"
NETWORK = "fixture:worker-network"
CONTAINER = "b" * 64
GATEWAY = "c" * 64


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
        "worker_gateway_network_id": NETWORK,
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(seconds=29)).isoformat().replace("+00:00", "Z"),
    }


@dataclass
class Executor:
    result: CommandResult
    calls: list[tuple[tuple[str, ...], float, int]] = field(default_factory=list)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        self.calls.append((argv, timeout_seconds, max_output_bytes))
        return self.result


@dataclass
class Attestor:
    events: list[str]
    document: object = field(default_factory=containment)

    def measure(self) -> dict[str, object]:
        self.events.append("attest")
        return self.document  # type: ignore[return-value]


@dataclass
class Connector:
    events: list[str]
    fail: bool = False

    def connect(self, *, network_id: str, container_id: str) -> None:
        self.events.append("connect")
        if self.fail:
            raise RuntimeError("private connector detail")


@dataclass
class Topology:
    events: list[str]
    fail: bool = False

    def verify_attached(
        self,
        *,
        network_id: str,
        gateway_container_id: str,
        worker_container_id: str,
    ) -> object:
        self.events.append("inspect")
        if self.fail:
            raise RuntimeError("private topology detail")
        return object()


@dataclass
class RecoveryController:
    events: list[str]
    fail: bool = False

    def discover_owned(self, worker_id: str) -> str | None:
        self.events.append("discover")
        return CONTAINER

    def verify_ownership(self, worker_id: str, container_id: str) -> None:
        self.events.append("verify_ownership")

    def terminate(self, container_id: str) -> None:
        self.events.append("terminate")
        if self.fail:
            raise RuntimeError("private cleanup detail")


class WorkerGatewayAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.runtime = DurableWorkerRuntimeRegistry(
            database_path=self.database, clock=lambda: NOW
        )
        self.runtime.register_launch_intent(
            worker_id=WORKER, containment=containment(), image_digest=IMAGE
        )
        self.running = self.runtime.mark_running(worker_id=WORKER, container_id=CONTAINER)
        self.attachments = DurableWorkerAttachmentRegistry(
            database_path=self.database, clock=lambda: NOW
        )
        self.events: list[str] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def coordinator(
        self,
        *,
        connector: Connector | None = None,
        topology: Topology | None = None,
        recovery_controller: RecoveryController | None = None,
        attestor: Attestor | None = None,
    ) -> WorkerGatewayAttachmentCoordinator:
        cleanup = recovery_controller or RecoveryController(self.events)
        recovery = WorkerRuntimeRecovery(
            registry=self.runtime, controller_for=lambda _runtime: cleanup
        )
        return WorkerGatewayAttachmentCoordinator(
            registry=self.attachments,
            attestor=attestor or Attestor(self.events),
            connector=connector or Connector(self.events),
            topology=topology or Topology(self.events),
            recovery=recovery,
        )

    def attach(self, coordinator: WorkerGatewayAttachmentCoordinator) -> dict[str, object]:
        return coordinator.attach(
            worker_id=WORKER,
            expected_runtime_version=int(self.running["version"]),
            gateway_container_id=GATEWAY,
        )

    def test_bounded_connector_uses_fixed_network_connect_command(self) -> None:
        executor = Executor(CommandResult(0, b""))
        connector = OciWorkerGatewayConnector(
            runtime="docker",
            executable=Path("/usr/bin/docker"),
            executor=executor,
        )
        connector.connect(network_id=NETWORK, container_id=CONTAINER)
        self.assertEqual(
            executor.calls,
            [
                (
                    ("/usr/bin/docker", "network", "connect", NETWORK, CONTAINER),
                    5,
                    4096,
                )
            ],
        )

    def test_podman_denies_unsupported_post_launch_attachment_before_effect(self) -> None:
        executor = Executor(CommandResult(0, b""))
        connector = OciWorkerGatewayConnector(
            runtime="podman",
            executable=Path("/usr/bin/podman"),
            executor=executor,
        )
        with self.assertRaises(WorkerGatewayAttachmentError) as raised:
            connector.connect(network_id=NETWORK, container_id=CONTAINER)
        self.assertEqual(raised.exception.code, "WORKER_ATTACHMENT_STRATEGY_INVALID")
        self.assertEqual(executor.calls, [])

    def test_connector_denies_invalid_identity_or_runtime_failure(self) -> None:
        for network, container, result in (
            ("--network", CONTAINER, CommandResult(0, b"")),
            (NETWORK, "short", CommandResult(0, b"")),
            (NETWORK, CONTAINER, CommandResult(1, b"", b"private")),
        ):
            with self.subTest(network=network, container=container), self.assertRaises(
                WorkerGatewayAttachmentError
            ) as raised:
                OciWorkerGatewayConnector(
                    runtime="docker", executable=Path("/usr/bin/docker"), executor=Executor(result)
                ).connect(network_id=network, container_id=container)
            self.assertNotIn("private", str(raised.exception))

    def test_persists_before_connect_then_verifies_before_attached_state(self) -> None:
        original_prepare = self.attachments.prepare
        original_mark = self.attachments.mark_attached

        def prepare(**kwargs: object) -> dict[str, object]:
            self.events.append("persist")
            return original_prepare(**kwargs)  # type: ignore[arg-type]

        def mark(**kwargs: object) -> dict[str, object]:
            self.events.append("mark_attached")
            return original_mark(**kwargs)  # type: ignore[arg-type]

        self.attachments.prepare = prepare  # type: ignore[method-assign]
        self.attachments.mark_attached = mark  # type: ignore[method-assign]
        attached = self.attach(self.coordinator())

        self.assertEqual(
            self.events, ["attest", "persist", "connect", "inspect", "mark_attached"]
        )
        self.assertEqual(attached["status"], "attached")
        self.assertFalse(attached["execution_enabled"])

    def test_denial_before_persistence_has_no_connect_or_cleanup_effect(self) -> None:
        denied = Attestor(self.events, document=[])
        with self.assertRaises(WorkerGatewayAttachmentError) as raised:
            self.attach(self.coordinator(attestor=denied))
        self.assertEqual(raised.exception.code, "WORKER_ATTACHMENT_DENIED")
        self.assertEqual(self.events, ["attest"])
        self.assertEqual(self.attachments.recovery_candidates(), ())

    def assert_failed_attachment(
        self, *, connector: Connector | None = None, topology: Topology | None = None
    ) -> None:
        with self.assertRaises(WorkerGatewayAttachmentError) as raised:
            self.attach(self.coordinator(connector=connector, topology=topology))
        self.assertEqual(raised.exception.code, "WORKER_ATTACHMENT_FAILED")
        self.assertNotIn("private", str(raised.exception))
        self.assertEqual(self.attachments.recovery_candidates()[0]["status"], "failed")
        self.assertIn("terminate", self.events)
        self.assertEqual(self.runtime.recovery_candidates(), ())

    def test_effect_failure_marks_failed_and_terminates_exact_worker(self) -> None:
        self.assert_failed_attachment(connector=Connector(self.events, fail=True))

    def test_topology_failure_marks_failed_and_terminates_exact_worker(self) -> None:
        self.assert_failed_attachment(topology=Topology(self.events, fail=True))

    def test_cleanup_failure_is_durable_and_returns_fixed_diagnostic(self) -> None:
        cleanup = RecoveryController(self.events, fail=True)
        with self.assertRaises(WorkerGatewayAttachmentError) as raised:
            self.attach(
                self.coordinator(
                    topology=Topology(self.events, fail=True),
                    recovery_controller=cleanup,
                )
            )
        self.assertEqual(raised.exception.code, "WORKER_ATTACHMENT_CLEANUP_FAILED")
        self.assertNotIn("private", str(raised.exception))
        self.assertEqual(self.attachments.recovery_candidates()[0]["status"], "failed")
        self.assertEqual(self.runtime.recovery_candidates()[0]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
