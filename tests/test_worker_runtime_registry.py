from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pentai_core.migrate import migrate
from pentai_core.worker_runtime_registry import (
    DurableWorkerRuntimeRegistry,
    WorkerRegistryError,
)

IMAGE = "sha256:" + "a" * 64
CONTAINER = "b" * 64
NOW = datetime(2026, 8, 17, 12, tzinfo=UTC)


def containment(**updates: object) -> dict[str, object]:
    document: dict[str, object] = {
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
    document.update(updates)
    return document


class DurableWorkerRuntimeRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.registry = DurableWorkerRuntimeRegistry(
            database_path=self.database, clock=lambda: NOW
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_launch_intent_precedes_container_binding_and_feeds_watchdog(self) -> None:
        planned = self.registry.register_launch_intent(
            worker_id="fixture:worker", containment=containment(), image_digest=IMAGE
        )
        self.assertEqual(planned["status"], "launching")
        self.assertIsNone(planned["container_id"])
        self.assertFalse(planned["execution_enabled"])
        self.assertEqual(self.registry.bindings(), ())

        running = self.registry.mark_running(
            worker_id="fixture:worker", container_id=CONTAINER
        )
        self.assertEqual((running["status"], running["version"]), ("running", 2))
        self.assertEqual(
            self.registry.bindings()[0].worker_gateway_network_id,
            "fixture:worker-network",
        )

    def test_duplicate_worker_or_active_containment_identity_denies(self) -> None:
        self.registry.register_launch_intent(
            worker_id="fixture:worker", containment=containment(), image_digest=IMAGE
        )
        cases = (
            ("fixture:worker", containment(runtime_instance_id="fixture:other-runtime")),
            ("fixture:other-worker", containment()),
        )
        for worker_id, evidence in cases:
            with self.subTest(worker_id=worker_id), self.assertRaises(
                WorkerRegistryError
            ) as raised:
                self.registry.register_launch_intent(
                    worker_id=worker_id, containment=evidence, image_digest=IMAGE
                )
            self.assertEqual(raised.exception.code, "WORKER_REGISTRATION_CONFLICT")

    def test_invalid_evidence_identity_and_transition_fail_closed(self) -> None:
        cases = (
            ("--worker", containment(), IMAGE),
            ("fixture:worker", containment(expires_at="2026-08-17T11:59:59Z"), IMAGE),
            ("fixture:worker", containment(network_role="gateway"), IMAGE),
            ("fixture:worker", containment(), "latest"),
        )
        for worker_id, evidence, image in cases:
            with self.subTest(worker_id=worker_id, image=image), self.assertRaises(
                WorkerRegistryError
            ):
                self.registry.register_launch_intent(
                    worker_id=worker_id, containment=evidence, image_digest=image
                )
        with self.assertRaises(WorkerRegistryError) as inactive:
            self.registry.mark_running(worker_id="missing", container_id=CONTAINER)
        self.assertEqual(inactive.exception.code, "WORKER_RUNTIME_INACTIVE")

    def test_recovery_candidates_include_pre_effect_and_running_records(self) -> None:
        self.registry.register_launch_intent(
            worker_id="fixture:worker", containment=containment(), image_digest=IMAGE
        )
        self.assertEqual(
            self.registry.recovery_candidates(),
            (
                {
                    "worker_id": "fixture:worker",
                    "container_id": None,
                    "status": "launching",
                    "version": 1,
                    "execution_enabled": False,
                },
            ),
        )
        self.registry.mark_running(worker_id="fixture:worker", container_id=CONTAINER)
        self.assertEqual(self.registry.recovery_candidates()[0]["container_id"], CONTAINER)

    def test_database_guards_identity_version_history_and_execution(self) -> None:
        self.registry.register_launch_intent(
            worker_id="fixture:worker", containment=containment(), image_digest=IMAGE
        )
        with closing(sqlite3.connect(self.database)) as connection:
            statements = (
                "UPDATE worker_runtime_instances SET runtime_instance_id = 'changed', "
                "version = version + 1",
                "UPDATE worker_runtime_instances SET updated_at = 'changed'",
                "UPDATE worker_runtime_instances SET execution_enabled = 1, "
                "version = version + 1",
                "DELETE FROM worker_runtime_instances",
            )
            for statement in statements:
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)


if __name__ == "__main__":
    unittest.main()
