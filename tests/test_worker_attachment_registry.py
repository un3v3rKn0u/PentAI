from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pentai_core.migrate import migrate
from pentai_core.worker_attachment_registry import (
    DurableWorkerAttachmentRegistry,
    WorkerAttachmentRegistryError,
)
from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry

NOW = datetime(2026, 8, 19, 10, tzinfo=UTC)
IMAGE = "sha256:" + "a" * 64
WORKER = "fixture:worker"
CONTAINER = "b" * 64
GATEWAY = "c" * 64


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


class DurableWorkerAttachmentRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        runtime = DurableWorkerRuntimeRegistry(
            database_path=self.database, clock=lambda: NOW
        )
        runtime.register_launch_intent(
            worker_id=WORKER, containment=containment(), image_digest=IMAGE
        )
        self.running = runtime.mark_running(worker_id=WORKER, container_id=CONTAINER)
        self.registry = DurableWorkerAttachmentRegistry(
            database_path=self.database, clock=lambda: NOW
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self, evidence: dict[str, object] | None = None) -> dict[str, object]:
        return self.registry.prepare(
            worker_id=WORKER,
            expected_runtime_version=int(self.running["version"]),
            containment=evidence or containment(),
            gateway_container_id=GATEWAY,
        )

    def test_pre_effect_state_binds_fresh_evidence_and_exact_running_worker(self) -> None:
        evidence = containment()
        prepared = self.prepare(evidence)

        self.assertEqual(prepared["status"], "prepared")
        self.assertEqual(prepared["attachment_attestation_id"], evidence["attestation_id"])
        self.assertEqual(prepared["runtime_version"], self.running["version"])
        self.assertEqual(prepared["container_id"], CONTAINER)
        self.assertEqual(prepared["gateway_container_id"], GATEWAY)
        self.assertFalse(prepared["execution_enabled"])

    def test_identity_or_freshness_drift_denies_without_record(self) -> None:
        cases = (
            ({"expires_at": "2026-08-19T09:59:59Z"}, int(self.running["version"]), GATEWAY),
            ({"runtime_instance_id": "changed"}, int(self.running["version"]), GATEWAY),
            ({"worker_gateway_network_id": "changed"}, int(self.running["version"]), GATEWAY),
            ({"runtime": "docker"}, int(self.running["version"]), GATEWAY),
            ({}, int(self.running["version"]) + 1, GATEWAY),
            ({}, int(self.running["version"]), "not-a-container"),
        )
        for updates, version, gateway in cases:
            with self.subTest(updates=updates, version=version), self.assertRaises(
                WorkerAttachmentRegistryError
            ):
                self.registry.prepare(
                    worker_id=WORKER,
                    expected_runtime_version=version,
                    containment=containment(**updates),
                    gateway_container_id=gateway,
                )
        self.assertEqual(self.registry.recovery_candidates(), ())

    def test_version_fenced_success_and_failure_transitions(self) -> None:
        prepared = self.prepare()
        attached = self.registry.mark_attached(
            worker_id=WORKER, expected_version=int(prepared["version"])
        )
        self.assertEqual((attached["status"], attached["version"]), ("attached", 2))
        with self.assertRaises(WorkerAttachmentRegistryError) as replayed:
            self.registry.mark_attached(
                worker_id=WORKER, expected_version=int(attached["version"])
            )
        self.assertEqual(replayed.exception.code, "WORKER_ATTACHMENT_RACE")

        failed = self.registry.mark_failed(
            worker_id=WORKER,
            expected_version=int(attached["version"]),
            reason="post-attachment inspection failed",
        )
        self.assertEqual((failed["status"], failed["version"]), ("failed", 3))
        self.assertEqual(self.registry.recovery_candidates()[0]["status"], "failed")

    def test_duplicate_and_database_mutation_attempts_fail_closed(self) -> None:
        self.prepare()
        with self.assertRaises(WorkerAttachmentRegistryError) as duplicate:
            self.prepare()
        self.assertEqual(duplicate.exception.code, "WORKER_ATTACHMENT_CONFLICT")

        with closing(sqlite3.connect(self.database)) as connection:
            statements = (
                "UPDATE worker_network_attachments SET container_id = 'changed', "
                "version = version + 1",
                "UPDATE worker_network_attachments SET execution_enabled = 1, "
                "version = version + 1",
                "UPDATE worker_network_attachments SET status = 'attached'",
                "UPDATE worker_network_attachments SET updated_at = 'changed', "
                "version = version + 1",
                "DELETE FROM worker_network_attachments",
            )
            for statement in statements:
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)

    def test_recovery_resolution_requires_failed_attachment_and_terminated_worker(self) -> None:
        prepared = self.prepare()
        with self.assertRaises(WorkerAttachmentRegistryError) as active:
            self.registry.resolve_recovery(
                worker_id=WORKER, expected_version=int(prepared["version"])
            )
        self.assertEqual(active.exception.code, "WORKER_ATTACHMENT_RECOVERY_PENDING")

        failed = self.registry.mark_failed(
            worker_id=WORKER,
            expected_version=int(prepared["version"]),
            reason="startup recovery",
        )
        with self.assertRaises(WorkerAttachmentRegistryError):
            self.registry.resolve_recovery(
                worker_id=WORKER, expected_version=int(failed["version"])
            )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                """UPDATE worker_runtime_instances
                SET status = 'termination_requested', termination_reason = 'recovery',
                    updated_at = '2026-08-19T10:00:01Z', version = version + 1
                WHERE worker_id = ?""",
                (WORKER,),
            )
            connection.execute(
                """UPDATE worker_runtime_instances
                SET status = 'terminated', updated_at = '2026-08-19T10:00:02Z',
                    version = version + 1 WHERE worker_id = ?""",
                (WORKER,),
            )
        resolved = self.registry.resolve_recovery(
            worker_id=WORKER, expected_version=int(failed["version"])
        )
        self.assertEqual(resolved["outcome"], "worker_terminated")
        self.assertFalse(resolved["execution_enabled"])
        self.assertEqual(self.registry.recovery_candidates(), ())
        with self.assertRaises(WorkerAttachmentRegistryError) as replayed:
            self.registry.resolve_recovery(
                worker_id=WORKER, expected_version=int(failed["version"])
            )
        self.assertEqual(replayed.exception.code, "WORKER_ATTACHMENT_RECOVERY_CONFLICT")

        with closing(sqlite3.connect(self.database)) as connection:
            for statement in (
                "UPDATE worker_attachment_recoveries SET recovered_at = 'changed'",
                "DELETE FROM worker_attachment_recoveries",
            ):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)


if __name__ == "__main__":
    unittest.main()
