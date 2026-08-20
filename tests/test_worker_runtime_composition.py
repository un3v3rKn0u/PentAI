from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pentai_core.config import Settings
from pentai_core.migrate import migrate
from pentai_core.worker_runtime_composition import compose_worker_runtime_supervisor


class Safety:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def set_global_safety(
        self, *, status: str, reason: str, actor_id: str
    ) -> dict[str, object]:
        self.calls.append((status, reason, actor_id))
        return {}


class Attestor:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def measure(self) -> dict[str, object]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic private detail")
        return {}


class Monitor:
    def check_all(self) -> int:
        return 0


def configured(database: Path) -> Settings:
    return Settings(
        environment="test",
        test_mode=True,
        database_path=database,
        gateway_runtime_enabled=True,
        gateway_runtime="docker",
        gateway_runtime_executable=Path("/bin/echo"),
        gateway_runtime_instance_id="fixture:runtime",
        gateway_network_id="fixture:gateway-network",
        gateway_probe_image_digest="sha256:" + "a" * 64,
        gateway_instance_id="fixture:instance",
        worker_supervision_enabled=True,
        worker_gateway_network_id="fixture-worker-network-id",
        worker_gateway_network_name="fixture-worker-network",
        worker_gateway_container_id="b" * 64,
        worker_gateway_container_name="fixture-gateway",
        worker_watchdog_interval_seconds=0.1,
    )


class WorkerRuntimeCompositionTests(unittest.TestCase):
    def test_environment_requires_explicit_complete_worker_opt_in(self) -> None:
        environment = {
            "PENTAI_ENVIRONMENT": "test",
            "PENTAI_TEST_MODE": "1",
            "PENTAI_GATEWAY_RUNTIME_ENABLED": "1",
            "PENTAI_GATEWAY_RUNTIME": "docker",
            "PENTAI_GATEWAY_RUNTIME_EXECUTABLE": "/usr/bin/docker",
            "PENTAI_GATEWAY_RUNTIME_INSTANCE_ID": "fixture:runtime",
            "PENTAI_GATEWAY_NETWORK_ID": "fixture:network",
            "PENTAI_GATEWAY_PROBE_IMAGE_DIGEST": "sha256:" + "a" * 64,
            "PENTAI_GATEWAY_INSTANCE_ID": "fixture:instance",
            "PENTAI_WORKER_SUPERVISION_ENABLED": "1",
            "PENTAI_WORKER_GATEWAY_NETWORK_ID": "fixture-worker-network-id",
            "PENTAI_WORKER_GATEWAY_NETWORK_NAME": "fixture-worker-network",
            "PENTAI_WORKER_GATEWAY_CONTAINER_ID": "b" * 64,
            "PENTAI_WORKER_GATEWAY_CONTAINER_NAME": "fixture-gateway",
            "PENTAI_WORKER_CONTAINER_NAME": "fixture-worker",
            "PENTAI_WORKER_WATCHDOG_INTERVAL_SECONDS": "1",
        }
        with patch.dict(os.environ, environment, clear=True):
            settings = Settings.from_environment()
        self.assertTrue(settings.worker_supervision_enabled)
        self.assertEqual(settings.worker_gateway_container_id, "b" * 64)
        self.assertEqual(settings.worker_container_name, "fixture-worker")

    def test_disabled_or_incomplete_configuration_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit enablement"):
            Settings(
                environment="test",
                test_mode=True,
                worker_gateway_network_name="fixture-network",
            ).validate()
        with self.assertRaisesRegex(ValueError, "invalid"):
            Settings(
                **(
                    configured(Path("fixture.db")).__dict__
                    | {"worker_gateway_container_id": "bad identity"}
                )
            ).validate()

    def test_empty_registry_recovers_before_ready_without_oci_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            settings = configured(database)
            settings.validate()
            safety = Safety()
            attestor = Attestor()
            supervisor = compose_worker_runtime_supervisor(
                settings=settings,
                safety_control=safety,
                baseline_attestor=attestor,
                monitor=Monitor(),
            )
            supervisor.start()
            self.assertEqual(supervisor.status()["status"], "ready")
            self.assertEqual(supervisor.status()["monitored_workers"], 0)
            supervisor.stop()
            self.assertEqual(attestor.calls, 1)
            self.assertEqual(safety.calls, [])

    def test_configured_baseline_failure_degrades_with_fixed_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            safety = Safety()
            supervisor = compose_worker_runtime_supervisor(
                settings=configured(database),
                safety_control=safety,
                baseline_attestor=Attestor(fail=True),
                monitor=Monitor(),
            )
            supervisor.start()
            self.assertEqual(
                supervisor.status()["reason_code"],
                "WORKER_CONTAINMENT_STARTUP_FAILED",
            )
            self.assertNotIn("private", str(supervisor.status()))

    def test_disabled_supervision_denies_unfinished_durable_workers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    """INSERT INTO worker_runtime_instances(
                    worker_id, containment_attestation_id, oci_runtime,
                    runtime_instance_id, worker_gateway_network_id, image_digest,
                    status, created_at, updated_at, execution_enabled, version)
                    VALUES ('fixture-worker', 'fixture-attestation', 'docker',
                    'fixture-runtime', 'fixture-network', ?, 'launching',
                    '2026-08-18T00:00:00Z', '2026-08-18T00:00:00Z', 0, 1)""",
                    ("sha256:" + "a" * 64,),
                )
            safety = Safety()
            supervisor = compose_worker_runtime_supervisor(
                settings=Settings(environment="test", test_mode=True, database_path=database),
                safety_control=safety,
            )
            supervisor.start()
            self.assertEqual(supervisor.status()["status"], "degraded")
            self.assertEqual(
                safety.calls,
                [("paused", "WORKER_SUPERVISION_UNAVAILABLE", "worker-runtime-supervisor")],
            )


if __name__ == "__main__":
    unittest.main()
