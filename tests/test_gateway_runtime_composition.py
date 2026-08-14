from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any
from unittest.mock import patch

from pentai_core.config import Settings
from pentai_core.gateway_http_fixture import (
    GatewayFixtureCleanupRecovery,
    GatewayHttpFixtureError,
)
from pentai_core.gateway_runtime_composition import (
    VerifiedGatewayRuntimeLifecycle,
    compose_gateway_runtime_supervisor,
)
from pentai_core.migrate import migrate
from pentai_core.runtime_snapshot_collector import CommandResult


@dataclass
class FixtureSafety:
    global_calls: list[tuple[str, str, str]] = field(default_factory=list)
    assessment_calls: list[tuple[str, str, str, str]] = field(default_factory=list)

    def set_global_safety(
        self, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]:
        self.global_calls.append((status, reason, actor_id))
        return {}

    def set_assessment_safety(
        self, engagement_id: str, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]:
        self.assessment_calls.append((engagement_id, status, reason, actor_id))
        return {}


@dataclass
class FixtureAttestor:
    calls: int = 0
    checked: Event = field(default_factory=Event)

    def measure(self) -> dict[str, object]:
        self.calls += 1
        if self.calls > 1:
            self.checked.set()
        return {}


@dataclass
class FixtureController:
    def launch(self, runtime_id: str, network_id: str, image_digest: str) -> str:
        raise AssertionError("launch is not part of runtime composition")

    def verify(self, runtime_id: str, container_id: str, network_id: str) -> None:
        return

    def terminate(self, runtime_id: str, container_id: str | None) -> None:
        return


@dataclass
class FixtureExecutor:
    responses: list[CommandResult]
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        self.calls.append(argv)
        return self.responses.pop(0)


def configured_settings(database: Path, executable: Path = Path("/bin/echo")) -> Settings:
    return Settings(
        environment="test",
        database_path=database,
        test_mode=True,
        gateway_runtime_enabled=True,
        gateway_runtime="podman",
        gateway_runtime_executable=executable,
        gateway_runtime_instance_id="fixture:runtime",
        gateway_network_id="fixture-network",
        gateway_probe_image_digest="sha256:" + "a" * 64,
        gateway_instance_id="fixture-instance",
        gateway_watchdog_interval_seconds=0.1,
    )


class GatewayRuntimeCompositionTests(unittest.TestCase):
    def test_environment_requires_explicit_complete_opt_in(self) -> None:
        environment = {
            "PENTAI_ENVIRONMENT": "test",
            "PENTAI_TEST_MODE": "1",
            "PENTAI_GATEWAY_RUNTIME_ENABLED": "1",
            "PENTAI_GATEWAY_RUNTIME": "podman",
            "PENTAI_GATEWAY_RUNTIME_EXECUTABLE": "/usr/bin/podman",
            "PENTAI_GATEWAY_RUNTIME_INSTANCE_ID": "fixture:runtime",
            "PENTAI_GATEWAY_NETWORK_ID": "fixture-network",
            "PENTAI_GATEWAY_PROBE_IMAGE_DIGEST": "sha256:" + "a" * 64,
            "PENTAI_GATEWAY_INSTANCE_ID": "fixture-instance",
            "PENTAI_GATEWAY_WATCHDOG_INTERVAL_SECONDS": "1",
        }
        with patch.dict(os.environ, environment, clear=True):
            settings = Settings.from_environment()
        self.assertTrue(settings.gateway_runtime_enabled)
        self.assertEqual(settings.gateway_runtime_executable, Path("/usr/bin/podman"))

    def test_recovery_terminates_durable_runtime_before_revalidation(self) -> None:
        events: list[str] = []

        class Lifecycle:
            def recover(self) -> int:
                events.append("recover")
                return 1

            def check_all(self) -> int:
                return 0

        class Attestor:
            def measure(self) -> dict[str, object]:
                events.append("attest")
                return {}

        class Cleanup:
            def recover(self) -> int:
                events.append("cleanup")
                return 0

        recovered = VerifiedGatewayRuntimeLifecycle(
            lifecycle=Lifecycle(), attestor=Attestor(), fixture_cleanup=Cleanup()
        ).recover()
        self.assertEqual(recovered, 1)
        self.assertEqual(events, ["cleanup", "recover", "attest"])

    def test_claimed_fixture_container_is_removed_and_absence_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            claim_id = "22222222-2222-4222-8222-222222222222"
            with sqlite3.connect(database) as connection:
                connection.execute("PRAGMA foreign_keys = OFF")
                connection.execute(
                    """INSERT INTO gateway_runtime_instances(
                    runtime_id, session_id, containment_attestation_id, oci_runtime,
                    oci_runtime_instance_id, gateway_network_id, image_digest,
                    container_id, status, created_at, execution_enabled
                    ) VALUES ('runtime', 'session', 'attestation', 'podman',
                    'oci-runtime', 'fixture-network', ?, NULL, 'running',
                    '2030-01-01T00:00:00Z', 0)""",
                    ("sha256:" + "a" * 64,),
                )
                connection.execute(
                    """INSERT INTO gateway_fixture_execution_claims(
                    claim_id, start_id, runtime_id, containment_attestation_id,
                    status, claimed_at, finalized_at
                    ) VALUES (?, 'start', 'runtime', 'attestation', 'claimed',
                    '2030-01-01T00:00:00Z', NULL)""",
                    (claim_id,),
                )
            name = f"pentai-fixture-{claim_id}"
            container_id = "b" * 64
            inspected = {
                "Id": container_id,
                "Name": f"/{name}",
                "Image": "sha256:" + "a" * 64,
                "Config": {"Labels": {
                    "com.pentai.managed": "true",
                    "com.pentai.role": "gateway-http-fixture",
                    "com.pentai.execution-claim": claim_id,
                    "com.pentai.runtime-id": "runtime",
                    "com.pentai.gateway-network": "fixture-network",
                    "com.pentai.image-digest": "sha256:" + "a" * 64,
                }},
                "NetworkSettings": {"Networks": {"fixture-network": {}}},
            }
            executor = FixtureExecutor([
                CommandResult(0, f"{name}\n".encode()),
                CommandResult(0, json.dumps(inspected).encode()),
                CommandResult(0, b""),
                CommandResult(0, b""),
            ])
            pauses: list[str] = []
            recovered = GatewayFixtureCleanupRecovery(
                database_path=database,
                executable=Path("/bin/echo"),
                executor=executor,
                pause_safety=pauses.append,
            ).recover()
            self.assertEqual(recovered, 1)
            self.assertEqual(
                executor.calls[2], ("/bin/echo", "rm", "--force", container_id)
            )
            self.assertEqual(pauses, [])

            failed_pauses: list[str] = []
            ambiguous = GatewayFixtureCleanupRecovery(
                database_path=database,
                executable=Path("/bin/echo"),
                executor=FixtureExecutor([
                    CommandResult(0, f"{name}\n".encode()),
                    CommandResult(
                        0,
                        json.dumps({**inspected, "Image": "sha256:" + "c" * 64}).encode(),
                    ),
                ]),
                pause_safety=failed_pauses.append,
            )
            with self.assertRaises(GatewayHttpFixtureError) as failed:
                ambiguous.recover()
            self.assertEqual(failed.exception.code, "HTTP_FIXTURE_RECOVERY_FAILED")
            self.assertEqual(failed_pauses, ["GATEWAY_FIXTURE_RECOVERY_FAILED"])

    def test_disabled_configuration_rejects_ambiguous_runtime_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit enablement"):
            Settings(
                environment="test",
                test_mode=True,
                gateway_runtime="podman",
            ).validate()

    def test_enabled_configuration_requires_every_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "incomplete"):
            Settings(
                environment="test",
                test_mode=True,
                gateway_runtime_enabled=True,
                gateway_runtime="podman",
            ).validate()

    def test_enabled_configuration_rejects_unsafe_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            cases = (
                {"gateway_runtime": "containerd"},
                {"gateway_runtime_executable": Path("relative/podman")},
                {"gateway_runtime_instance_id": "bad identity"},
                {"gateway_probe_image_digest": "podman:latest"},
                {"gateway_watchdog_interval_seconds": 0.01},
            )
            for changed in cases:
                with self.subTest(changed=changed), self.assertRaisesRegex(
                    ValueError, "invalid"
                ):
                    values = configured_settings(database).__dict__ | changed
                    Settings(**values).validate()

    def test_composed_supervisor_attests_before_ready_and_during_watchdog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            settings = configured_settings(database)
            settings.validate()
            attestor = FixtureAttestor()
            safety = FixtureSafety()
            supervisor = compose_gateway_runtime_supervisor(
                settings=settings,
                safety_control=safety,
                attestor=attestor,
                controller=FixtureController(),
            )
            supervisor.start()
            self.assertEqual(supervisor.status()["status"], "ready")
            self.assertEqual(attestor.calls, 1)
            self.assertTrue(attestor.checked.wait(1))
            supervisor.stop()
            self.assertGreaterEqual(attestor.calls, 3)
            self.assertEqual(supervisor.status()["status"], "stopped")
            self.assertEqual(safety.global_calls, [])

    def test_untrusted_runtime_configuration_degrades_with_fixed_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            migrate(database)
            settings = configured_settings(database, Path("/missing/podman"))
            settings.validate()
            safety = FixtureSafety()
            supervisor = compose_gateway_runtime_supervisor(
                settings=settings, safety_control=safety
            )
            supervisor.start()
            self.assertEqual(
                supervisor.status()["reason_code"],
                "GATEWAY_RUNTIME_COMPOSITION_FAILED",
            )
            self.assertEqual(
                safety.global_calls,
                [
                    (
                        "paused",
                        "GATEWAY_RUNTIME_COMPOSITION_FAILED",
                        "gateway-runtime-supervisor",
                    )
                ],
            )


if __name__ == "__main__":
    unittest.main()
