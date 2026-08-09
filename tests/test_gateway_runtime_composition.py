from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any
from unittest.mock import patch

from pentai_core.config import Settings
from pentai_core.gateway_runtime_composition import (
    VerifiedGatewayRuntimeLifecycle,
    compose_gateway_runtime_supervisor,
)
from pentai_core.migrate import migrate


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

        recovered = VerifiedGatewayRuntimeLifecycle(
            lifecycle=Lifecycle(), attestor=Attestor()
        ).recover()
        self.assertEqual(recovered, 1)
        self.assertEqual(events, ["recover", "attest"])

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
