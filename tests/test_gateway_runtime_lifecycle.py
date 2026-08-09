from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from pentai_core.authorization import AuthorizationService
from pentai_core.gateway_runtime_lifecycle import (
    AuthorizationSafetyHandler,
    GatewayRuntimeError,
    GatewayRuntimeLifecycle,
    GatewayRuntimeWatchdog,
    OciGatewayFixtureController,
)
from pentai_core.migrate import migrate
from pentai_core.runtime_snapshot_collector import CommandResult

RUNTIME_IDENTITY = "fixture-runtime"
NETWORK_ID = "fixture-network"
IMAGE = "sha256:" + "a" * 64
CONTAINER = "b" * 64
OCI = Path("/usr/bin/podman")


def timestamp(offset: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")


def containment(**updates: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "1.0.0",
        "attestation_id": str(uuid4()),
        "runtime": "podman",
        "runtime_instance_id": RUNTIME_IDENTITY,
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
        "gateway_network_id": NETWORK_ID,
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": timestamp(-1),
        "expires_at": timestamp(29),
    }
    document.update(updates)
    return document


def session(session_id: str) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "session_id": session_id,
        "reservation_id": str(uuid4()),
        "grant_id": str(uuid4()),
        "attestation_id": str(uuid4()),
        "destination_authorization_id": str(uuid4()),
        "status": "prepared",
        "request_count": 1,
        "response_bytes_limit": 4096,
        "prepared_at": timestamp(-2),
        "execution_enabled": False,
    }


@dataclass
class FixtureController:
    fail_launch: bool = False
    fail_verify: bool = False
    fail_terminate: bool = False
    calls: list[tuple[object, ...]] = field(default_factory=list)

    def launch(self, runtime_id: str, network_id: str, image_digest: str) -> str:
        self.calls.append(("launch", runtime_id, network_id, image_digest))
        if self.fail_launch:
            raise RuntimeError("synthetic launch failure")
        return CONTAINER

    def verify(self, runtime_id: str, container_id: str, network_id: str) -> None:
        self.calls.append(("verify", runtime_id, container_id, network_id))
        if self.fail_verify:
            raise RuntimeError("synthetic drift")

    def terminate(self, runtime_id: str, container_id: str | None) -> None:
        self.calls.append(("terminate", runtime_id, container_id))
        if self.fail_terminate:
            raise RuntimeError("synthetic termination failure")


@dataclass
class FixtureMonitor:
    result: dict[str, object]

    def measure(self) -> dict[str, object]:
        return self.result


@dataclass
class FixtureSafety:
    calls: list[tuple[str, str]] = field(default_factory=list)

    def halt(self, session_id: str, reason: str) -> None:
        self.calls.append((session_id, reason))


@dataclass
class FixtureAssessmentSafety:
    calls: list[tuple[str, str, str, str]] = field(default_factory=list)

    def set_assessment_safety(
        self, engagement_id: str, *, status: str, reason: str, actor_id: str
    ) -> dict[str, object]:
        self.calls.append((engagement_id, status, reason, actor_id))
        return {"status": status}


@dataclass
class FixtureExecutor:
    responses: list[CommandResult]
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        self.calls.append(argv)
        return self.responses.pop(0)


class GatewayRuntimeLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.session_id = str(uuid4())
        self.session = session(self.session_id)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                """INSERT INTO gateway_sessions(session_id, reservation_id, grant_id,
                attestation_id, destination_authorization_id, status, prepared_at,
                execution_enabled) VALUES (?, ?, ?, ?, ?, 'prepared', ?, 0)""",
                (
                    self.session_id,
                    self.session["reservation_id"],
                    self.session["grant_id"],
                    self.session["attestation_id"],
                    self.session["destination_authorization_id"],
                    self.session["prepared_at"],
                ),
            )
        self.controller = FixtureController()
        self.safety = FixtureSafety()
        self.monitor = FixtureMonitor(containment())
        self.lifecycle = GatewayRuntimeLifecycle(
            database_path=self.database,
            controller=self.controller,
            monitor=self.monitor,
            safety=self.safety,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_launch_check_and_terminate_preserve_nonexecuting_history(self) -> None:
        launched = self.lifecycle.launch(
            session=self.session, containment=self.monitor.result, image_digest=IMAGE
        )
        self.assertEqual(launched["status"], "running")
        self.assertFalse(launched["execution_enabled"])
        checked = self.lifecycle.check(str(launched["runtime_id"]))
        self.assertEqual(checked["status"], "running")
        self.lifecycle.terminate(str(launched["runtime_id"]), reason="operator stop")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            row = connection.execute(
                """SELECT status, termination_reason, execution_enabled
                FROM gateway_runtime_instances"""
            ).fetchone()
            actions = [
                audit[0]
                for audit in connection.execute(
                    "SELECT action FROM audit_events ORDER BY sequence"
                )
            ]
        self.assertEqual(row, ("terminated", "operator stop", 0))
        self.assertEqual(
            actions,
            [
                "gateway.runtime_launching",
                "gateway.runtime_started",
                "gateway.runtime_finalized",
            ],
        )
        self.assertTrue(AuthorizationService(self.database).verify_audit_chain()["valid"])
        self.assertEqual(self.safety.calls, [(self.session_id, "operator stop")])

    def test_replay_stale_containment_and_inactive_session_deny(self) -> None:
        self.lifecycle.launch(
            session=self.session, containment=self.monitor.result, image_digest=IMAGE
        )
        with self.assertRaises(GatewayRuntimeError) as replayed:
            self.lifecycle.launch(
                session=self.session, containment=containment(), image_digest=IMAGE
            )
        self.assertEqual(replayed.exception.code, "GATEWAY_RUNTIME_REPLAYED")
        stale = containment(expires_at=timestamp(-1))
        other = session(str(uuid4()))
        with self.assertRaises(GatewayRuntimeError):
            self.lifecycle.launch(session=other, containment=stale, image_digest=IMAGE)

    def test_monitor_drift_terminates_and_halts_session(self) -> None:
        launched = self.lifecycle.launch(
            session=self.session, containment=self.monitor.result, image_digest=IMAGE
        )
        self.monitor.result = containment(gateway_network_id="changed-network")
        with self.assertRaises(GatewayRuntimeError) as raised:
            self.lifecycle.check(str(launched["runtime_id"]))
        self.assertEqual(raised.exception.code, "GATEWAY_MONITOR_FAILED")
        self.assertEqual(self.controller.calls[-1][0], "terminate")
        self.assertEqual(self.safety.calls[-1][0], self.session_id)

    def test_startup_recovery_terminates_running_instances(self) -> None:
        self.lifecycle.launch(
            session=self.session, containment=self.monitor.result, image_digest=IMAGE
        )
        self.assertEqual(self.lifecycle.recover(), 1)
        self.assertEqual(self.lifecycle.recover(), 0)
        self.assertEqual(self.controller.calls[-1][0], "terminate")

    def test_watchdog_checks_all_running_instances(self) -> None:
        launched = self.lifecycle.launch(
            session=self.session, containment=self.monitor.result, image_digest=IMAGE
        )
        from threading import Event

        stop = Event()
        stop.set()
        GatewayRuntimeWatchdog(self.lifecycle, interval_seconds=0.1).run(stop)
        self.assertEqual(self.lifecycle.check_all(), 1)
        self.assertEqual(self.controller.calls[-1][1], launched["runtime_id"])

    def test_termination_failure_is_durable_and_still_halts(self) -> None:
        launched = self.lifecycle.launch(
            session=self.session, containment=self.monitor.result, image_digest=IMAGE
        )
        self.controller.fail_terminate = True
        with self.assertRaises(GatewayRuntimeError):
            self.lifecycle.terminate(str(launched["runtime_id"]), reason="drift")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            status = connection.execute(
                "SELECT status FROM gateway_runtime_instances"
            ).fetchone()[0]
        self.assertEqual(status, "failed")
        self.assertEqual(self.safety.calls[-1], (self.session_id, "drift"))

    def test_failed_launch_cleanup_is_retried_during_recovery(self) -> None:
        self.controller.fail_verify = True
        self.controller.fail_terminate = True
        with self.assertRaises(GatewayRuntimeError) as raised:
            self.lifecycle.launch(
                session=self.session, containment=self.monitor.result, image_digest=IMAGE
            )
        self.assertEqual(raised.exception.code, "GATEWAY_TERMINATION_FAILED")
        self.controller.fail_terminate = False
        self.assertEqual(self.lifecycle.recover(), 1)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            status = connection.execute(
                "SELECT status FROM gateway_runtime_instances"
            ).fetchone()[0]
        self.assertEqual(status, "terminated")

    def test_fixed_oci_commands_are_locked_down(self) -> None:
        inspected = {
            "Id": CONTAINER,
            "State": {"Running": True},
            "Config": {
                "User": "65532:65532",
                "Labels": {
                    "com.pentai.managed": "true",
                    "com.pentai.runtime-role": "gateway-fixture",
                    "com.pentai.runtime-id": "runtime-1",
                }
            },
            "HostConfig": {
                "NetworkMode": "fixture-name",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "PidMode": "",
                "IpcMode": "private",
                "PidsLimit": 16,
                "Memory": 33_554_432,
                "NanoCpus": 250_000_000,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Binds": None,
            },
            "NetworkSettings": {"Networks": {"fixture-name": {"NetworkID": NETWORK_ID}}},
        }
        executor = FixtureExecutor(
            [CommandResult(0, CONTAINER.encode()), CommandResult(0, json.dumps(inspected).encode())]
        )
        controller = OciGatewayFixtureController(
            runtime="docker", executable=OCI, executor=executor
        )
        container_id = controller.launch("runtime-1", NETWORK_ID, IMAGE)
        controller.verify("runtime-1", container_id, NETWORK_ID)
        launch = executor.calls[0]
        for required in (
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pid=private",
            "--ipc=private",
            "--pids-limit=16",
            "--memory=32m",
            "--cpus=0.25",
            "--mode=sentinel",
        ):
            self.assertIn(required, launch)
        self.assertNotIn("--privileged", launch)

    def test_oci_drift_diagnostics_name_controls_without_values(self) -> None:
        inspected = {
            "Id": CONTAINER,
            "State": {"Running": True},
            "Config": {"User": "0", "Labels": {}},
            "HostConfig": {},
            "NetworkSettings": {"Networks": {}},
        }
        controller = OciGatewayFixtureController(
            runtime="docker",
            executable=OCI,
            executor=FixtureExecutor([CommandResult(0, json.dumps(inspected).encode())]),
        )
        with self.assertRaises(GatewayRuntimeError) as raised:
            controller.verify("runtime-1", CONTAINER, NETWORK_ID)
        self.assertIn("network_identity", str(raised.exception))
        self.assertIn("non_root_user", str(raised.exception))
        self.assertNotIn(NETWORK_ID, str(raised.exception))

    def test_podman_verification_uses_effective_caps_and_exact_network_name(self) -> None:
        inspected = {
            "Id": CONTAINER,
            "State": {"Running": True},
            "EffectiveCaps": [],
            "Config": {
                "User": "65532:65532",
                "Labels": {
                    "com.pentai.managed": "true",
                    "com.pentai.runtime-role": "gateway-fixture",
                    "com.pentai.runtime-id": "runtime-1",
                },
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "PidMode": "private",
                "IpcMode": "private",
                "PidsLimit": 16,
                "Memory": 33_554_432,
                "CpuQuota": 25_000,
                "CpuPeriod": 100_000,
                "CapDrop": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"],
                "SecurityOpt": ["no-new-privileges"],
                "Binds": [],
            },
            "NetworkSettings": {
                "Networks": {"fixture-name": {"NetworkID": ""}}
            },
        }
        executor = FixtureExecutor(
            [
                CommandResult(0, json.dumps(inspected).encode()),
                CommandResult(
                    0,
                    json.dumps({"id": NETWORK_ID, "name": "fixture-name"}).encode(),
                ),
                CommandResult(0, CONTAINER.encode()),
            ]
        )
        controller = OciGatewayFixtureController(
            runtime="podman", executable=OCI, executor=executor
        )
        controller.verify("runtime-1", CONTAINER, NETWORK_ID)
        controller.terminate("runtime-1", CONTAINER)
        self.assertEqual(
            executor.calls[-1],
            (str(OCI), "rm", "--force", "--time=0", CONTAINER),
        )

    def test_authorization_safety_adapter_pauses_owning_assessment(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                """INSERT INTO budget_reservations(
                reservation_id, engagement_id, policy_bundle_id, grant_id,
                destination_authorization_id, request_count, response_bytes_limit,
                status, reserved_at
                ) VALUES (?, 'engagement-1', 'policy-1', ?, ?, 1, 1, 'reserved', ?)""",
                (
                    self.session["reservation_id"],
                    self.session["grant_id"],
                    self.session["destination_authorization_id"],
                    self.session["prepared_at"],
                ),
            )
        safety = FixtureAssessmentSafety()
        AuthorizationSafetyHandler(
            database_path=self.database, safety_control=safety
        ).halt(self.session_id, "runtime drift")
        self.assertEqual(
            safety.calls,
            [
                (
                    "engagement-1",
                    "paused",
                    "runtime drift",
                    "gateway-runtime-monitor",
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
