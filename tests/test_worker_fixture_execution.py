from __future__ import annotations

import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pentai_core.migrate import migrate
from pentai_core.worker_fixture_execution import (
    DurableWorkerFixtureExecutionRegistry,
    OciWorkerGatewayHttpFixtureTransport,
    WorkerFixtureExecutionError,
    WorkerFixtureExecutionRecovery,
)
from test_gateway_http_fixture import (
    RUNTIME,
    VERIFIER,
    FixtureExecutor,
    claim,
    containment,
    output,
)

NOW = datetime(2026, 8, 19, 15, tzinfo=UTC)
CLAIM = "22222222-2222-4222-8222-222222222222"
WORKER = "fixture:worker"
CONTAINER = "b" * 64


def seed(database: Path, *, attachment_status: str = "attached") -> None:
    migrate(database)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """INSERT INTO gateway_fixture_execution_claims(
            claim_id, start_id, runtime_id, containment_attestation_id, status, claimed_at)
            VALUES (?, 'fixture:start', 'fixture:gateway-runtime', 'fixture:attestation',
            'claimed', '2026-08-19T15:00:00Z')""",
            (CLAIM,),
        )
        connection.execute(
            """INSERT INTO gateway_runtime_instances(
            runtime_id, session_id, containment_attestation_id, oci_runtime,
            oci_runtime_instance_id, gateway_network_id, image_digest, container_id,
            status, created_at, execution_enabled)
            VALUES ('fixture:gateway-runtime', 'fixture:session', 'fixture:attestation',
            'podman', 'fixture:runtime', 'fixture:gateway-network', ?, ?, 'running',
            '2026-08-19T15:00:00Z', 0)""",
            ("sha256:" + "a" * 64, "c" * 64),
        )
        connection.execute(
            """INSERT INTO worker_runtime_instances(
            worker_id, containment_attestation_id, oci_runtime, runtime_instance_id,
            worker_gateway_network_id, image_digest, container_id, status, created_at,
            updated_at, execution_enabled, version)
            VALUES (?, 'fixture:worker-attestation', 'podman', 'fixture:runtime',
            'fixture:network', ?, ?, 'running', '2026-08-19T15:00:00Z',
            '2026-08-19T15:00:00Z', 0, 2)""",
            (WORKER, "sha256:" + "a" * 64, CONTAINER),
        )
        connection.execute(
            """INSERT INTO worker_network_attachments(
            worker_id, attachment_attestation_id, runtime_version, container_id,
            worker_gateway_network_id, gateway_container_id, status, created_at,
            updated_at, failure_reason, execution_enabled, version)
            VALUES (?, 'fixture:attachment-attestation', 2, ?, 'fixture:network', ?, ?,
            '2026-08-19T15:00:00Z', '2026-08-19T15:00:00Z', ?, 0, 2)""",
            (
                WORKER,
                CONTAINER,
                "c" * 64,
                attachment_status,
                "fixture failure" if attachment_status == "failed" else None,
            ),
        )


def test_registry_binds_claim_to_exact_attached_worker_and_fences_result() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "pentai.db"
        seed(database)
        registry = DurableWorkerFixtureExecutionRegistry(
            database_path=database, clock=lambda: NOW
        )
        prepared = registry.prepare(claim_id=CLAIM, worker_id=WORKER)
        assert prepared == {
            "claim_id": CLAIM,
            "worker_id": WORKER,
            "attachment_version": 2,
            "container_id": CONTAINER,
            "status": "prepared",
            "external_execution_enabled": False,
        }
        assert registry.unfinished() == (
            {
                "claim_id": CLAIM,
                "worker_id": WORKER,
                "attachment_version": 2,
                "container_id": CONTAINER,
                "external_execution_enabled": False,
            },
        )
        assert registry.finalize(claim_id=CLAIM, succeeded=True)["status"] == "completed"
        assert registry.unfinished() == ()
        with pytest.raises(WorkerFixtureExecutionError):
            registry.finalize(claim_id=CLAIM, succeeded=True)


def test_registry_denies_nonattached_worker_and_replay() -> None:
    for status in ("prepared", "failed"):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "pentai.db"
            seed(database, attachment_status=status)
            registry = DurableWorkerFixtureExecutionRegistry(
                database_path=database, clock=lambda: NOW
            )
            with pytest.raises(WorkerFixtureExecutionError) as raised:
                registry.prepare(claim_id=CLAIM, worker_id=WORKER)
            assert raised.value.code == "WORKER_FIXTURE_DENIED"


def test_worker_transport_executes_signed_claim_only_inside_exact_worker() -> None:
    now = datetime.now(UTC)
    executor = FixtureExecutor(output())
    terminated: list[str] = []
    transport = OciWorkerGatewayHttpFixtureTransport(
        worker_container_id=CONTAINER,
        executable=RUNTIME,
        executor=executor,
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
        terminate_worker=terminated.append,
        clock=lambda: now,
    )
    measurement = transport.execute(
        claim=claim(deadline_at=(now + timedelta(seconds=2)).isoformat()),
        containment=containment(),
    )
    assert measurement.outcome == "completed"
    command, _, output_limit = executor.calls[0]
    assert command[:4] == (str(RUNTIME), "exec", CONTAINER, "/pentai-network-probe")
    assert "run" not in command
    assert "--target=192.0.2.20:8080" in command
    assert any(value.startswith("--claim-part=") for value in command)
    assert any(value.startswith("--claim-signature=") for value in command)
    assert output_limit == 4096
    assert terminated == []


def test_startup_recovery_terminates_exact_worker_before_failure_receipt() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "pentai.db"
        seed(database)
        registry = DurableWorkerFixtureExecutionRegistry(
            database_path=database, clock=lambda: NOW
        )
        registry.prepare(claim_id=CLAIM, worker_id=WORKER)
        terminations: list[tuple[str, str]] = []
        recovery = WorkerFixtureExecutionRecovery(
            registry=registry,
            terminate_worker=lambda worker, reason: terminations.append((worker, reason)),
        )
        assert recovery.recover_all() == 1
        assert terminations == [(WORKER, "startup worker fixture recovery")]
        assert registry.unfinished() == ()
