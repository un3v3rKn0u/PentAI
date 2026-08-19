from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction
from pentai_core.gateway_http_fixture import (
    GatewayFixtureAuthority,
    GatewayHttpFixtureError,
    OciGatewayHttpFixtureTransport,
)
from pentai_core.gateway_response import GatewayResponseMeasurement
from pentai_core.policy_signing import PolicyVerifier
from pentai_core.runtime_snapshot_collector import BoundedCommandExecutor, CommandResult

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")


class WorkerFixtureExecutionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DurableWorkerFixtureExecutionRegistry:
    """Bind one existing gateway claim to one exact attached worker before effect."""

    def __init__(
        self, *, database_path: Path, clock: Callable[[], datetime] | None = None
    ) -> None:
        self._database_path = database_path
        self._clock = clock or (lambda: datetime.now(UTC))

    def prepare(self, *, claim_id: str, worker_id: str) -> dict[str, object]:
        if not _IDENTIFIER.fullmatch(worker_id):
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_DENIED", "worker fixture execution is invalid"
            )
        timestamp = self._timestamp()
        try:
            with transaction(self._database_path) as connection:
                inserted = connection.execute(
                    """INSERT INTO worker_fixture_executions(
                    claim_id, worker_id, attachment_version, container_id,
                    status, prepared_at, external_execution_enabled)
                    SELECT claim.claim_id, attachment.worker_id, attachment.version,
                        attachment.container_id, 'prepared', ?, 0
                    FROM gateway_fixture_execution_claims AS claim
                    JOIN gateway_runtime_instances AS gateway
                      ON gateway.runtime_id = claim.runtime_id
                    JOIN worker_network_attachments AS attachment ON attachment.worker_id = ?
                    JOIN worker_runtime_instances AS runtime
                      ON runtime.worker_id = attachment.worker_id
                     AND runtime.container_id = attachment.container_id
                    WHERE claim.claim_id = ? AND claim.status = 'claimed'
                      AND attachment.status = 'attached'
                      AND attachment.execution_enabled = 0
                      AND attachment.gateway_container_id = gateway.container_id
                      AND gateway.status = 'running' AND gateway.execution_enabled = 0
                      AND runtime.status = 'running' AND runtime.execution_enabled = 0""",
                    (timestamp, worker_id, claim_id),
                )
                if inserted.rowcount == 1:
                    append_audit_event(
                        connection,
                        action="worker.fixture_execution_prepared",
                        subject_type="gateway_fixture_execution_claim",
                        subject_id=claim_id,
                        actor_type="service",
                        actor_id="worker-execution-broker",
                        data={
                            "claim_id": claim_id,
                            "worker_id": worker_id,
                            "external_execution_enabled": False,
                        },
                        occurred_at=timestamp,
                    )
        except sqlite3.IntegrityError as exc:
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_CONFLICT", "worker fixture execution conflicts"
            ) from exc
        if inserted.rowcount != 1:
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_DENIED", "worker fixture authority is inactive"
            )
        return self._document(claim_id)

    def finalize(
        self, *, claim_id: str, succeeded: bool, reason: str | None = None
    ) -> dict[str, object]:
        normalized_reason = reason.strip() if reason is not None else None
        if succeeded == (normalized_reason is not None) or (
            normalized_reason is not None and len(normalized_reason) > 256
        ):
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_INVALID", "worker fixture result is invalid"
            )
        with transaction(self._database_path) as connection:
            finalized_at = self._timestamp()
            updated = connection.execute(
                """UPDATE worker_fixture_executions
                SET status = ?, finalized_at = ?, failure_reason = ?
                WHERE claim_id = ? AND status = 'prepared'""",
                (
                    "completed" if succeeded else "failed",
                    finalized_at,
                    normalized_reason,
                    claim_id,
                ),
            )
            if updated.rowcount == 1:
                append_audit_event(
                    connection,
                    action="worker.fixture_execution_finalized",
                    subject_type="gateway_fixture_execution_claim",
                    subject_id=claim_id,
                    actor_type="service",
                    actor_id="worker-execution-broker",
                    data={
                        "claim_id": claim_id,
                        "outcome": "completed" if succeeded else "failed",
                        "external_execution_enabled": False,
                    },
                    occurred_at=finalized_at,
                )
        if updated.rowcount != 1:
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_RACE", "worker fixture state changed"
            )
        return self._document(claim_id)

    def unfinished(self) -> tuple[dict[str, object], ...]:
        with transaction(self._database_path) as connection:
            rows = connection.execute(
                """SELECT claim_id, worker_id, attachment_version, container_id
                FROM worker_fixture_executions WHERE status = 'prepared'
                ORDER BY prepared_at, claim_id"""
            ).fetchall()
        return tuple(
            {
                "claim_id": str(row["claim_id"]),
                "worker_id": str(row["worker_id"]),
                "attachment_version": int(row["attachment_version"]),
                "container_id": str(row["container_id"]),
                "external_execution_enabled": False,
            }
            for row in rows
        )

    def _document(self, claim_id: str) -> dict[str, object]:
        with transaction(self._database_path) as connection:
            row = connection.execute(
                "SELECT * FROM worker_fixture_executions WHERE claim_id = ?", (claim_id,)
            ).fetchone()
        if row is None:
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_NOT_FOUND", "worker fixture execution was not found"
            )
        return {
            "claim_id": str(row["claim_id"]),
            "worker_id": str(row["worker_id"]),
            "attachment_version": int(row["attachment_version"]),
            "container_id": str(row["container_id"]),
            "status": str(row["status"]),
            "external_execution_enabled": False,
        }

    def _timestamp(self) -> str:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_CLOCK", "worker fixture clock is invalid"
            )
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class WorkerFixtureExecutionRecovery:
    def __init__(
        self,
        *,
        registry: DurableWorkerFixtureExecutionRegistry,
        terminate_worker: Callable[[str, str], object],
    ) -> None:
        self._registry = registry
        self._terminate_worker = terminate_worker

    def recover_all(self) -> int:
        candidates = self._registry.unfinished()
        failures = 0
        for candidate in candidates:
            try:
                worker_id = candidate.get("worker_id")
                claim_id = candidate.get("claim_id")
                if not isinstance(worker_id, str) or not isinstance(claim_id, str):
                    raise WorkerFixtureExecutionError(
                        "WORKER_FIXTURE_RECOVERY_INVALID",
                        "worker fixture recovery candidate is invalid",
                    )
                self._terminate_worker(worker_id, "startup worker fixture recovery")
                self._registry.finalize(
                    claim_id=claim_id,
                    succeeded=False,
                    reason="startup worker fixture recovery",
                )
            except Exception:
                failures += 1
        if failures:
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_RECOVERY_INCOMPLETE",
                "worker fixture recovery is incomplete",
            )
        return len(candidates)


class OciWorkerGatewayHttpFixtureTransport(OciGatewayHttpFixtureTransport):
    """Execute the signed fixed fixture request inside one exact attached worker."""

    def __init__(
        self,
        *,
        worker_container_id: str,
        executable: Path,
        executor: BoundedCommandExecutor,
        pause_safety: Callable[[str], Any],
        claim_verifier: PolicyVerifier,
        terminate_worker: Callable[[str], object],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not _CONTAINER_ID.fullmatch(worker_container_id):
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_DENIED", "worker container identity is invalid"
            )
        super().__init__(
            executable=executable,
            executor=executor,
            pause_safety=pause_safety,
            claim_verifier=claim_verifier,
            clock=clock,
        )
        self._worker_container_id = worker_container_id
        self._terminate_worker = terminate_worker

    def _execute_transport(
        self,
        *,
        claim: dict[str, Any],
        network_id: str,
        maximum_response_bytes: int,
        deadline_milliseconds: int,
        claim_payload_arguments: tuple[str, ...],
        signature_value: str,
        container_name: str,
        timeout_seconds: float,
    ) -> CommandResult:
        del claim, network_id, container_name
        return self._executor.execute(
            (
                self._executable,
                "exec",
                self._worker_container_id,
                "/pentai-network-probe",
                "--mode=http-fixture-client",
                "--target=192.0.2.20:8080",
                "--host=example.test",
                "--path=/fixture",
                f"--maximum-response-bytes={maximum_response_bytes}",
                f"--deadline-unix-milliseconds={deadline_milliseconds}",
                *claim_payload_arguments,
                f"--claim-signature={signature_value}",
            ),
            timeout_seconds=timeout_seconds,
            max_output_bytes=4096,
        )

    def _remove_timed_out_container(self, container_name: str) -> None:
        del container_name
        try:
            self._terminate_worker(self._worker_container_id)
        except Exception as exc:
            self._fail_cleanup(exc)


class WorkerGatewayHttpFixtureExecution:
    def __init__(
        self,
        *,
        authority: GatewayFixtureAuthority,
        registry: DurableWorkerFixtureExecutionRegistry,
        transport_for: Callable[[str], OciWorkerGatewayHttpFixtureTransport],
    ) -> None:
        self._authority = authority
        self._registry = registry
        self._transport_for = transport_for

    def execute(
        self, start_id: str, *, worker_id: str, containment: dict[str, Any]
    ) -> dict[str, Any]:
        claim = self._authority.claim_gateway_fixture_execution(
            start_id, containment=containment
        )
        binding = self._registry.prepare(
            claim_id=str(claim["claim_id"]), worker_id=worker_id
        )
        try:
            measurement: GatewayResponseMeasurement = self._transport_for(
                str(binding["container_id"])
            ).execute(claim=claim, containment=containment)
            result = self._authority.finalize_gateway_request(
                start_id, measurement, execution_claim_id=str(claim["claim_id"])
            )
            self._registry.finalize(claim_id=str(claim["claim_id"]), succeeded=True)
            return result
        except Exception as exc:
            try:
                self._registry.finalize(
                    claim_id=str(claim["claim_id"]),
                    succeeded=False,
                    reason="worker fixture execution did not complete",
                )
            except Exception as persistence_exc:
                raise WorkerFixtureExecutionError(
                    "WORKER_FIXTURE_RECOVERY_REQUIRED",
                    "worker fixture recovery is required",
                ) from persistence_exc
            if isinstance(exc, GatewayHttpFixtureError):
                raise
            raise WorkerFixtureExecutionError(
                "WORKER_FIXTURE_FAILED", "worker fixture execution did not complete"
            ) from exc
