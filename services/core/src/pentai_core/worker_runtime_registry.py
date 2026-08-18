from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pentai_core.database import transaction
from pentai_core.worker_containment import validate_worker_containment_attestation
from pentai_core.worker_containment_supervisor import WorkerContainmentBinding

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class WorkerRegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DurableWorkerRuntimeRegistry:
    """Persist non-executing worker identities for monitoring and later recovery."""

    def __init__(
        self,
        *,
        database_path: Path,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database_path = database_path
        self._clock = clock or (lambda: datetime.now(UTC))

    def register_launch_intent(
        self,
        *,
        worker_id: str,
        containment: dict[str, Any],
        image_digest: str,
    ) -> dict[str, object]:
        try:
            validate_worker_containment_attestation(containment, now=self._clock())
        except Exception as exc:
            raise WorkerRegistryError(
                "WORKER_REGISTRATION_DENIED", "worker containment evidence is invalid"
            ) from exc
        runtime_id = containment.get("runtime_instance_id")
        network_id = containment.get("worker_gateway_network_id")
        if (
            not _IDENTIFIER.fullmatch(worker_id)
            or not isinstance(runtime_id, str)
            or not _IDENTIFIER.fullmatch(runtime_id)
            or not isinstance(network_id, str)
            or not _IDENTIFIER.fullmatch(network_id)
            or not _DIGEST.fullmatch(image_digest)
            or containment.get("network_role") != "worker_gateway"
        ):
            raise WorkerRegistryError(
                "WORKER_REGISTRATION_DENIED", "worker registration is invalid"
            )
        created_at = self._timestamp()
        try:
            with transaction(self._database_path) as connection:
                connection.execute(
                    """INSERT INTO worker_runtime_instances(
                    worker_id, containment_attestation_id, oci_runtime,
                    runtime_instance_id, worker_gateway_network_id, image_digest,
                    status, created_at, updated_at, execution_enabled, version)
                    VALUES (?, ?, ?, ?, ?, ?, 'launching', ?, ?, 0, 1)""",
                    (
                        worker_id,
                        containment["attestation_id"],
                        containment["runtime"],
                        runtime_id,
                        network_id,
                        image_digest,
                        created_at,
                        created_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkerRegistryError(
                "WORKER_REGISTRATION_CONFLICT", "worker registration conflicts"
            ) from exc
        return self._document(worker_id)

    def mark_running(self, *, worker_id: str, container_id: str) -> dict[str, object]:
        if not _IDENTIFIER.fullmatch(worker_id) or not _CONTAINER_ID.fullmatch(container_id):
            raise WorkerRegistryError("WORKER_RUNTIME_INVALID", "worker identity is invalid")
        updated_at = self._timestamp()
        try:
            with transaction(self._database_path) as connection:
                updated = connection.execute(
                    """UPDATE worker_runtime_instances
                    SET container_id = ?, status = 'running', updated_at = ?, version = version + 1
                    WHERE worker_id = ? AND status = 'launching' AND container_id IS NULL""",
                    (container_id, updated_at, worker_id),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkerRegistryError(
                "WORKER_RUNTIME_CONFLICT", "worker runtime identity conflicts"
            ) from exc
        if updated.rowcount != 1:
            raise WorkerRegistryError("WORKER_RUNTIME_INACTIVE", "worker runtime is inactive")
        return self._document(worker_id)

    def bindings(self) -> tuple[WorkerContainmentBinding, ...]:
        with transaction(self._database_path) as connection:
            rows = connection.execute(
                """SELECT worker_id, runtime_instance_id, worker_gateway_network_id
                FROM worker_runtime_instances WHERE status = 'running'
                ORDER BY worker_id"""
            ).fetchall()
        return tuple(
            WorkerContainmentBinding(
                str(row["worker_id"]),
                str(row["runtime_instance_id"]),
                str(row["worker_gateway_network_id"]),
            )
            for row in rows
        )

    def recovery_candidates(self) -> tuple[dict[str, object], ...]:
        with transaction(self._database_path) as connection:
            rows = connection.execute(
                """SELECT worker_id, oci_runtime, container_id, status, version
                FROM worker_runtime_instances
                WHERE status IN ('launching', 'running', 'termination_requested', 'failed')
                ORDER BY worker_id"""
            ).fetchall()
        return tuple(
            {
                "worker_id": str(row["worker_id"]),
                "oci_runtime": str(row["oci_runtime"]),
                "container_id": row["container_id"],
                "status": str(row["status"]),
                "version": int(row["version"]),
                "execution_enabled": False,
            }
            for row in rows
        )

    def request_termination(
        self,
        *,
        worker_id: str,
        expected_version: int,
        reason: str,
        discovered_container_id: str | None = None,
    ) -> dict[str, object]:
        normalized_reason = reason.strip()
        if (
            not _IDENTIFIER.fullmatch(worker_id)
            or expected_version < 1
            or not normalized_reason
            or len(normalized_reason) > 256
            or (
                discovered_container_id is not None
                and not _CONTAINER_ID.fullmatch(discovered_container_id)
            )
        ):
            raise WorkerRegistryError(
                "WORKER_TERMINATION_INVALID", "worker termination request is invalid"
            )
        updated_at = self._timestamp()
        with transaction(self._database_path) as connection:
            if discovered_container_id is None:
                updated = connection.execute(
                    """UPDATE worker_runtime_instances
                    SET status = 'termination_requested', termination_reason = ?,
                        updated_at = ?, version = version + 1
                    WHERE worker_id = ? AND version = ?
                      AND status IN ('launching', 'running', 'failed')""",
                    (normalized_reason, updated_at, worker_id, expected_version),
                )
            else:
                updated = connection.execute(
                    """UPDATE worker_runtime_instances
                    SET container_id = ?, status = 'termination_requested',
                        termination_reason = ?, updated_at = ?, version = version + 1
                    WHERE worker_id = ? AND version = ? AND status = 'launching'
                      AND container_id IS NULL""",
                    (
                        discovered_container_id,
                        normalized_reason,
                        updated_at,
                        worker_id,
                        expected_version,
                    ),
                )
        if updated.rowcount != 1:
            raise WorkerRegistryError("WORKER_RUNTIME_RACE", "worker runtime state changed")
        return self._document(worker_id)

    def finalize_termination(
        self,
        *,
        worker_id: str,
        expected_version: int,
        succeeded: bool,
    ) -> dict[str, object]:
        if not _IDENTIFIER.fullmatch(worker_id) or expected_version < 1:
            raise WorkerRegistryError(
                "WORKER_TERMINATION_INVALID", "worker termination result is invalid"
            )
        updated_at = self._timestamp()
        status = "terminated" if succeeded else "failed"
        with transaction(self._database_path) as connection:
            updated = connection.execute(
                """UPDATE worker_runtime_instances
                SET status = ?, updated_at = ?, version = version + 1
                WHERE worker_id = ? AND version = ? AND status = 'termination_requested'""",
                (status, updated_at, worker_id, expected_version),
            )
        if updated.rowcount != 1:
            raise WorkerRegistryError("WORKER_RUNTIME_RACE", "worker runtime state changed")
        return self._document(worker_id)

    def _document(self, worker_id: str) -> dict[str, object]:
        with transaction(self._database_path) as connection:
            row = connection.execute(
                "SELECT * FROM worker_runtime_instances WHERE worker_id = ?", (worker_id,)
            ).fetchone()
        if row is None:
            raise WorkerRegistryError("WORKER_RUNTIME_NOT_FOUND", "worker runtime was not found")
        return {
            "worker_id": str(row["worker_id"]),
            "containment_attestation_id": str(row["containment_attestation_id"]),
            "runtime_instance_id": str(row["runtime_instance_id"]),
            "worker_gateway_network_id": str(row["worker_gateway_network_id"]),
            "image_digest": str(row["image_digest"]),
            "container_id": row["container_id"],
            "status": str(row["status"]),
            "version": int(row["version"]),
            "execution_enabled": False,
        }

    def _timestamp(self) -> str:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise WorkerRegistryError("WORKER_CLOCK_INVALID", "worker clock is invalid")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
