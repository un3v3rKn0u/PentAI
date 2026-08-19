from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pentai_core.database import transaction
from pentai_core.worker_containment import validate_worker_containment_attestation

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")


class WorkerAttachmentRegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DurableWorkerAttachmentRegistry:
    """Persist attachment authority and outcomes without enabling execution."""

    def __init__(
        self,
        *,
        database_path: Path,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database_path = database_path
        self._clock = clock or (lambda: datetime.now(UTC))

    def prepare(
        self,
        *,
        worker_id: str,
        expected_runtime_version: int,
        containment: dict[str, Any],
        gateway_container_id: str,
    ) -> dict[str, object]:
        try:
            validate_worker_containment_attestation(containment, now=self._clock())
        except Exception as exc:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_DENIED", "worker attachment evidence is invalid"
            ) from exc
        runtime_id = containment.get("runtime_instance_id")
        network_id = containment.get("worker_gateway_network_id")
        if (
            not _IDENTIFIER.fullmatch(worker_id)
            or type(expected_runtime_version) is not int
            or expected_runtime_version < 1
            or not isinstance(runtime_id, str)
            or not _IDENTIFIER.fullmatch(runtime_id)
            or not isinstance(network_id, str)
            or not _IDENTIFIER.fullmatch(network_id)
            or not _CONTAINER_ID.fullmatch(gateway_container_id)
            or containment.get("network_role") != "worker_gateway"
        ):
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_DENIED", "worker attachment request is invalid"
            )
        timestamp = self._timestamp()
        try:
            with transaction(self._database_path) as connection:
                inserted = connection.execute(
                    """INSERT INTO worker_network_attachments(
                    worker_id, attachment_attestation_id, runtime_version, container_id,
                    worker_gateway_network_id, gateway_container_id, status, created_at,
                    updated_at, execution_enabled, version)
                    SELECT worker_id, ?, version, container_id, worker_gateway_network_id,
                        ?, 'prepared', ?, ?, 0, 1
                    FROM worker_runtime_instances
                    WHERE worker_id = ? AND status = 'running' AND version = ?
                      AND container_id IS NOT NULL AND oci_runtime = ?
                      AND runtime_instance_id = ? AND worker_gateway_network_id = ?""",
                    (
                        containment["attestation_id"],
                        gateway_container_id,
                        timestamp,
                        timestamp,
                        worker_id,
                        expected_runtime_version,
                        containment["runtime"],
                        runtime_id,
                        network_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_CONFLICT", "worker attachment conflicts"
            ) from exc
        if inserted.rowcount != 1:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_STALE", "worker runtime identity changed"
            )
        return self._document(worker_id)

    def mark_attached(
        self, *, worker_id: str, expected_version: int
    ) -> dict[str, object]:
        return self._transition(
            worker_id=worker_id,
            expected_version=expected_version,
            status="attached",
            failure_reason=None,
        )

    def mark_failed(
        self, *, worker_id: str, expected_version: int, reason: str
    ) -> dict[str, object]:
        normalized_reason = reason.strip()
        if not normalized_reason or len(normalized_reason) > 256:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_INVALID", "worker attachment failure is invalid"
            )
        return self._transition(
            worker_id=worker_id,
            expected_version=expected_version,
            status="failed",
            failure_reason=normalized_reason,
        )

    def recovery_candidates(self) -> tuple[dict[str, object], ...]:
        with transaction(self._database_path) as connection:
            rows = connection.execute(
                """SELECT worker_id, container_id, worker_gateway_network_id,
                    gateway_container_id, status, version
                FROM worker_network_attachments AS attachment
                WHERE status IN ('prepared', 'attached', 'failed')
                  AND NOT EXISTS (
                    SELECT 1 FROM worker_attachment_recoveries AS recovery
                    WHERE recovery.worker_id = attachment.worker_id
                  )
                ORDER BY worker_id"""
            ).fetchall()
        return tuple(
            {
                "worker_id": str(row["worker_id"]),
                "container_id": str(row["container_id"]),
                "worker_gateway_network_id": str(row["worker_gateway_network_id"]),
                "gateway_container_id": str(row["gateway_container_id"]),
                "status": str(row["status"]),
                "version": int(row["version"]),
                "execution_enabled": False,
            }
            for row in rows
        )

    def resolve_recovery(
        self, *, worker_id: str, expected_version: int
    ) -> dict[str, object]:
        if (
            not _IDENTIFIER.fullmatch(worker_id)
            or type(expected_version) is not int
            or expected_version < 1
        ):
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_RECOVERY_INVALID", "worker attachment recovery is invalid"
            )
        timestamp = self._timestamp()
        try:
            with transaction(self._database_path) as connection:
                inserted = connection.execute(
                    """INSERT INTO worker_attachment_recoveries(
                    worker_id, attachment_version, recovered_at, outcome, execution_enabled)
                    SELECT attachment.worker_id, attachment.version, ?, 'worker_terminated', 0
                    FROM worker_network_attachments AS attachment
                    JOIN worker_runtime_instances AS runtime
                      ON runtime.worker_id = attachment.worker_id
                     AND runtime.container_id = attachment.container_id
                    WHERE attachment.worker_id = ? AND attachment.version = ?
                      AND attachment.status = 'failed' AND runtime.status = 'terminated'""",
                    (timestamp, worker_id, expected_version),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_RECOVERY_CONFLICT", "worker attachment recovery conflicts"
            ) from exc
        if inserted.rowcount != 1:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_RECOVERY_PENDING",
                "worker attachment recovery is incomplete",
            )
        return {
            "worker_id": worker_id,
            "attachment_version": expected_version,
            "outcome": "worker_terminated",
            "execution_enabled": False,
        }

    def _transition(
        self,
        *,
        worker_id: str,
        expected_version: int,
        status: str,
        failure_reason: str | None,
    ) -> dict[str, object]:
        if (
            not _IDENTIFIER.fullmatch(worker_id)
            or type(expected_version) is not int
            or expected_version < 1
        ):
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_INVALID", "worker attachment transition is invalid"
            )
        timestamp = self._timestamp()
        with transaction(self._database_path) as connection:
            updated = connection.execute(
                """UPDATE worker_network_attachments
                SET status = ?, failure_reason = ?, updated_at = ?, version = version + 1
                WHERE worker_id = ? AND version = ? AND (
                    (? = 'attached' AND status = 'prepared')
                    OR (? = 'failed' AND status IN ('prepared', 'attached'))
                )""",
                (
                    status,
                    failure_reason,
                    timestamp,
                    worker_id,
                    expected_version,
                    status,
                    status,
                ),
            )
        if updated.rowcount != 1:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_RACE", "worker attachment state changed"
            )
        return self._document(worker_id)

    def _document(self, worker_id: str) -> dict[str, object]:
        with transaction(self._database_path) as connection:
            row = connection.execute(
                "SELECT * FROM worker_network_attachments WHERE worker_id = ?", (worker_id,)
            ).fetchone()
        if row is None:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_NOT_FOUND", "worker attachment was not found"
            )
        return {
            "worker_id": str(row["worker_id"]),
            "attachment_attestation_id": str(row["attachment_attestation_id"]),
            "runtime_version": int(row["runtime_version"]),
            "container_id": str(row["container_id"]),
            "worker_gateway_network_id": str(row["worker_gateway_network_id"]),
            "gateway_container_id": str(row["gateway_container_id"]),
            "status": str(row["status"]),
            "version": int(row["version"]),
            "execution_enabled": False,
        }

    def _timestamp(self) -> str:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise WorkerAttachmentRegistryError(
                "WORKER_ATTACHMENT_CLOCK_INVALID", "worker attachment clock is invalid"
            )
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
