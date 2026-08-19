from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from pentai_core.runtime_snapshot_collector import BoundedCommandExecutor
from pentai_core.worker_attachment_registry import DurableWorkerAttachmentRegistry
from pentai_core.worker_runtime_recovery import WorkerRuntimeRecovery

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")


class WorkerGatewayAttachmentError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WorkerAttachmentAttestor(Protocol):
    def measure(self) -> dict[str, object]: ...


class WorkerAttachmentTopologyVerifier(Protocol):
    def verify_attached(
        self,
        *,
        network_id: str,
        gateway_container_id: str,
        worker_container_id: str,
    ) -> object: ...


class WorkerAttachmentConnector(Protocol):
    def connect(self, *, network_id: str, container_id: str) -> None: ...


class OciWorkerGatewayConnector:
    """Perform one bounded attachment to an already verified internal network."""

    def __init__(
        self,
        *,
        runtime: str,
        executable: Path,
        executor: BoundedCommandExecutor,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise WorkerGatewayAttachmentError(
                "WORKER_ATTACHMENT_RUNTIME_INVALID", "worker runtime is unsupported"
            )
        if not executable.is_absolute():
            raise WorkerGatewayAttachmentError(
                "WORKER_ATTACHMENT_RUNTIME_INVALID", "worker runtime is untrusted"
            )
        self._executable = str(executable)
        self._executor = executor

    def connect(self, *, network_id: str, container_id: str) -> None:
        if not _IDENTIFIER.fullmatch(network_id) or not _CONTAINER_ID.fullmatch(container_id):
            raise WorkerGatewayAttachmentError(
                "WORKER_ATTACHMENT_IDENTITY_INVALID", "worker attachment identity is invalid"
            )
        result = self._executor.execute(
            (self._executable, "network", "connect", network_id, container_id),
            timeout_seconds=5,
            max_output_bytes=4096,
        )
        if result.returncode != 0:
            raise WorkerGatewayAttachmentError(
                "WORKER_ATTACHMENT_EFFECT_FAILED", "worker attachment effect failed"
            )


class WorkerGatewayAttachmentCoordinator:
    """Persist, attach, verify, and retain no execution authority."""

    def __init__(
        self,
        *,
        registry: DurableWorkerAttachmentRegistry,
        attestor: WorkerAttachmentAttestor,
        connector: WorkerAttachmentConnector,
        topology: WorkerAttachmentTopologyVerifier,
        recovery: WorkerRuntimeRecovery,
    ) -> None:
        self._registry = registry
        self._attestor = attestor
        self._connector = connector
        self._topology = topology
        self._recovery = recovery

    def attach(
        self,
        *,
        worker_id: str,
        expected_runtime_version: int,
        gateway_container_id: str,
    ) -> dict[str, object]:
        try:
            containment = self._attestor.measure()
            if not isinstance(containment, dict):
                raise TypeError("attestation is not an object")
            prepared = self._registry.prepare(
                worker_id=worker_id,
                expected_runtime_version=expected_runtime_version,
                containment=containment,
                gateway_container_id=gateway_container_id,
            )
        except Exception as exc:
            raise WorkerGatewayAttachmentError(
                "WORKER_ATTACHMENT_DENIED", "worker attachment authorization was denied"
            ) from exc

        version = prepared.get("version")
        container_id = prepared.get("container_id")
        network_id = prepared.get("worker_gateway_network_id")
        bound_gateway_id = prepared.get("gateway_container_id")
        if (
            type(version) is not int
            or not isinstance(container_id, str)
            or not isinstance(network_id, str)
            or not isinstance(bound_gateway_id, str)
            or prepared.get("status") != "prepared"
            or prepared.get("execution_enabled") is not False
        ):
            self._cleanup(worker_id, version)
            raise WorkerGatewayAttachmentError(
                "WORKER_ATTACHMENT_CLEANUP_FAILED", "worker attachment cleanup is incomplete"
            )

        try:
            self._connector.connect(network_id=network_id, container_id=container_id)
            self._topology.verify_attached(
                network_id=network_id,
                gateway_container_id=bound_gateway_id,
                worker_container_id=container_id,
            )
            return self._registry.mark_attached(
                worker_id=worker_id, expected_version=version
            )
        except Exception as exc:
            if not self._cleanup(worker_id, version):
                raise WorkerGatewayAttachmentError(
                    "WORKER_ATTACHMENT_CLEANUP_FAILED",
                    "worker attachment cleanup is incomplete",
                ) from exc
            raise WorkerGatewayAttachmentError(
                "WORKER_ATTACHMENT_FAILED", "worker attachment did not complete"
            ) from exc

    def _cleanup(self, worker_id: str, version: object) -> bool:
        state_failed = False
        if type(version) is int:
            try:
                self._registry.mark_failed(
                    worker_id=worker_id,
                    expected_version=version,
                    reason="attachment did not complete",
                )
            except Exception:
                state_failed = True
        else:
            state_failed = True
        recovery_failed = False
        try:
            self._recovery.terminate_worker(worker_id, "attachment did not complete")
        except Exception:
            recovery_failed = True
        return not (state_failed or recovery_failed)
