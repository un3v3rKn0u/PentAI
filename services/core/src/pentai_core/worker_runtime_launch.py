from __future__ import annotations

from typing import Protocol

from pentai_core.worker_attachment_registry import DurableWorkerAttachmentRegistry
from pentai_core.worker_runtime_recovery import WorkerRuntimeRecovery
from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry


class WorkerLaunchError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WorkerLaunchAttestor(Protocol):
    def measure(self) -> dict[str, object]: ...


class WorkerLaunchController(Protocol):
    def launch(self, worker_id: str, image_digest: str) -> str: ...

    def verify(self, worker_id: str, container_id: str, image_digest: str) -> None: ...


class DirectWorkerLaunchController(Protocol):
    def launch_attached(self, worker_id: str, image_digest: str, *, network_id: str) -> str: ...

    def verify_attached(
        self,
        worker_id: str,
        container_id: str,
        image_digest: str,
        *,
        network_name: str,
        network_id: str,
    ) -> None: ...


class DirectWorkerTopologyVerifier(Protocol):
    def verify_attached(
        self,
        *,
        network_id: str,
        gateway_container_id: str,
        worker_container_id: str,
    ) -> object: ...


class WorkerRuntimeLaunchCoordinator:
    """Create one durable, verified, non-networked worker sentinel."""

    def __init__(
        self,
        *,
        registry: DurableWorkerRuntimeRegistry,
        controller: WorkerLaunchController,
        recovery: WorkerRuntimeRecovery,
        attestor: WorkerLaunchAttestor,
    ) -> None:
        self._registry = registry
        self._controller = controller
        self._recovery = recovery
        self._attestor = attestor

    def launch(self, *, worker_id: str, image_digest: str) -> dict[str, object]:
        try:
            containment = self._attestor.measure()
            if not isinstance(containment, dict):
                raise TypeError("attestation is not an object")
            self._registry.register_launch_intent(
                worker_id=worker_id,
                containment=containment,
                image_digest=image_digest,
            )
        except Exception as exc:
            raise WorkerLaunchError(
                "WORKER_LAUNCH_DENIED", "worker launch authorization was denied"
            ) from exc

        try:
            container_id = self._controller.launch(worker_id, image_digest)
            self._controller.verify(worker_id, container_id, image_digest)
            return self._registry.mark_running(worker_id=worker_id, container_id=container_id)
        except Exception as exc:
            try:
                self._recovery.terminate_worker(worker_id, "launch did not complete")
            except Exception as cleanup_exc:
                raise WorkerLaunchError(
                    "WORKER_LAUNCH_CLEANUP_FAILED",
                    "worker launch cleanup is incomplete",
                ) from cleanup_exc
            raise WorkerLaunchError(
                "WORKER_LAUNCH_FAILED", "worker launch did not complete"
            ) from exc


class PodmanDirectWorkerGatewayLaunchCoordinator:
    """Durably authorize and verify rootless Podman's direct network launch."""

    def __init__(
        self,
        *,
        runtime_registry: DurableWorkerRuntimeRegistry,
        attachment_registry: DurableWorkerAttachmentRegistry,
        controller: DirectWorkerLaunchController,
        topology: DirectWorkerTopologyVerifier,
        recovery: WorkerRuntimeRecovery,
        attestor: WorkerLaunchAttestor,
        network_name: str,
    ) -> None:
        self._runtime_registry = runtime_registry
        self._attachment_registry = attachment_registry
        self._controller = controller
        self._topology = topology
        self._recovery = recovery
        self._attestor = attestor
        self._network_name = network_name

    def launch(
        self, *, worker_id: str, image_digest: str, gateway_container_id: str
    ) -> dict[str, object]:
        try:
            containment = self._attestor.measure()
            if not isinstance(containment, dict):
                raise TypeError("attestation is not an object")
            intent = self._runtime_registry.register_direct_attachment_intent(
                worker_id=worker_id,
                containment=containment,
                image_digest=image_digest,
                gateway_container_id=gateway_container_id,
            )
            network_id = intent.get("worker_gateway_network_id")
            if not isinstance(network_id, str):
                raise TypeError("network identity is invalid")
        except Exception as exc:
            raise WorkerLaunchError(
                "WORKER_LAUNCH_DENIED", "worker launch authorization was denied"
            ) from exc

        try:
            container_id = self._controller.launch_attached(
                worker_id, image_digest, network_id=network_id
            )
            self._controller.verify_attached(
                worker_id,
                container_id,
                image_digest,
                network_name=self._network_name,
                network_id=network_id,
            )
            self._topology.verify_attached(
                network_id=network_id,
                gateway_container_id=gateway_container_id,
                worker_container_id=container_id,
            )
            running = self._runtime_registry.mark_running(
                worker_id=worker_id, container_id=container_id
            )
            runtime_version = running.get("version")
            if type(runtime_version) is not int:
                raise TypeError("runtime version is invalid")
            return self._attachment_registry.record_direct_attached(
                worker_id=worker_id,
                expected_runtime_version=runtime_version,
                containment=containment,
                gateway_container_id=gateway_container_id,
            )
        except Exception as exc:
            try:
                self._recovery.terminate_worker(worker_id, "launch did not complete")
            except Exception as cleanup_exc:
                raise WorkerLaunchError(
                    "WORKER_LAUNCH_CLEANUP_FAILED",
                    "worker launch cleanup is incomplete",
                ) from cleanup_exc
            raise WorkerLaunchError(
                "WORKER_LAUNCH_FAILED", "worker launch did not complete"
            ) from exc
