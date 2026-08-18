from __future__ import annotations

from typing import Protocol

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
            return self._registry.mark_running(
                worker_id=worker_id, container_id=container_id
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
