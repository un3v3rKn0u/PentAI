from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry


class WorkerTerminationController(Protocol):
    def discover_owned(self, worker_id: str) -> str | None: ...

    def verify_ownership(self, worker_id: str, container_id: str) -> None: ...

    def terminate(self, container_id: str) -> None: ...


class WorkerRecoveryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WorkerRuntimeRecovery:
    """Terminate every durable unfinished worker before startup may continue."""

    def __init__(
        self,
        *,
        registry: DurableWorkerRuntimeRegistry,
        controller_for: Callable[[str], WorkerTerminationController],
    ) -> None:
        self._registry = registry
        self._controller_for = controller_for

    def recover_all(self) -> int:
        return self.terminate_all("startup recovery")

    def terminate_all(self, reason: str) -> int:
        candidates = self._registry.recovery_candidates()
        failures = 0
        for candidate in candidates:
            try:
                self._recover(candidate, reason)
            except Exception:
                failures += 1
        if failures:
            raise WorkerRecoveryError(
                "WORKER_RECOVERY_INCOMPLETE", "worker startup recovery is incomplete"
            )
        return len(candidates)

    def _recover(self, candidate: dict[str, object], reason: str) -> None:
        worker_id = candidate.get("worker_id")
        runtime = candidate.get("oci_runtime")
        status = candidate.get("status")
        version = candidate.get("version")
        container_id = candidate.get("container_id")
        if (
            not isinstance(worker_id, str)
            or not isinstance(runtime, str)
            or status
            not in {"launching", "running", "termination_requested", "failed"}
            or type(version) is not int
            or version < 1
            or candidate.get("execution_enabled") is not False
        ):
            raise WorkerRecoveryError("WORKER_RECOVERY_INVALID", "worker recovery is invalid")
        controller = self._controller_for(runtime)
        if container_id is None:
            container_id = controller.discover_owned(worker_id)
        elif not isinstance(container_id, str):
            raise WorkerRecoveryError("WORKER_RECOVERY_INVALID", "worker recovery is invalid")
        if status == "termination_requested":
            request_version = version
        else:
            requested = self._registry.request_termination(
                worker_id=worker_id,
                expected_version=version,
                reason=reason,
                discovered_container_id=(
                    container_id if candidate["container_id"] is None else None
                ),
            )
            updated_version = requested.get("version")
            if type(updated_version) is not int:
                raise WorkerRecoveryError(
                    "WORKER_RECOVERY_INVALID", "worker recovery is invalid"
                )
            request_version = updated_version
        try:
            if container_id is not None:
                controller.verify_ownership(worker_id, container_id)
                controller.terminate(container_id)
        except Exception:
            self._registry.finalize_termination(
                worker_id=worker_id,
                expected_version=request_version,
                succeeded=False,
            )
            raise
        self._registry.finalize_termination(
            worker_id=worker_id,
            expected_version=request_version,
            succeeded=True,
        )
