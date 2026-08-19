from __future__ import annotations

from pentai_core.worker_attachment_registry import (
    DurableWorkerAttachmentRegistry,
    WorkerAttachmentRegistryError,
)
from pentai_core.worker_runtime_recovery import WorkerRuntimeRecovery


class WorkerAttachmentRecoveryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class WorkerAttachmentRecovery:
    """Resolve every unfinished attachment only after exact-worker termination."""

    def __init__(
        self,
        *,
        registry: DurableWorkerAttachmentRegistry,
        runtime_recovery: WorkerRuntimeRecovery,
    ) -> None:
        self._registry = registry
        self._runtime_recovery = runtime_recovery

    def recover_all(self) -> int:
        candidates = self._registry.recovery_candidates()
        failures = 0
        for candidate in candidates:
            try:
                self._recover(candidate)
            except Exception:
                failures += 1
        if failures:
            raise WorkerAttachmentRecoveryError(
                "WORKER_ATTACHMENT_RECOVERY_INCOMPLETE",
                "worker attachment recovery is incomplete",
            )
        return len(candidates)

    def _recover(self, candidate: dict[str, object]) -> None:
        worker_id = candidate.get("worker_id")
        status = candidate.get("status")
        version = candidate.get("version")
        if (
            not isinstance(worker_id, str)
            or status not in {"prepared", "attached", "failed"}
            or type(version) is not int
            or version < 1
            or candidate.get("execution_enabled") is not False
        ):
            raise WorkerAttachmentRecoveryError(
                "WORKER_ATTACHMENT_RECOVERY_INVALID",
                "worker attachment recovery candidate is invalid",
            )
        if status != "failed":
            failed = self._registry.mark_failed(
                worker_id=worker_id,
                expected_version=version,
                reason="startup attachment recovery",
            )
            version = failed.get("version")
            if type(version) is not int:
                raise WorkerAttachmentRecoveryError(
                    "WORKER_ATTACHMENT_RECOVERY_INVALID",
                    "worker attachment recovery state is invalid",
                )
        try:
            self._registry.resolve_recovery(
                worker_id=worker_id, expected_version=version
            )
            return
        except WorkerAttachmentRegistryError as exc:
            if exc.code != "WORKER_ATTACHMENT_RECOVERY_PENDING":
                raise
        self._runtime_recovery.terminate_worker(
            worker_id, "startup attachment recovery"
        )
        self._registry.resolve_recovery(
            worker_id=worker_id, expected_version=version
        )
