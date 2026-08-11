from __future__ import annotations

from threading import Lock


class StorageSafetyLatch:
    """Process-local fail-closed latch for uncertain durable storage."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._reason_code: str | None = None

    def trip(self, reason_code: str = "STORAGE_FAILURE") -> None:
        with self._lock:
            if self._reason_code is None:
                self._reason_code = reason_code

    def reason_code(self) -> str | None:
        with self._lock:
            return self._reason_code

    def require_safe(self) -> None:
        if self.reason_code() is not None:
            raise StorageSafetyError("durable storage is unsafe; human recovery is required")


class StorageSafetyError(RuntimeError):
    pass
