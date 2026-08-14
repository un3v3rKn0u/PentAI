from __future__ import annotations

import math
import time
from collections.abc import Callable
from datetime import UTC, datetime
from threading import Lock


class ClockHealthError(RuntimeError):
    pass


class ClockHealthMonitor:
    """Compare wall-clock progress with monotonic elapsed time."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        max_drift_seconds: float = 1,
    ) -> None:
        if not 0 < max_drift_seconds <= 5 or not math.isfinite(max_drift_seconds):
            raise ValueError("clock drift tolerance is invalid")
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._max_drift_seconds = max_drift_seconds
        self._baseline: tuple[datetime, float] | None = None
        self._lock = Lock()

    def check(self) -> None:
        wall = self._wall_clock()
        monotonic = self._monotonic_clock()
        if wall.tzinfo is None or not math.isfinite(monotonic):
            raise ClockHealthError("clock observation is invalid")
        wall = wall.astimezone(UTC)
        with self._lock:
            if self._baseline is not None:
                prior_wall, prior_monotonic = self._baseline
                monotonic_elapsed = monotonic - prior_monotonic
                wall_elapsed = (wall - prior_wall).total_seconds()
                if (
                    monotonic_elapsed < 0
                    or wall_elapsed < 0
                    or abs(wall_elapsed - monotonic_elapsed) > self._max_drift_seconds
                ):
                    raise ClockHealthError("clock progress is untrusted")
            self._baseline = (wall, monotonic)
