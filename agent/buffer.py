"""Rolling retention for captured data.

Frames and audio are only kept long enough to explain an incident. Anything
under ``runtime/`` older than the retention window (24h by default) is deleted
at start-up and then once an hour.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from core.config import RETENTION_HOURS, RUNTIME_DIR


def purge_old_files(root: Path = RUNTIME_DIR, max_age_hours: float = RETENTION_HOURS) -> int:
    """Delete files under ``root`` older than ``max_age_hours``. Returns the count."""
    if not root.exists():
        return 0
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    for path in root.rglob("*"):
        if path.is_file() and path.stat().st_mtime < cutoff:
            path.unlink(missing_ok=True)
            removed += 1
    return removed


class RetentionJanitor(threading.Thread):
    """Background thread that runs :func:`purge_old_files` periodically."""

    def __init__(self, interval_s: float = 3600.0) -> None:
        super().__init__(name="retention-janitor", daemon=True)
        self.interval_s = interval_s
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.is_set():
            purge_old_files()
            self._halt.wait(self.interval_s)

    def stop(self) -> None:
        self._halt.set()
