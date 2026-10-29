"""Client for the live Tripwire Sentinel service on Modal (``modal_app/sentinel.py``).

Sentinel is a bonus layer: if Modal is not configured, cold, slow or down,
``score`` returns None and Tripwire runs exactly as it would without it.
"""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path

from core.config import REPO_ROOT

THRESHOLD_FILE = REPO_ROOT / "eval" / "results" / "sentinel_threshold.json"
_POOL = ThreadPoolExecutor(4, thread_name_prefix="sentinel")


def threshold() -> float:
    try:
        return float(json.loads(THRESHOLD_FILE.read_text(encoding="utf-8"))["threshold"])
    except (OSError, ValueError, KeyError):
        return 0.96


def configured() -> bool:
    """Modal credentials are available (env vars on the server, ~/.modal.toml on a developer machine)."""
    return bool(os.environ.get("MODAL_TOKEN_ID")) or (Path.home() / ".modal.toml").exists()


_shared: "SentinelClient | None" = None


def shared() -> "SentinelClient | None":
    """One client per process, or None when Sentinel is off (``TRIPWIRE_SENTINEL=0``) or Modal is not configured."""
    global _shared
    if os.environ.get("TRIPWIRE_SENTINEL", "1") == "0" or not configured():
        return None
    if _shared is None:
        _shared = SentinelClient()
    return _shared


class SentinelClient:
    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout
        self._service = None
        self._lock = threading.Lock()

    def _get(self):
        with self._lock:
            if self._service is None:
                import modal

                self._service = modal.Cls.from_name("tripwire-sentinel", "SentinelService")()
            return self._service

    def warm(self) -> None:
        """Start a container in the background (a cold start loads the model: ~30-60 s)."""
        _POOL.submit(lambda: self._get().ping.remote())

    def score(self, turns: list[tuple[str, str]]) -> float | None:
        try:
            future = _POOL.submit(lambda: self._get().score.remote([list(t) for t in turns]))
            return future.result(timeout=self.timeout)
        except (FutureTimeout, Exception):
            return None
