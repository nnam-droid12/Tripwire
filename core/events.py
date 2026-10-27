"""Shared event type and a thread-safe event bus.

Every Tier-0 watcher (screen, audio, process, network, clipboard) runs on its
own thread and reports what it sees as an :class:`Event` on an
:class:`EventBus`. Downstream consumers (the Tier-1 analysts, the session log,
the eval harness) read events from the bus without knowing which watcher
produced them.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class Event:
    """One observation from a watcher.

    Attributes:
        source: Which watcher produced it: ``screen``, ``audio``, ``process``,
            ``network`` or ``clipboard``.
        kind: What happened, e.g. ``frame_kept``, ``transcript``,
            ``process_launched``, ``remote_session_suspected``.
        data: Kind-specific payload. Must be JSON-serialisable and must never
            contain raw sensitive values (card numbers, passwords).
        ts: Unix timestamp in seconds.
    """

    source: str
    kind: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    def summary(self) -> str:
        """Human-readable one-liner for the console log."""
        clock = time.strftime("%H:%M:%S", time.localtime(self.ts))
        detail = self.data.get("summary") or ", ".join(f"{k}={v}" for k, v in self.data.items())
        return f"{clock} [{self.source:9}] {self.kind}: {detail}"


class EventBus:
    """Fan-in queue for events, with optional subscribers and a JSONL log."""

    def __init__(self, log_path: Path | None = None) -> None:
        self._queue: queue.Queue[Event] = queue.Queue()
        self._subscribers: list[Callable[[Event], None]] = []
        self._lock = threading.Lock()
        self._log_path = log_path
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)

    def subscribe(self, callback: Callable[[Event], None]) -> None:
        """Call ``callback`` synchronously for every published event."""
        self._subscribers.append(callback)

    def publish(self, event: Event) -> None:
        """Called by watchers from any thread."""
        if self._log_path:
            with self._lock, self._log_path.open("a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")
        for callback in self._subscribers:
            callback(event)
        self._queue.put(event)

    def get(self, timeout: float | None = None) -> Event | None:
        """Block for the next event; ``None`` on timeout."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None
