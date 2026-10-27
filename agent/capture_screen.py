"""Screen capture with change detection (Tier 0).

Grabs the primary monitor at ~1.5 fps but only *keeps* a frame when it differs
meaningfully from the last kept one, measured as the Hamming distance between
perceptual hashes. While the screen is changing continuously (scrolling,
typing) at most one frame is kept every ``min_keep_interval_s``; comparisons
are always against the last *kept* frame, so a change is delayed, never lost. A static desktop therefore costs nothing downstream; a
full-screen "virus detected" page appearing produces exactly one kept frame.

Kept frames are saved locally as PNGs under ``runtime/frames`` (rolling 24h
buffer). They are redacted before leaving the machine (see ``redact.py``).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import imagehash
import mss
from PIL import Image

from core.config import FRAMES_DIR
from core.events import Event, EventBus

# Max width of stored frames: enough for a vision model to read UI text, small
# enough to keep upload size and token cost down.
STORE_MAX_WIDTH = 1280


class FrameChangeDetector:
    """Decides whether a frame is different enough from the last kept one."""

    def __init__(self, threshold: int = 10, hash_size: int = 16) -> None:
        self.threshold = threshold
        self.hash_size = hash_size
        self._last: imagehash.ImageHash | None = None

    def check(self, image: Image.Image) -> tuple[bool, int]:
        """Return ``(keep, distance)``. The first frame is always kept."""
        h = imagehash.phash(image, hash_size=self.hash_size)
        if self._last is None:
            self._last = h
            return True, -1
        distance = int(h - self._last)
        if distance >= self.threshold:
            self._last = h
            return True, distance
        return False, distance


class ScreenWatcher(threading.Thread):
    """Samples the screen and publishes ``frame_kept`` events."""

    def __init__(self, bus: EventBus, fps: float = 1.5, out_dir: Path = FRAMES_DIR, threshold: int = 10, min_keep_interval_s: float = 2.0) -> None:
        super().__init__(name="screen-watcher", daemon=True)
        self.bus = bus
        self.interval_s = 1.0 / fps
        self.out_dir = out_dir
        self.detector = FrameChangeDetector(threshold=threshold)
        self.min_keep_interval_s = min_keep_interval_s
        self._last_kept = 0.0
        self._halt = threading.Event()

    def run(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # primary display
            while not self._halt.is_set():
                started = time.monotonic()
                if started - self._last_kept < self.min_keep_interval_s:
                    self._halt.wait(self.interval_s)
                    continue
                try:
                    shot = sct.grab(monitor)
                    image = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                    keep, distance = self.detector.check(image)
                    if keep:
                        self._last_kept = started
                        self._save_and_publish(image, distance)
                except Exception as exc:  # e.g. secure desktop / UAC prompt; keep watching
                    self.bus.publish(Event("screen", "capture_error", {"summary": repr(exc)}))
                self._halt.wait(max(0.0, self.interval_s - (time.monotonic() - started)))

    def _save_and_publish(self, image: Image.Image, distance: int) -> None:
        if image.width > STORE_MAX_WIDTH:
            image = image.resize((STORE_MAX_WIDTH, round(image.height * STORE_MAX_WIDTH / image.width)))
        ts = time.time()
        path = self.out_dir / f"frame_{int(ts * 1000)}.png"
        image.save(path, optimize=True)
        reason = "first frame" if distance < 0 else f"changed, distance {distance}"
        self.bus.publish(
            Event("screen", "frame_kept", {"path": str(path), "distance": distance, "summary": f"{path.name} ({reason})"}, ts=ts)
        )

    def stop(self) -> None:
        self._halt.set()
