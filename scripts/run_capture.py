"""Stage B gate: run every Tier-0 watcher and print a live event log.

Usage::

    python -m scripts.run_capture                      # live mic + screen + watchers
    python -m scripts.run_capture --wav call.wav       # replay a recorded call instead of the mic
    python -m scripts.run_capture --watch notepad.exe  # treat an extra exe as a remote-access tool (testing)
    python -m scripts.run_capture --seconds 60

Events are also appended to ``runtime/logs/session_<ts>.jsonl``.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from functools import partial
from pathlib import Path

from agent.buffer import RetentionJanitor
from agent.capture_audio import AudioWatcher, wav_frames
from agent.capture_screen import ScreenWatcher
from agent.watchers import ClipboardWatcher, ProcessWatcher
from core.config import LOGS_DIR
from core.events import EventBus


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=float, default=0, help="stop after N seconds (0 = until Ctrl+C)")
    parser.add_argument("--wav", type=Path, help="replay a 24 kHz mono WAV instead of the microphone")
    parser.add_argument("--no-audio", action="store_true")
    parser.add_argument("--watch", action="append", default=[], help="extra exe name to treat as a remote-access tool")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    log_path = LOGS_DIR / f"session_{int(time.time())}.jsonl"
    bus = EventBus(log_path)
    bus.subscribe(lambda e: print(e.summary(), flush=True))

    watchers: list[threading.Thread] = [
        RetentionJanitor(),
        ScreenWatcher(bus),
        ProcessWatcher(bus, extra_tools={exe: f"{exe} (test)" for exe in args.watch}),
        ClipboardWatcher(bus),
    ]
    if not args.no_audio:
        source = partial(wav_frames, args.wav) if args.wav else None
        watchers.append(AudioWatcher(bus, source=source))

    print(f"Tripwire capture running. Log: {log_path}", flush=True)
    for w in watchers:
        w.start()
    deadline = time.time() + args.seconds if args.seconds else None
    try:
        while deadline is None or time.time() < deadline:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    for w in watchers:
        w.stop()
    # let the audio watcher flush its last ASR session
    for w in watchers:
        if isinstance(w, AudioWatcher):
            w.join(timeout=20)
    print("stopped.", flush=True)


if __name__ == "__main__":
    main()
