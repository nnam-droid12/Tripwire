"""Run Tripwire live: capture, analysts, judge, interventions and tray icon.

Usage::

    python -m scripts.run_tripwire                           # mic + watchers; screen captured but not analysed
    python -m scripts.run_tripwire --allow-unredacted-frames # also send screenshots to the ScreenAnalyst
    python -m scripts.run_tripwire --kill dry                # report, but do not terminate, remote-access tools

Until on-device redaction lands (Stage F), live screenshots are only sent to
the model with the explicit flag, because the real screen may show account
numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from functools import partial

from agent.tray import TrayIcon
from analysts.interventionist import Interventionist
from core.casefile import CaseFile
from core.config import LOGS_DIR
from core.events import EventBus
from core.orchestrator import Orchestrator
from core.settings import Settings
from eval.replay import format_update, print_casefile
from scripts.run_capture import add_capture_args, build_watchers, run_until_stopped


def _sync_tray(tray: TrayIcon, event) -> None:
    """Turn the tray icon red during a hard stop and back afterwards."""
    if (event.source, event.kind) == ("decision", "hard_stop"):
        tray.set_state("alert")
    elif (event.source, event.kind) == ("intervention", "dismissed"):
        tray.set_state("paused" if tray.paused else "watching")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_capture_args(parser)
    parser.add_argument("--allow-unredacted-frames", action="store_true", help="send live screenshots to the model before redaction exists")
    parser.add_argument("--kill", choices=("live", "dry", "off"), default="live", help="what a hard stop does to remote-access tools")
    parser.add_argument("--no-tray", action="store_true")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    log = partial(print, flush=True)

    settings = Settings.load()
    stamp = int(time.time())
    bus = EventBus(LOGS_DIR / f"session_{stamp}.jsonl")
    bus.subscribe(lambda e: log(e.summary()))
    case = CaseFile()
    case.on_update(lambda u: log(format_update(u)))
    orchestrator = Orchestrator(bus, case, log=log, analyze_screen=args.allow_unredacted_frames)
    orchestrator.start()
    interventionist = Interventionist(
        bus, case, orchestrator, settings, kill_mode=args.kill, extra_tools={exe: f"{exe} (test)" for exe in args.watch}
    )
    interventionist.start()
    if not args.allow_unredacted_frames:
        log("Screen frames are captured locally but NOT analysed (no redaction yet; see --allow-unredacted-frames).")

    quit_requested = threading.Event()
    tray = None
    if not args.no_tray:
        tray = TrayIcon(
            settings, interventionist.overlay,
            is_alert_active=lambda: interventionist.active,
            on_pause=lambda paused: setattr(orchestrator, "paused", paused),
            on_quit=quit_requested.set,
        )
        tray.run_detached()
        bus.subscribe(partial(_sync_tray, tray))

    log("Tripwire running. Ctrl+C or tray > Quit to stop.")
    run_until_stopped(build_watchers(bus, args), args.seconds, quit_requested)
    orchestrator.drain()
    interventionist.stop()
    if tray:
        tray.stop()
    print_casefile(case, log)
    out = LOGS_DIR / f"case_live_{stamp}.json"
    out.write_text(json.dumps(case.snapshot(), indent=2), encoding="utf-8")
    log(f"CaseFile saved to {out}")


if __name__ == "__main__":
    main()
