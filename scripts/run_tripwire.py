"""Run Tripwire live: Tier-0 capture + Tier-1 analysts filling a CaseFile.

Usage::

    python -m scripts.run_tripwire                           # mic + watchers; screen captured but not analysed
    python -m scripts.run_tripwire --allow-unredacted-frames # also send screenshots to the ScreenAnalyst

Until on-device redaction lands (Stage F), live screenshots are only sent to
the model with the explicit flag, because the real screen may show account
numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from functools import partial

from core.casefile import CaseFile
from core.config import LOGS_DIR
from core.events import EventBus
from core.orchestrator import Orchestrator
from eval.replay import format_update, print_casefile
from scripts.run_capture import add_capture_args, build_watchers, run_until_stopped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_capture_args(parser)
    parser.add_argument("--allow-unredacted-frames", action="store_true", help="send live screenshots to the model before redaction exists")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    log = partial(print, flush=True)

    stamp = int(time.time())
    bus = EventBus(LOGS_DIR / f"session_{stamp}.jsonl")
    bus.subscribe(lambda e: log(e.summary()))
    case = CaseFile()
    case.on_update(lambda u: log(format_update(u)))
    orchestrator = Orchestrator(bus, case, log=log, analyze_screen=args.allow_unredacted_frames)
    orchestrator.start()
    if not args.allow_unredacted_frames:
        log("Screen frames are captured locally but NOT analysed (no redaction yet; see --allow-unredacted-frames).")

    log("Tripwire running. Ctrl+C to stop.")
    run_until_stopped(build_watchers(bus, args), args.seconds)
    orchestrator.drain()
    print_casefile(case, log)
    out = LOGS_DIR / f"case_live_{stamp}.json"
    out.write_text(json.dumps(case.snapshot(), indent=2), encoding="utf-8")
    log(f"CaseFile saved to {out}")


if __name__ == "__main__":
    main()
