"""Stage a scam live on this screen, for the demo video.

Usage::

    python -m scripts.demo                       # PC SafeGuard tech-support + refund scam
    python -m scripts.demo --scenario scam_refund_quickassist --report

What happens:

* the scenario's screens (fake pop-up, bank page, gift cards) appear in a
  1280x720 window, and Tripwire's warning covers that window only;
* the call plays through the speakers, two voices: scammer and victim;
* the same audio is streamed to Muse Voice Transcribe, as the live microphone would be;
* Notepad stands in for AnyDesk, so the hard stop has a real process to end;
* Tripwire runs for real: analysts, CaseJudge, the spoken nudge, the full-screen
  warning in the natural voice, the remote tool terminated, and (``--report``)
  the incident sent to the family dashboard.

The warning stays up until dismissed with the family PIN, or with "I am safe"
after the 60-second cooldown, or until ``--hold`` seconds have passed.
Only Notepad is ever terminated, never a real remote-access tool.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from core.config import REPO_ROOT
from eval.replay import SCENARIOS, TimedItem, frame_path, replay

KEY_EVENTS = ("decision", "intervention", "judge")


def play_call(wav: Path) -> subprocess.Popen:
    """Play the call aloud in a separate process, independent of Tripwire's own voice."""
    return subprocess.Popen(
        ["powershell", "-NoProfile", "-Command", f"(New-Object Media.SoundPlayer '{wav}').PlaySync()"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", default="scam_pc_safeguard")
    parser.add_argument("--report", action="store_true", help="send the incident to the family dashboard backend")
    parser.add_argument("--hold", type=float, default=90, help="seconds the warning stays up after the call ends")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    scenario_path = SCENARIOS / f"{args.scenario}.json"
    wav = SCENARIOS / "audio" / f"{args.scenario}.wav"
    if not wav.exists():
        subprocess.run([sys.executable, "-m", "scripts.make_call_audio", str(scenario_path)], check=True, cwd=REPO_ROOT)

    stage = subprocess.Popen([sys.executable, "-m", "scripts.demo_stage"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=REPO_ROOT)
    region = stage.stdout.readline().split()  # "REGION x,y,w,h" once the window is up
    if len(region) == 2 and region[0] == "REGION":
        os.environ["TRIPWIRE_OVERLAY_REGION"] = region[1]  # warning covers the demo window, not the whole screen
    stand_in = subprocess.Popen(["notepad.exe"])  # the "AnyDesk" the hard stop will end
    player: list[subprocess.Popen] = []

    def show(item: TimedItem) -> None:
        if item.kind == "frame":
            stage.stdin.write(str(frame_path(item.payload["name"])) + "\n")
            stage.stdin.flush()

    def log(line: str) -> None:
        if any(f"[{src}" in line for src in KEY_EVENTS) or "transcript" in line:
            print(line, flush=True)

    try:
        result = replay(
            scenario_path, mode="audio", log=log, interventions="live", kill_only={"notepad.exe"},
            overlay_seconds=args.hold, report=args.report,
            on_item=show, on_call_start=lambda: player.append(play_call(wav)),
        )
        print(f"\nResult: {result.action.label.upper()}", flush=True)
    finally:
        for proc in player + [stand_in]:
            if proc.poll() is None:
                proc.kill()
        if stage.poll() is None:
            stage.stdin.close()
            stage.wait(timeout=5)


if __name__ == "__main__":
    main()
