"""Replay a scripted scenario through the real pipeline.

A scenario (``eval/scenarios/*.json``) is a timeline of screen frames,
Tier-0 system events and call lines. Replay publishes them onto an
:class:`EventBus` at the right moments, so the orchestrator and analysts see
exactly what they would see live, without touching the real screen.

Two ways to deliver the call:

* ``audio`` - stream the synthesized WAV through the real Muse Voice
  Transcribe session (end-to-end, real time only).
* ``text``  - publish each call line directly as a transcript event
  (caller = speaker A, protected person = speaker B). Faster, and
  deterministic for evals.

Usage::

    python -m eval.replay eval/scenarios/scam_pc_safeguard.json --mode audio
    python -m eval.replay eval/scenarios/scam_pc_safeguard.json --mode text --speed 3
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from agent.capture_audio import AudioWatcher, wav_frames
from core.casefile import CaseFile, CaseUpdate
from core.config import LOGS_DIR, REPO_ROOT
from core.events import Event, EventBus
from core.orchestrator import Orchestrator

SCENARIOS = REPO_ROOT / "eval" / "scenarios"
SPEAKER_LABELS = {"caller": "A", "senior": "B"}


@dataclass(frozen=True)
class TimedItem:
    t: float
    kind: str  # frame | tier0 | say
    payload: dict


def _line_offsets(scenario: dict) -> list[float]:
    """Start time of each call line: from the synthesized audio if present, else estimated."""
    offsets_file = SCENARIOS / "audio" / f"{scenario['name']}.offsets.json"
    if offsets_file.exists():
        return json.loads(offsets_file.read_text())
    offsets, t = [], 0.0
    for line in scenario.get("call", []):
        offsets.append(round(t, 2))
        t += len(line["text"].split()) * 0.38 + 0.7
    return offsets


def build_timeline(scenario: dict, mode: str) -> list[TimedItem]:
    start = float(scenario.get("call_start", 0))
    offsets = _line_offsets(scenario)
    items: list[TimedItem] = []
    for ev in scenario.get("events", []):
        t = ev["t"] if "t" in ev else start + offsets[ev["line"]] + ev.get("offset", 0)
        if "frame" in ev:
            items.append(TimedItem(t, "frame", {"name": ev["frame"]}))
        elif "tier0" in ev:
            items.append(TimedItem(t, "tier0", ev["tier0"]))
    if mode == "text":
        for i, line in enumerate(scenario.get("call", [])):
            # a transcript arrives when the line has been spoken, not when it starts
            duration = len(line["text"].split()) * 0.38
            items.append(TimedItem(start + offsets[i] + duration, "say", {"speaker": SPEAKER_LABELS[line["speaker"]], "text": line["text"], "turn_id": i}))
    return sorted(items, key=lambda it: it.t)


def publish_item(bus: EventBus, item: TimedItem) -> None:
    if item.kind == "frame":
        path = SCENARIOS / "frames" / f"{item.payload['name']}.png"
        bus.publish(Event("screen", "frame_kept", {"path": str(path), "summary": f"scenario frame {path.name}"}))
    elif item.kind == "tier0":
        bus.publish(Event(item.payload["source"], item.payload["kind"], dict(item.payload.get("data", {}))))
    elif item.kind == "say":
        p = item.payload
        bus.publish(Event("audio", "transcript", {**p, "summary": f'Speaker {p["speaker"]}: "{p["text"]}"'}))


def replay(scenario_path: Path, mode: str = "text", speed: float = 1.0, log=print) -> CaseFile:
    """Run one scenario end to end and return the filled CaseFile."""
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
    bus = EventBus(LOGS_DIR / f"replay_{scenario['name']}_{int(time.time())}.jsonl")
    case = CaseFile()
    orchestrator = Orchestrator(bus, case, log=log)
    case.on_update(lambda u: log(format_update(u)))
    bus.subscribe(lambda e: log(e.summary()))
    orchestrator.start()

    audio: AudioWatcher | None = None
    if mode == "audio":
        speed = 1.0  # the realtime ASR must be fed in real time
        wav = SCENARIOS / "audio" / f"{scenario['name']}.wav"
        if not wav.exists():
            raise FileNotFoundError(f"{wav} missing: run python -m scripts.make_call_audio {scenario_path}")
        audio = AudioWatcher(bus, source=partial(wav_frames, wav))

    log(f"=== replaying {scenario['name']} ({scenario['label']}) mode={mode} speed={speed} ===")
    t0 = time.monotonic()
    audio_started = False
    for item in build_timeline(scenario, mode):
        if audio and not audio_started and item.t >= scenario.get("call_start", 0):
            _sleep_until(t0, scenario.get("call_start", 0) / speed)
            audio.start()
            audio_started = True
        _sleep_until(t0, item.t / speed)
        publish_item(bus, item)
    if audio:
        if not audio_started:
            audio.start()
        audio.join()
    orchestrator.drain()
    return case


def _sleep_until(t0: float, target: float) -> None:
    delay = target - (time.monotonic() - t0)
    if delay > 0:
        time.sleep(delay)


def format_update(update: CaseUpdate) -> str:
    added = ", ".join(f"{s.name}<{s.source}>" for s in update.new_signals)
    present = "".join(str(int(s)) for s in sorted(update.stages_present))
    return f"  >> CASE +[{added}]  stage={update.stage.name} stages={{{present}}} confidence={update.confidence:.2f}"


def print_casefile(case: CaseFile, log=print) -> None:
    snap = case.snapshot()
    log("\n=== CaseFile ===")
    log(f"stage: {snap['stage']} {snap['stage_name']} | confidence {snap['confidence']:.2f} | stages present {snap['stages_present']} | remote active {snap['remote_active']}")
    log(f"brands: {snap['brands']}")
    for s in snap["signals"]:
        log(f"  [{s['stage']}] {s['name']:<28} {s['source']:<9} {s['evidence'][:90]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--mode", choices=("text", "audio"), default="text")
    parser.add_argument("--speed", type=float, default=1.0, help="time compression for text mode")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    log = partial(print, flush=True)
    case = replay(args.scenario, args.mode, args.speed, log)
    print_casefile(case, log)
    out = LOGS_DIR / f"case_{args.scenario.stem}_{int(time.time())}.json"
    out.write_text(json.dumps(case.snapshot(), indent=2), encoding="utf-8")
    log(f"\nCaseFile saved to {out}")


if __name__ == "__main__":
    main()
