"""Evaluate Tripwire on scam conversations we did not write.

Datasets (Apache-2.0, downloaded on first run into the git-ignored ``data/external``):

* ``BothBosu/youtube-scam-conversations``: 20 real scam calls transcribed from
  scam-baiting YouTube channels (tech support, refund, reward, SSN). All scams.
* ``BothBosu/scam-dialogue`` (test split): 320 phone dialogues, 160 scams
  (SSN, refund, support, reward) and 160 legitimate calls (delivery,
  insurance, telemarketing, wrong number).

These are calls only (no screen), so Tripwire must decide from the
conversation alone. Each conversation is replayed one turn at a time through
the real CallAnalyst, CaseFile, escalation policy and CaseJudge, waiting for
the analysis of each turn before the next ("turn-synchronous"). We record
whether, and at which turn, it reached a hard stop.

Usage::

    python -m eval.run_external                 # everything, 6 conversations in parallel
    python -m eval.run_external --limit 40      # quick sample (stratified by type)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import statistics
import sys
import time
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from core.casefile import CaseFile
from core.config import REPO_ROOT
from core.events import Event, EventBus
from core.orchestrator import Orchestrator
from core.policy import Action

EXTERNAL = REPO_ROOT / "data" / "external"
RESULTS = REPO_ROOT / "eval" / "results"
SOURCES = {
    "youtube": ("BothBosu/youtube-scam-conversations", "youtube_scam_conversations.csv"),
    "dialogue": ("BothBosu/scam-dialogue", "scam-dialogue_test.csv"),
}
_TURN = re.compile(r"(?:^|\s)(Suspect|Innocent|caller|receiver)\s*:\s*", re.I)
CALLER = {"suspect", "caller"}


@dataclass(frozen=True)
class Conversation:
    source: str
    kind: str  # scam type, or the benign call type
    is_scam: bool
    turns: list[tuple[str, str]]  # (speaker label A/B, text)


def _fetch(source: str) -> str:
    repo, name = SOURCES[source]
    path = EXTERNAL / name
    if not path.exists():
        EXTERNAL.mkdir(parents=True, exist_ok=True)
        url = f"https://huggingface.co/datasets/{repo}/resolve/main/{name}"
        path.write_text(urllib.request.urlopen(url, timeout=60).read().decode("utf-8", "ignore"), encoding="utf-8")
    return path.read_text(encoding="utf-8")


def parse_turns(dialogue: str) -> list[tuple[str, str]]:
    """Split "caller: ... receiver: ..." (or Suspect/Innocent) text into (A|B, text) turns. A is the caller."""
    parts = _TURN.split(dialogue)
    turns = []
    for who, text in zip(parts[1::2], parts[2::2]):
        text = " ".join(text.split())
        if text:
            turns.append(("A" if who.lower() in CALLER else "B", text))
    return turns


def load(limit: int | None = None) -> list[Conversation]:
    convs: list[Conversation] = []
    for row in csv.DictReader(io.StringIO(_fetch("youtube"))):
        convs.append(Conversation("youtube", row["type"], True, parse_turns(row["dialogue"])))
    dialogue = [Conversation("dialogue", r["type"], r["label"] == "1", parse_turns(r["dialogue"])) for r in csv.DictReader(io.StringIO(_fetch("dialogue")))]
    if limit:  # stratified: the same number of each call type
        by_type: dict[str, list[Conversation]] = defaultdict(list)
        for c in dialogue:
            by_type[c.kind].append(c)
        per = max(1, limit // len(by_type))
        dialogue = [c for cs in by_type.values() for c in cs[:per]]
    return [c for c in convs + dialogue if len(c.turns) >= 2]


class _NoScreen:
    """These conversations have no screen; the ScreenAnalyst is never called."""


def run_one(conv: Conversation) -> dict:
    bus, case = EventBus(), CaseFile()
    orch = Orchestrator(bus, case, screen=_NoScreen(), log=lambda _: None)
    orch.start()
    stop_turn = nudge_turn = None
    errs: list[str] = []
    orch.log = lambda m: errs.append(m)
    for i, (speaker, text) in enumerate(conv.turns):
        bus.publish(Event("audio", "transcript", {"speaker": speaker, "text": text[:1200]}))
        orch.drain()  # turn-synchronous: analysis (and any judge call) for this turn completes first
        if nudge_turn is None and orch.action >= Action.NUDGE:
            nudge_turn = i + 1
        if orch.action == Action.HARD_STOP:
            stop_turn = i + 1
            break
    errors = sum("analyst" in m or "judge" in m for m in errs)
    return {
        "source": conv.source, "kind": conv.kind, "is_scam": conv.is_scam, "turns": len(conv.turns),
        "action": orch.action.label, "stop_turn": stop_turn, "nudge_turn": nudge_turn,
        "stop_fraction": round(stop_turn / len(conv.turns), 2) if stop_turn else None,
        "judge_calls": len(orch.verdicts), "errors": errors, "error_samples": errs[:2],
    }


def _rate(xs: list[bool]) -> float | None:
    return round(sum(xs) / len(xs), 3) if xs else None


def summarize(rows: list[dict]) -> dict:
    out: dict = {}
    for name, sel in [("youtube_real", lambda r: r["source"] == "youtube"), ("dialogue", lambda r: r["source"] == "dialogue")]:
        rs = [r for r in rows if sel(r)]
        scam = [r for r in rs if r["is_scam"]]
        benign = [r for r in rs if not r["is_scam"]]
        fracs = [r["stop_fraction"] for r in scam if r["stop_fraction"] is not None]
        out[name] = {
            "scam": len(scam), "benign": len(benign),
            "detection_rate": _rate([r["action"] == "hard_stop" for r in scam]),
            "false_alarm_rate": _rate([r["action"] == "hard_stop" for r in benign]),
            "benign_nudge_rate": _rate([r["action"] == "nudge" for r in benign]),
            "median_stop_turn": statistics.median([r["stop_turn"] for r in scam if r["stop_turn"]]) if fracs else None,
            "median_stop_fraction": statistics.median(fracs) if fracs else None,
        }
    by_kind: dict[str, dict] = {}
    for kind in sorted({r["kind"] for r in rows}):
        rs = [r for r in rows if r["kind"] == kind and r["source"] == "dialogue"]
        if rs:
            by_kind[kind] = {"n": len(rs), "is_scam": rs[0]["is_scam"], "hard_stop_rate": _rate([r["action"] == "hard_stop" for r in rs]),
                             "nudge_rate": _rate([r["action"] == "nudge" for r in rs])}
    out["by_kind"] = by_kind
    out["errors"] = sum(r["errors"] for r in rows)
    return out


def to_markdown(s: dict, meta: dict) -> str:
    pct = lambda x: "n/a" if x is None else f"{x * 100:.0f}%"
    y, d = s["youtube_real"], s["dialogue"]
    lines = [
        f"Evaluated {meta['date']} on conversations we did not write (call audio only, no screen).",
        "",
        "| Dataset | Scams stopped | False alarms on legitimate calls | Median turn of the stop |",
        "|---|---|---|---|",
        f"| Real scam calls from scam-baiting videos ({y['scam']}) | **{pct(y['detection_rate'])}** | (all scams) | {y['median_stop_turn']} ({pct(y['median_stop_fraction'])} into the call) |",
        f"| Phone dialogues ({d['scam']} scam, {d['benign']} legitimate) | **{pct(d['detection_rate'])}** | **{pct(d['false_alarm_rate'])}** (nudged: {pct(d['benign_nudge_rate'])}) | {d['median_stop_turn']} ({pct(d['median_stop_fraction'])} into the call) |",
        "",
        "| Call type | Kind | Hard stop | Nudge |",
        "|---|---|---|---|",
    ]
    for kind, k in s["by_kind"].items():
        lines.append(f"| {kind} | {'scam' if k['is_scam'] else 'legitimate'} | {pct(k['hard_stop_rate'])} | {pct(k['nudge_rate'])} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, help="stratified sample size of the dialogue set")
    parser.add_argument("--parallel", type=int, default=6)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    convs = load(args.limit)
    print(f"{len(convs)} conversations, {args.parallel} in parallel", flush=True)
    done = [0]

    def run(c: Conversation) -> dict:
        try:
            r = run_one(c)
        except Exception as exc:
            r = {"source": c.source, "kind": c.kind, "is_scam": c.is_scam, "turns": len(c.turns), "action": "error", "stop_turn": None,
                 "nudge_turn": None, "stop_fraction": None, "judge_calls": 0, "errors": 1, "error": repr(exc)}
        done[0] += 1
        if done[0] % 10 == 0:
            print(f"  {done[0]}/{len(convs)}", flush=True)
        return r

    started = time.time()
    with ThreadPoolExecutor(args.parallel) as pool:
        rows = list(pool.map(run, convs))
    summary = summarize(rows)
    meta = {"date": time.strftime("%Y-%m-%d"), "conversations": len(rows), "minutes": round((time.time() - started) / 60, 1)}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "external.json").write_text(json.dumps({"meta": meta, "summary": summary, "runs": rows}, indent=2), encoding="utf-8")
    md = to_markdown(summary, meta)
    (RESULTS / "external.md").write_text(md, encoding="utf-8")
    print("\n" + md + f"\nerrors: {summary['errors']} | {meta['minutes']} min")


if __name__ == "__main__":
    main()
