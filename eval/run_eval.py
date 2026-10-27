"""Evaluation harness: replay every scenario and report the numbers.

Usage::

    python -m eval.run_eval                       # all scenarios, 2 runs each, 6 in parallel
    python -m eval.run_eval --runs 3 --parallel 8

Metrics (scam scenarios unless stated):

* **Detection rate**: share of scam runs that reached ``hard_stop``.
* **False-alarm rate**: share of benign runs that reached ``hard_stop``
  (nudges on benign runs are reported separately; a calm spoken sentence is
  a much smaller cost than a full-screen stop).
* **Time to detection**: seconds from the scam's first observable sign
  (scenario ``onset``) to the hard stop, in scenario time.
* **Stopped before the money ask**: the hard stop came before the line where
  money was first requested (scenario ``extraction_line``).
* **Tier-1-only ablation**: what would have happened if the cheap Tier-1
  score alone (>= 0.8) triggered the stop, without the CaseJudge.

Runs replay call lines as text at real-time speed (``--speed 1``) so model
latency counts against time to detection exactly as it would live. Results
go to ``eval/results/latest.json`` and ``eval/results/latest.md``.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core.config import REPO_ROOT
from core.policy import Action
from eval.replay import SCENARIOS, ReplayResult, _line_offsets, replay

RESULTS = REPO_ROOT / "eval" / "results"
TIER1_STOP = 0.8


def _scenario_time(scenario: dict, marker: dict | int | None) -> float | None:
    """Scenario seconds for ``{"t": x}``, ``{"line": n}`` or a bare line index."""
    if marker is None:
        return None
    if isinstance(marker, int):
        marker = {"line": marker}
    if "t" in marker:
        return float(marker["t"])
    return float(scenario.get("call_start", 0)) + _line_offsets(scenario)[marker["line"]]


def score_run(result: ReplayResult) -> dict:
    s = result.scenario
    stops = [v.ts for a, v in result.decisions if a == Action.HARD_STOP]
    stop_t = result.scenario_time(stops[0]) if stops else None
    onset_t = _scenario_time(s, s.get("onset"))
    extraction_t = _scenario_time(s, s.get("extraction_line"))
    t1_stop = next((result.scenario_time(ts) for ts, c in result.tier1_history if c >= TIER1_STOP), None)
    timeline = result.case.snapshot()["timeline"]
    return {
        "scenario": s["name"],
        "label": s["label"],
        "action": result.action.label,
        "passed": result.passed,
        "hard_stop_at": round(stop_t, 1) if stop_t is not None else None,
        "time_to_detection": round(stop_t - onset_t, 1) if stop_t is not None and onset_t is not None else None,
        "before_money_ask": (stop_t < extraction_t) if stop_t is not None and extraction_t is not None else None,
        "tier1_max": round(max((c for _, c in result.tier1_history), default=0.0), 2),
        "tier1_only_stop": t1_stop is not None,
        "tier1_only_ttd": round(t1_stop - onset_t, 1) if t1_stop is not None and onset_t is not None else None,
        "judge_calls": len(result.verdicts),
        "tier1_calls": sum(1 for t in timeline if t["source"] in ("screen", "call")),
    }


def _rate(xs: list[bool]) -> float | None:
    return round(sum(xs) / len(xs), 3) if xs else None


def summarize(runs: list[dict]) -> dict:
    scam = [r for r in runs if r["label"] == "scam"]
    benign = [r for r in runs if r["label"] == "benign"]
    ttd = [r["time_to_detection"] for r in scam if r["time_to_detection"] is not None]
    t1_ttd = [r["tier1_only_ttd"] for r in scam if r["tier1_only_ttd"] is not None]
    before = [r["before_money_ask"] for r in scam if r["before_money_ask"] is not None]
    return {
        "scam_runs": len(scam),
        "benign_runs": len(benign),
        "detection_rate": _rate([r["action"] == "hard_stop" for r in scam]),
        "false_alarm_rate": _rate([r["action"] == "hard_stop" for r in benign]),
        "benign_nudge_rate": _rate([r["action"] == "nudge" for r in benign]),
        "median_time_to_detection_s": round(statistics.median(ttd), 1) if ttd else None,
        "max_time_to_detection_s": max(ttd) if ttd else None,
        "stopped_before_money_ask": _rate(before),
        "tier1_only_detection_rate": _rate([r["tier1_only_stop"] for r in scam]),
        "tier1_only_false_alarm_rate": _rate([r["tier1_only_stop"] for r in benign]),
        "tier1_only_median_ttd_s": round(statistics.median(t1_ttd), 1) if t1_ttd else None,
        "judge_calls_per_run": round(statistics.mean(r["judge_calls"] for r in runs), 1) if runs else None,
        "tier1_calls_per_run": round(statistics.mean(r["tier1_calls"] for r in runs), 1) if runs else None,
    }


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def to_markdown(summary: dict, runs: list[dict], meta: dict) -> str:
    s = summary
    lines = [
        f"Evaluated {meta['date']}: {len(set(r['scenario'] for r in runs))} scenarios x {meta['runs']} runs "
        f"({s['scam_runs']} scam runs, {s['benign_runs']} benign runs), text replay at real-time speed.",
        "",
        "| Metric | Tripwire (Tier 1 + CaseJudge) | Tier-1 score alone (ablation) |",
        "|---|---|---|",
        f"| Scam detection rate (hard stop) | **{_pct(s['detection_rate'])}** | {_pct(s['tier1_only_detection_rate'])} |",
        f"| False-alarm rate (hard stop on benign) | **{_pct(s['false_alarm_rate'])}** | {_pct(s['tier1_only_false_alarm_rate'])} |",
        f"| Median time to detection | **{s['median_time_to_detection_s']} s** | {s['tier1_only_median_ttd_s']} s |",
        f"| Scams stopped before money was asked for | **{_pct(s['stopped_before_money_ask'])}** | |",
        f"| Benign runs that got a spoken nudge | {_pct(s['benign_nudge_rate'])} | |",
        f"| Model calls per run (Tier 1 / Tier 2) | {s['tier1_calls_per_run']} / {s['judge_calls_per_run']} | |",
        "",
        "| Scenario | Kind | Result per run | Time to detection (s) | Before money ask |",
        "|---|---|---|---|---|",
    ]
    for name in sorted({r["scenario"] for r in runs}):
        rs = [r for r in runs if r["scenario"] == name]
        result = ", ".join(r["action"] for r in rs)
        ttd = ", ".join("-" if r["time_to_detection"] is None else str(r["time_to_detection"]) for r in rs)
        before = ", ".join("-" if r["before_money_ask"] is None else ("yes" if r["before_money_ask"] else "no") for r in rs)
        lines.append(f"| `{name}` | {rs[0]['label']} | {result} | {ttd} | {before} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--parallel", type=int, default=6)
    parser.add_argument("--speed", type=float, default=1.0)
    parser.add_argument("--only", nargs="*", help="scenario names to run (default: all)")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    paths = sorted(SCENARIOS.glob("*.json"))
    if args.only:
        paths = [p for p in paths if p.stem in args.only]
    jobs = [p for p in paths for _ in range(args.runs)]
    print(f"{len(jobs)} runs ({len(paths)} scenarios x {args.runs}), {args.parallel} in parallel", flush=True)

    def run(path: Path) -> dict:
        started = time.time()
        try:
            scored = score_run(replay(path, "text", args.speed, log=lambda _: None))
        except Exception as exc:  # report a crashed run as a failure, keep the rest
            scored = {"scenario": path.stem, "label": "scam" if path.stem.startswith("scam") else "benign", "action": "error",
                      "passed": False, "error": f"{type(exc).__name__}: {exc}", "time_to_detection": None, "before_money_ask": None,
                      "tier1_max": 0, "tier1_only_stop": False, "tier1_only_ttd": None, "judge_calls": 0, "tier1_calls": 0}
        print(f"  {'PASS' if scored['passed'] else 'FAIL'} {scored['scenario']:<32} {scored['action']:<9} "
              f"ttd={scored['time_to_detection']} ({time.time() - started:.0f}s)", flush=True)
        return scored

    with ThreadPoolExecutor(args.parallel) as pool:
        runs = list(pool.map(run, jobs))

    summary = summarize(runs)
    meta = {"date": time.strftime("%Y-%m-%d"), "runs": args.runs, "speed": args.speed}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "latest.json").write_text(json.dumps({"meta": meta, "summary": summary, "runs": runs}, indent=2), encoding="utf-8")
    md = to_markdown(summary, runs, meta)
    (RESULTS / "latest.md").write_text(md, encoding="utf-8")
    print("\n" + md)


if __name__ == "__main__":
    main()
