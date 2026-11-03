"""Does Scam Memory make Tripwire stop scams earlier? A leave-one-out test on real scam calls.

The 20 real scam calls (transcribed from scam-baiting videos) come from different scammers,
but many follow the same scripts. For each call:

1. **Learn.** A playbook is written from every call (Muse Spark), checked word by word against
   what the caller really said, and reviewed step by step (Muse Spark Open). Cached in
   ``eval/results/memory_playbooks.json``.
2. **Leave one out.** Call *i* is replayed with a memory holding only the playbooks learned from
   the *other* 19 calls (merged when they are the same script), so Tripwire never remembers the call
   it is being tested on. The same call is replayed without memory, on the same day, for comparison.
3. **False alarms.** The 160 legitimate calls of the dialogue test set are replayed with every learned
   playbook in memory: memory must not turn ordinary calls into stops.

Usage::

    python -m eval.run_memory                  # with Tripwire Sentinel (the published configuration)
    python -m eval.run_memory --no-sentinel    # without it
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from analysts.playbook import Recall, learn
from core.memory import merge_key
from eval import run_external as ext

CACHE = ext.RESULTS / "memory_playbooks.json"


def learn_all(calls: list[ext.Conversation]) -> list[dict | None]:
    if CACHE.exists():
        return json.loads(CACHE.read_text(encoding="utf-8"))["playbooks"]

    def one(i_c):
        i, c = i_c
        lines = [t for who, t in c.turns if who == "A"]
        pb, receipt = learn(lines)
        if receipt["outcome"].startswith(("writer failed", "reviewer unavailable")):  # a dropped reply, not a judgement: try once more
            pb, receipt = learn(lines)
        print(f"  call {i + 1}: {receipt['outcome']}" + (f" ({pb['title']}, {len(pb['steps'])} steps)" if pb else ""), flush=True)
        return ({**pb, "id": f"call{i + 1}", "seen": 1} if pb else None), receipt

    with ThreadPoolExecutor(6) as pool:
        out = list(pool.map(one, enumerate(calls)))
    CACHE.write_text(json.dumps({"playbooks": [p for p, _ in out], "receipts": [r for _, r in out]}, indent=2), encoding="utf-8")
    return [p for p, _ in out]


def merged(playbooks: list[dict]) -> list[dict]:
    """The memory store as backend.memory would build it: the same script from two calls becomes one entry seen twice."""
    store: list[dict] = []
    for pb in playbooks:
        same = merge_key(pb, store)
        if same is not None:
            same["seen"] += 1
        else:
            store.append(json.loads(json.dumps(pb)))
    return store


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-sentinel", action="store_true")
    parser.add_argument("--skip-benign", action="store_true")
    parser.add_argument("--parallel", type=int, default=6)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    if not args.no_sentinel:
        ext.SENTINEL.update(json.loads((ext.RESULTS / "sentinel_scores.json").read_text(encoding="utf-8")))
    every = ext.load(split="test")
    calls = [c for c in every if c.source == "youtube"]
    print(f"learning playbooks from {len(calls)} real scam calls", flush=True)
    playbooks = learn_all(calls)
    print(f"  {sum(p is not None for p in playbooks)} learned", flush=True)

    def replay(job):
        i, with_memory = job
        memory = None
        if with_memory:
            others = merged([p for j, p in enumerate(playbooks) if p is not None and j != i])
            memory = Recall(lambda: others)
        try:
            return ext.run_one(calls[i], memory=memory)
        except Exception as exc:
            return {"action": "error", "error": repr(exc), "stop_turn": None, "turns": len(calls[i].turns), "memory_turn": None}

    started = time.time()
    jobs = [(i, m) for i in range(len(calls)) for m in (False, True)]
    with ThreadPoolExecutor(args.parallel) as pool:
        rows = list(pool.map(replay, jobs))
    pairs = [{"call": i + 1, "kind": calls[i].kind, "turns": len(calls[i].turns), "without": rows[2 * i], "with": rows[2 * i + 1]}
             for i in range(len(calls))]

    benign_rows = []
    if not args.skip_benign:
        benign = [c for c in every if c.source == "dialogue" and not c.is_scam]
        store = merged([p for p in playbooks if p is not None])
        print(f"replaying {len(benign)} legitimate calls with all {len(store)} playbooks in memory", flush=True)
        with ThreadPoolExecutor(args.parallel) as pool:
            benign_rows = list(pool.map(lambda c: ext.run_one(c, memory=Recall(lambda: store)), benign))

    def stats(key):
        rs = [p[key] for p in pairs]
        stopped = [r for r in rs if r["action"] == "hard_stop"]
        fr = [r["stop_turn"] / r["turns"] for r in stopped]
        return {"stopped": len(stopped), "of": len(rs), "median_stop_turn": statistics.median([r["stop_turn"] for r in stopped]) if stopped else None,
                "median_fraction": round(statistics.median(fr), 3) if fr else None, "mean_stop_turn": round(statistics.mean([r["stop_turn"] for r in stopped]), 1) if stopped else None}

    earlier = sum(1 for p in pairs if p["with"]["stop_turn"] and (not p["without"]["stop_turn"] or p["with"]["stop_turn"] < p["without"]["stop_turn"]))
    later = sum(1 for p in pairs if p["without"]["stop_turn"] and (not p["with"]["stop_turn"] or p["with"]["stop_turn"] > p["without"]["stop_turn"]))
    summary = {
        "without_memory": stats("without"), "with_memory": stats("with"), "stopped_earlier_with_memory": earlier, "stopped_later_with_memory": later,
        "memory_fired": sum(1 for p in pairs if p["with"].get("memory_turn")),
        "playbooks_learned": sum(p is not None for p in playbooks),
        "benign": {"calls": len(benign_rows), "false_alarms": sum(r["action"] == "hard_stop" for r in benign_rows),
                   "memory_fired": sum(1 for r in benign_rows if r.get("memory_turn"))} if benign_rows else None,
    }
    meta = {"date": time.strftime("%Y-%m-%d"), "sentinel": not args.no_sentinel, "minutes": round((time.time() - started) / 60, 1)}
    stem = "memory" + ("" if not args.no_sentinel else "_no_sentinel")
    (ext.RESULTS / f"{stem}.json").write_text(json.dumps({"meta": meta, "summary": summary, "pairs": pairs, "benign": benign_rows}, indent=2), encoding="utf-8")
    md = to_markdown(summary, meta, pairs)
    (ext.RESULTS / f"{stem}.md").write_text(md, encoding="utf-8")
    print("\n" + md)


def to_markdown(s: dict, meta: dict, pairs: list[dict]) -> str:
    w, m = s["without_memory"], s["with_memory"]
    pct = lambda x: "n/a" if x is None else f"{x * 100:.0f}%"
    lines = [f"Scam Memory, leave-one-out on the 20 real scam calls ({meta['date']}, Sentinel {'on' if meta['sentinel'] else 'off'}). "
             f"Each call was replayed with a memory learned only from the other 19.", "",
             "| | Scams stopped | Median turn of the stop | Median point in the call |", "|---|---|---|---|",
             f"| Without memory | {w['stopped']}/{w['of']} | {w['median_stop_turn']} | {pct(w['median_fraction'])} |",
             f"| With Scam Memory | {m['stopped']}/{m['of']} | {m['median_stop_turn']} | {pct(m['median_fraction'])} |", "",
             f"Stopped earlier with memory: {s['stopped_earlier_with_memory']} calls; later: {s['stopped_later_with_memory']}. "
             f"Memory recognised a learned script in {s['memory_fired']} of {w['of']} calls. Playbooks learned: {s['playbooks_learned']} of 20."]
    if s.get("benign"):
        b = s["benign"]
        lines.append(f"Legitimate calls replayed with every playbook in memory: {b['calls']}; false alarms: {b['false_alarms']}; "
                     f"memory matched a script: {b['memory_fired']}.")
    lines += ["", "| Call | Type | Turns | Stop without memory | Stop with memory | Memory matched at |", "|---|---|---|---|---|---|"]
    for p in pairs:
        lines.append(f"| {p['call']} | {p['kind']} | {p['turns']} | {p['without']['stop_turn'] or 'no stop'} | {p['with']['stop_turn'] or 'no stop'} | "
                     f"{p['with'].get('memory_turn') or '-'} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
