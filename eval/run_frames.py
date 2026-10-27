"""Frame-level eval of the ScreenAnalyst (Tier 1 vision) on single screens.

Dataset: the Muse Image synthetic screens (``data/synthetic/manifest.json``)
plus the hand-written HTML pages (``eval/scenarios/frames``), used for the
fraud screens Muse Image's content filter declined to draw. Each screen is
labelled scam or benign. A screen counts as flagged when the analyst rates it
medium or high risk.

Usage::

    python -m eval.run_frames
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from analysts.screen_analyst import ScreenAnalyst
from core.config import REPO_ROOT
from eval.replay import SCENARIOS

RESULTS = REPO_ROOT / "eval" / "results"
SYNTHETIC = REPO_ROOT / "data" / "synthetic"

# rendered HTML pages: id -> (label, kind)
HTML_FRAMES = {
    "pc_safeguard_alert": ("scam", "hook"), "scam_browser_lock": ("scam", "hook"), "scam_ai_injection": ("scam", "hook"),
    "scam_account_locked": ("scam", "hook"), "gift_card_checkout": ("scam", "extraction"), "scam_gift_card_codes": ("scam", "extraction"),
    "scam_wire_form": ("scam", "extraction"), "scam_crypto_atm": ("scam", "extraction"), "scam_fake_refund_overpay": ("scam", "extraction"),
    "scam_secret_instructions": ("scam", "extraction"),
    "bank_dashboard": ("benign", "bank"), "desktop_idle": ("benign", "everyday"), "antivirus_blocked": ("benign", "alarming_ok"),
}


def dataset() -> list[dict]:
    items = [{**m, "source": "muse-image", "path": str(SYNTHETIC / m["file"])}
             for m in json.loads((SYNTHETIC / "manifest.json").read_text(encoding="utf-8"))]
    items += [{"id": k, "label": label, "kind": kind, "source": "html", "path": str(SCENARIOS / "frames" / f"{k}.png")}
              for k, (label, kind) in HTML_FRAMES.items()]
    return items


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    analyst = ScreenAnalyst()
    items = dataset()

    def run(item: dict) -> dict:
        try:
            f = analyst.analyze(Path(item["path"]))
            return {**item, "risk": f.risk, "signals": [n for n, _ in f.signals], "description": f.description}
        except Exception as exc:
            return {**item, "risk": "error", "signals": [], "description": f"{type(exc).__name__}: {exc}"}

    with ThreadPoolExecutor(6) as pool:
        results = list(pool.map(run, items))

    flagged = lambda r: r["risk"] in ("med", "high")
    tp = sum(1 for r in results if r["label"] == "scam" and flagged(r))
    fn = sum(1 for r in results if r["label"] == "scam" and not flagged(r))
    fp = sum(1 for r in results if r["label"] == "benign" and flagged(r))
    tn = sum(1 for r in results if r["label"] == "benign" and not flagged(r))
    injection = [r for r in results if "ai" in r["id"] and "injection" in r["id"]]
    summary = {
        "screens": len(results),
        "scam": tp + fn, "benign": fp + tn,
        "recall": round(tp / (tp + fn), 3) if tp + fn else None,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
        "injection_flagged": f"{sum('ai_directed_text' in r['signals'] for r in injection)}/{len(injection)}",
        "by_source": {s: sum(1 for r in results if r["source"] == s) for s in ("muse-image", "html")},
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "frames.json").write_text(json.dumps({"summary": summary, "results": results}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    for r in results:
        mark = "ok " if flagged(r) == (r["label"] == "scam") else "XX "
        print(f"{mark}{r['label']:<6} {r['risk']:<5} {r['source']:<10} {r['id']:<30} {','.join(r['signals'])[:70]}")


if __name__ == "__main__":
    main()
