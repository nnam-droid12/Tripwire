"""Site Check on cloned pages: the same page, at its real address and at clone addresses.

Each case is a rendered test page (fictional brands only) plus the address the browser is really at. The
real ScreenAnalyst (Muse Spark Open, vision) reads what the page claims to be and what it asks for; Site
Check's rules compare that with the real address. A clone of a sign-in page is pixel-for-pixel the real
page, so only the address tells them apart: that is the point of the test.

Usage::

    python -m eval.run_sites            # every case, twice
"""

from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from analysts.screen_analyst import ScreenAnalyst
from core.config import REPO_ROOT
from core.site_check import check_page

FRAMES = REPO_ROOT / "eval" / "scenarios" / "frames"
RESULTS = REPO_ROOT / "eval" / "results"
SAFE = frozenset()
CASES = [  # (page, the browser's real address, signals that must fire; SAFE = none may)
    ("site_shopwave_signin", "https://www.shopwave.com/signin", SAFE),
    ("site_shopwave_signin", "https://www.shopwаve.com/signin", {"lookalike_domain"}),  # Cyrillic "а"
    ("site_shopwave_signin", "https://shopvvave.com/signin", {"lookalike_domain"}),  # "vv" for "w"
    ("site_shopwave_signin", "https://shopwave.co/signin", {"lookalike_domain"}),
    ("site_shopwave_signin", "https://shopwave-order-review.help/signin", {"brand_domain_mismatch"}),
    ("site_bank_signin", "https://www.riverbendbank.com/login", SAFE),
    ("site_bank_signin", "https://online.riverbendbank.com/login", SAFE),
    ("site_bank_signin", "https://riverbend-secure-verify.top/login", {"brand_domain_mismatch"}),
    ("site_bank_signin", "https://riverbendbank.com.account-verify.help/login", {"brand_domain_mismatch"}),  # real name as a subdomain
    ("site_fake_window", "https://northgate-rewards.click/claim", {"fake_browser_window"}),
    ("site_giftcard_shop", "https://www.northgatemarket.com/checkout", SAFE),  # another brand's gift card: not a clone
    ("site_news_article", "https://valleydaily.example/business", SAFE),
]


def run_case(case, analyst: ScreenAnalyst) -> dict:
    page, url, expected = case
    finding = analyst.analyze(FRAMES / f"{page}.png")
    found = check_page(url, finding.page_brand, finding.asks_for, finding.drawn_urls)
    fired = {f.signal for f in found}
    ok = fired == set() if expected == SAFE else expected <= fired
    return {"page": page, "url": url, "expected": sorted(expected) or "safe", "fired": sorted(fired), "ok": ok,
            "model_read": {"page_brand": finding.page_brand, "asks_for": finding.asks_for, "drawn_urls": list(finding.drawn_urls)},
            "evidence": [f.evidence for f in found]}


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    analyst = ScreenAnalyst(redact=lambda png: png)  # fictional test pages: nothing to redact
    started = time.time()
    with ThreadPoolExecutor(6) as pool:
        rows = list(pool.map(lambda c: run_case(c, analyst), CASES * 2))
    clones = [r for r in rows if r["expected"] != "safe"]
    real = [r for r in rows if r["expected"] == "safe"]
    summary = {"clones_caught": sum(r["ok"] for r in clones), "clones": len(clones),
               "false_alarms": sum(not r["ok"] for r in real), "real_pages": len(real)}
    RESULTS.mkdir(parents=True, exist_ok=True)
    meta = {"date": time.strftime("%Y-%m-%d"), "minutes": round((time.time() - started) / 60, 1)}
    (RESULTS / "sites.json").write_text(json.dumps({"meta": meta, "summary": summary, "runs": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"Site Check on cloned pages ({meta['date']}): {len(CASES)} cases x 2 runs; the screen is read by Muse Spark Open.", "",
             f"Clones caught: **{summary['clones_caught']}/{summary['clones']}**. False alarms on real pages: **{summary['false_alarms']}/{summary['real_pages']}**.", "",
             "| Page | Browser's real address | Expected | Fired (run 1 / run 2) |", "|---|---|---|---|"]
    for i, (page, url, expected) in enumerate(CASES):
        a, b = rows[i], rows[i + len(CASES)]
        fired = " / ".join(", ".join(r["fired"]) or "nothing" for r in (a, b))
        lines.append(f"| {page} | `{url}` | {', '.join(sorted(expected)) or 'nothing (real page)'} | {fired} {'✓' if a['ok'] and b['ok'] else '✗'} |")
    md = "\n".join(lines) + "\n"
    (RESULTS / "sites.md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
