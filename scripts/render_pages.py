"""Render the fictional scenario pages to PNG screenshots with headless Edge/Chrome.

Usage::

    python -m scripts.render_pages

Writes ``eval/scenarios/frames/<page>.png`` (1280x720) for every
``eval/scenarios/pages/*.html``. The PNGs are what scenario replays feed to
the ScreenAnalyst, so evals do not depend on what is on the real screen.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from core.config import REPO_ROOT

PAGES = REPO_ROOT / "eval" / "scenarios" / "pages"
FRAMES = REPO_ROOT / "eval" / "scenarios" / "frames"
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "msedge",
    "chrome",
]


def find_browser() -> str:
    for candidate in BROWSERS:
        if Path(candidate).exists() or shutil.which(candidate):
            return candidate
    raise RuntimeError("No Edge or Chrome found for headless rendering")


def render(page: Path, out: Path, browser: str) -> None:
    subprocess.run(
        [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--screenshot={out}", "--window-size=1280,720", page.as_uri()],
        check=True,
        capture_output=True,
        timeout=60,
    )


def main() -> None:
    FRAMES.mkdir(parents=True, exist_ok=True)
    browser = find_browser()
    for page in sorted(p for p in PAGES.glob("*.html") if not p.name.startswith("_")):
        out = FRAMES / f"{page.stem}.png"
        render(page, out, browser)
        print(f"rendered {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
