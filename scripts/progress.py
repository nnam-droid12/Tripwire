"""Publish the build dashboard (/progress) from this machine.

Usage::

    python -m scripts.progress "Running the final test-split evaluation"
    python -m scripts.progress --done EXT --doing SITE "Building the landing page"

Reads the milestones from ``docs/progress.json``, applies any status changes
given here (and saves them back), adds the latest commits from git, and posts
everything with the agent token to ``TRIPWIRE_BACKEND_URL``. Nothing here is
secret: the dashboard is public by design.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import urllib.request

from agent.reporter import agent_token
from core.config import REPO_ROOT

SPEC = REPO_ROOT / "docs" / "progress.json"


def recent_commits(n: int = 12) -> list[dict[str, str]]:
    out = subprocess.run(["git", "log", f"-{n}", "--pretty=format:%h\t%cI\t%s"], capture_output=True, text=True, cwd=REPO_ROOT).stdout
    return [dict(zip(("sha", "date", "subject"), line.split("\t", 2))) for line in out.splitlines() if line]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("now", help="one sentence: what is being worked on right now")
    parser.add_argument("--done", action="append", default=[], help="milestone id to mark done")
    parser.add_argument("--doing", action="append", default=[], help="milestone id to mark in progress")
    args = parser.parse_args()

    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    for m in spec["milestones"]:
        if m["id"] in args.done:
            m["status"] = "done"
        elif m["id"] in args.doing:
            m["status"] = "in_progress"
    SPEC.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")

    body = {**spec, "now": args.now, "commits": recent_commits()}
    url = os.environ.get("TRIPWIRE_BACKEND_URL", "http://127.0.0.1:8765").rstrip("/") + "/api/progress"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "X-Tripwire-Token": agent_token()})
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(f"published to {url}: {resp.status}")


if __name__ == "__main__":
    main()
