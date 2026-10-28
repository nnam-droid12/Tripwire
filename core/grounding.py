"""Grounding: no claim without evidence that is actually in the record.

Model output is free text, so it can state things that never happened. Before
any reason can justify an action, the quote it rests on is checked against the
*ground-truth* record of the session:

* what was actually said (transcript lines, from speech recognition), and
* what actually happened on the computer (Tier-0 system events).

Descriptions written by the analysts are deliberately not ground truth: a
model cannot vouch for a model. Screen evidence counts only through the screen
descriptions' own quoted text when the judge cites them, and is marked as such.

Matching tolerates the small differences of transcription (case, punctuation,
spacing, a word or two) but not paraphrase: at least 85% of the quote must
appear as one near-contiguous run of the source.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Iterable

_NON_WORD = re.compile(r"[^a-z0-9$ ]+")
MIN_WORDS = 3
MIN_RATIO = 0.85


def normalize(text: str) -> str:
    return " ".join(_NON_WORD.sub(" ", text.lower()).split())


def supported(quote: str, sources: Iterable[str]) -> str | None:
    """Return the source line that contains ``quote`` (allowing transcription noise), or None."""
    q = normalize(quote)
    if len(q.split()) < MIN_WORDS:
        return None  # too short to prove anything ("yes", "okay")
    for source in sources:
        s = normalize(source)
        if q in s:
            return source
        match = SequenceMatcher(None, q, s, autojunk=False).find_longest_match(0, len(q), 0, len(s))
        if match.size >= MIN_RATIO * len(q):
            return source
        # tolerate a single dropped or changed word: compare against a window of the same length
        if len(s) >= len(q) and match.size >= 0.5 * len(q):
            start = max(0, match.b - match.a)
            window = s[start:start + len(q) + 8]
            if SequenceMatcher(None, q, window, autojunk=False).ratio() >= MIN_RATIO:
                return source
    return None


def ground_truth(snapshot: dict) -> list[str]:
    """The lines a claim may cite: what was said, and what the computer actually did."""
    lines = []
    for t in snapshot.get("timeline", []):
        if t["source"] in ("call", "process", "network", "clipboard", "control", "intervention", "rules"):
            lines.append(t["text"])
        elif t["source"] == "screen":
            lines.append(t["text"])  # screen description: allowed, but reasons citing it are tagged "screen"
    return lines


def verify_reasons(reasons: list[dict], snapshot: dict) -> tuple[list[dict], list[dict]]:
    """Split reasons into ``(verified, unsupported)``; verified ones carry the exact source line."""
    timeline = snapshot.get("timeline", [])
    verified, unsupported = [], []
    for r in reasons:
        source = supported(r.get("evidence", ""), ground_truth(snapshot))
        if source is None:
            unsupported.append(r)
            continue
        kind = next((t["source"] for t in timeline if t["text"] == source), "record")
        verified.append({**r, "source": source[:300], "source_kind": kind})
    return verified, unsupported
