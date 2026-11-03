"""Scam Memory: what one stopped scam teaches Tripwire about the *script*.

Community Shield remembers who the scammer was (a phone number, a remote-access
ID). A new scammer with a new number but the same script would still start from
zero. Scam Memory remembers how the scam worked: after a stop, the caller's side
of the call is distilled into a *playbook*, an ordered list of steps, each a
tactic from the kill-chain vocabulary plus the caller's own words for it.

On a later call, playbooks are compared with what the caller has said so far.
This module is the deterministic half (no model):

* :func:`candidates` finds playbooks worth a closer look: a cheap word-overlap
  score, step by step, so a model is asked only when there is something to ask;
* :func:`scrub` keeps playbooks free of personal data: digits, e-mail addresses
  and the protected person's names never enter memory;
* :func:`merge_key` decides when a new playbook is the same script as a stored one,
  so memory grows by evidence ("seen in 4 stopped scams"), not by duplicates.

The model half (writing, reviewing and recognising playbooks) lives in
:mod:`analysts.playbook`; storage in :mod:`backend.memory`.

Memory is data, never instructions: playbook text reaches models only inside
tags, under the same untrusted-evidence rules as a transcript, and only scams that
Tripwire actually stopped, with verified reasons, are ever learned.
"""

from __future__ import annotations

import re
from typing import Iterable

from core.killchain import SIGNALS, SYSTEM_ONLY

_WORD = re.compile(r"[a-z][a-z']+")
_DIGITS = re.compile(r"\d[\d\s().,-]*\d|\d")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
STOP = set("""
a an the and or but if then so of to in on at by for with from as is are was were be been being am i you he she it we they me him her us
them my your his its our their this that these those there here what which who whom whose when where why how all any both each few more
most other some such no nor not only own same than too very can will just don't should now do does did doing have has had having would
could ok okay yes yeah hello hi sir maam ma'am mam please thank thanks well right oh um uh like know get got going go one let just also
about into out up down over again once really sure today call calling called phone line speak speaking talk talking say said tell told
""".split())
MIN_STEP_WORDS = 3  # a step must carry at least this many content words to be matchable


def content_words(text: str) -> set[str]:
    return {w.strip("'") for w in _WORD.findall(text.lower()) if w.strip("'") not in STOP and len(w) > 2}


def scrub(text: str, protected_names: Iterable[str] = ()) -> str:
    """Remove what must never be remembered: numbers of any kind, e-mail addresses, the protected person's names."""
    text = _EMAIL.sub("[email]", text)
    text = _DIGITS.sub("#", text)
    for name in protected_names:
        if name:
            text = re.sub(rf"\b{re.escape(name)}\b", "[name]", text, flags=re.I)
    return " ".join(text.split())[:300]


def valid_tactic(name: str) -> bool:
    """Steps may only use tactics a model is allowed to name (never a system-only signal)."""
    return name in SIGNALS and name not in SYSTEM_ONLY


def step_overlap(step_line: str, line: str) -> float:
    """Share of the step's content words that appear in ``line`` (0..1)."""
    words = content_words(step_line)
    if len(words) < MIN_STEP_WORDS:
        return 0.0
    return len(words & content_words(line)) / len(words)


def score(playbook: dict, caller_lines: list[str], signals: set[str] = frozenset()) -> tuple[float, list[int]]:
    """How far the call so far follows ``playbook``: ``(score, matched step indexes)``.

    A step counts when some caller line repeats at least half of its content words, or, weaker, when the
    call already carries the step's tactic signal (said in other words). Steps must match in order.
    """
    matched, line_at, total = [], 0, 0.0
    for i, step in enumerate(playbook.get("steps", [])):
        best, best_at = 0.0, None
        for j in range(line_at, len(caller_lines)):
            o = step_overlap(step["line"], caller_lines[j])
            if o > best:
                best, best_at = o, j
        if best >= 0.5:
            matched.append(i)
            total += 1.0
            line_at = best_at  # the next step must come at or after this line
        elif step.get("tactic") in signals:
            total += 0.5
    return total, matched


def candidates(playbooks: list[dict], caller_lines: list[str], signals: set[str] = frozenset(),
               threshold: float = 1.5, limit: int = 3) -> list[tuple[dict, float]]:
    """Playbooks the call may be following, best first: only these go to the model for a closer look."""
    scored = []
    for pb in playbooks:
        s, _ = score(pb, caller_lines, signals)
        if s >= threshold:
            scored.append((pb, s))
    scored.sort(key=lambda x: -x[1])
    return scored[:limit]


def merge_key(new: dict, stored: list[dict]) -> dict | None:
    """The stored playbook that is the same script as ``new`` (most of its steps re-appear in order), if any."""
    lines = [s["line"] for s in new.get("steps", [])]
    best, best_score = None, 0.0
    for pb in stored:
        s, matched = score(pb, lines)
        need = max(2, (len(pb.get("steps", [])) + 1) // 2)
        if len(matched) >= need and s > best_score:
            best, best_score = pb, s
    return best


def describe(playbook: dict) -> str:
    """The playbook as compact text for a model prompt (always inside <playbook> tags: it is data)."""
    head = f'"{playbook.get("title", "")}" (claims to be: {playbook.get("claimed_to_be", "?")}; wants: {playbook.get("ask", "?")})'
    steps = "\n".join(f"{i + 1}. [{s['tactic']}] {s['line']}" for i, s in enumerate(playbook.get("steps", [])))
    return f"{head}\n{steps}"
