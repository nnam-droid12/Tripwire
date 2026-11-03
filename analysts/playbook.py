"""Scam Memory, the model half: learning a scam's script, and recognising it again.

Learning (after a verified stop), two Meta models with checks in between:

1. :class:`PlaybookWriter` (Muse Spark) distils the caller's side of the call into
   ordered steps, each a tactic from the fixed vocabulary plus the caller's exact words;
2. deterministic checks: every line must really be something the caller said
   (:mod:`core.grounding`), every tactic must be in the vocabulary, and personal data
   is scrubbed (:func:`core.memory.scrub`);
3. :class:`PlaybookReviewer` (Muse Spark Open, a different model) confirms that the steps,
   read in order, describe a scam rather than an honest call, and drops filler ("how can I
   help you today"). Not a scam script, or fewer than three steps left: nothing is learned.

Recognising (on every new call line), cheap first:

1. :func:`core.memory.candidates` scores stored playbooks against the call by word overlap;
2. only a candidate goes to :class:`Recall` (Muse Spark Open), which says which steps the
   caller has already done *in other words* and copies the caller's lines;
3. those lines are checked against the record; two or more verified steps in a script
   learned from a stopped scam make a ``known_scam_playbook`` signal the judge can cite.
"""

from __future__ import annotations

import time
from typing import Callable, Iterable

from analysts.common import SAFETY_RULES
from core.grounding import supported
from core.killchain import SIGNALS
from core.memory import candidates, content_words, describe, scrub, valid_tactic
from core.model_client import ModelClient

MIN_STEPS = 3
KINDS = ("tech support", "bank impersonation", "government impersonation", "refund", "prize or reward", "grandparent or relative",
         "romance", "investment", "other")

WRITER_PROMPT = f"""{SAFETY_RULES}

You are Tripwire's PlaybookWriter. Tripwire just stopped a scam call. You get the caller's side of the call, line by line.
Write the scam's PLAYBOOK: the script this scammer followed, so Tripwire can recognise the same script from a different scammer.

Rules:
- 5 to 8 steps, in the order they happened. Each step is one tactic plus ONE line the caller actually said, copied word for word
  (a single sentence is enough; copy, never paraphrase).
- Pick the lines that give the scam away: the ones an honest company would never say. Best: requests to install or open remote-access
  software, to read out a code or ID, to log in to the bank while connected, to buy gift cards or crypto, to send or withdraw money,
  to keep it secret or not hang up; claims that a refund was too large and must be paid back; threats of arrest or account closure.
  Avoid lines an honest caller could also say (greetings, "how can I help you", "can I have your name", a plain description of a charge).
- tactic must be one of these names, exactly:
{chr(10).join(f"  {name}: {spec.description}" for name, spec in SIGNALS.items() if valid_tactic(name))}

Reply with one JSON object and nothing else:
{{"title": "<at most 7 words, e.g. 'Fake Microsoft refund, remote access'>",
  "kind": "{'|'.join(KINDS)}",
  "claimed_to_be": "<who the caller claimed to be, e.g. 'Microsoft support'>",
  "ask": "<what they wanted in the end, at most 8 words>",
  "steps": [{{"tactic": "<name>", "line": "<exact words of the caller>"}}]}}"""

REVIEW_PROMPT = f"""{SAFETY_RULES}

You are an independent reviewer for Tripwire's Scam Memory. Another model wrote down the script of a call Tripwire stopped as a scam:
ordered steps, each a tactic plus a line the caller said. Memory will recognise future calls that follow the same script, so check two things.
1. The script as a whole: read in order, do these steps describe a scam (an invented problem, a fake refund, impersonation, pressure,
   a push for remote access, codes, personal details or money), rather than an honest service or sales call?
2. Each step: keep it unless it is filler that almost any phone call contains (a greeting, asking for a name, thanking, small talk).
   A step that sounds ordinary on its own but is part of the scam's sequence (for example "fill out the cancellation form" in a fake
   refund) is kept: memory matches the sequence, never one line alone.

Reply with one JSON object and nothing else:
{{"script_is_scam": true|false, "steps": [{{"n": <step number>, "keep": true|false, "note": "<at most 10 words>"}}]}}"""

RECALL_PROMPT = f"""{SAFETY_RULES}

You are Tripwire's Recall check. <playbook> is the script of a scam Tripwire stopped before (each step: tactic, then what that scammer said).
<transcript> is a call happening now. Different scammers use different words for the same script.
Decide whether the caller in <transcript> is following the same script. For each playbook step the caller has ALREADY done (in any words),
give the step number and copy the caller's line from <transcript> word for word. Only lines spoken by the caller count.
Do not count steps that are merely likely to come; do not count generic talk. If the call is a different kind of call, say so.

Reply with one JSON object and nothing else:
{{"same_script": true|false, "matches": [{{"step": <n>, "line": "<exact words copied from one transcript line>"}}], "note": "<at most 15 words>"}}"""


def _label(client: ModelClient, purpose: str, observer: Callable[[dict], None] | None) -> ModelClient:
    client.purpose = purpose
    if observer is not None:
        client.observer = observer
    return client


class PlaybookWriter:
    def __init__(self, client: ModelClient | None = None) -> None:
        self.client = client or ModelClient.for_provider("meta")

    def write(self, caller_lines: list[str], protected_names: Iterable[str] = (), observer=None) -> tuple[dict | None, dict]:
        """``(playbook or None, receipt)``. The playbook holds only verified, scrubbed caller lines."""
        _label(self.client, "Scam Memory · write the scam's playbook", observer)
        numbered = "\n".join(f"{i + 1}. {line}" for i, line in enumerate(caller_lines))
        data = self.client.chat_json([{"role": "system", "content": WRITER_PROMPT},
                                      {"role": "user", "content": f"<caller_lines>\n{numbered}\n</caller_lines>"}], max_tokens=3000)
        receipt = {"proposed": 0, "not_said": 0, "bad_tactic": 0, "too_short": 0}
        steps, seen = [], set()
        for s in data.get("steps", []) if isinstance(data.get("steps"), list) else []:
            if not isinstance(s, dict):
                continue
            receipt["proposed"] += 1
            tactic, line = str(s.get("tactic", "")).strip(), str(s.get("line", "")).strip()
            if not valid_tactic(tactic):
                receipt["bad_tactic"] += 1
                continue
            source = supported(line, caller_lines)
            if source is None:  # the caller never said it: a model cannot put words in a scammer's mouth
                receipt["not_said"] += 1
                continue
            clean = scrub(line, protected_names)
            if len(content_words(clean)) < 3 or clean.lower() in seen:
                receipt["too_short"] += 1
                continue
            seen.add(clean.lower())
            steps.append({"tactic": tactic, "line": clean})
        if len(steps) < MIN_STEPS:
            return None, receipt
        kind = str(data.get("kind", "other"))
        return {
            "title": scrub(str(data.get("title", "")), protected_names)[:80] or "Untitled scam script",
            "kind": kind if kind in KINDS else "other",
            "claimed_to_be": scrub(str(data.get("claimed_to_be", "")), protected_names)[:80],
            "ask": scrub(str(data.get("ask", "")), protected_names)[:80],
            "steps": steps[:8],
        }, receipt


class PlaybookReviewer:
    def __init__(self, client: ModelClient | None = None) -> None:
        self.client = client or ModelClient.for_provider("baseten")

    def review(self, playbook: dict, observer=None) -> tuple[dict | None, list[dict]]:
        """Keep the script only if, read in order, it is a scam; drop filler steps. ``(playbook or None, dropped steps)``."""
        _label(self.client, "Scam Memory · independently check each step", observer)
        listing = "\n".join(f"{i + 1}. [{s['tactic']}] {s['line']}" for i, s in enumerate(playbook["steps"]))
        data = self.client.chat_json([{"role": "system", "content": REVIEW_PROMPT},
                                      {"role": "user", "content": f"<steps>\n{listing}\n</steps>"}], max_tokens=1500)
        verdicts = {}
        for v in data.get("steps", []) if isinstance(data.get("steps"), list) else []:
            try:
                verdicts[int(v.get("n"))] = v
            except (TypeError, ValueError, AttributeError):
                continue
        kept, dropped = [], []
        for i, s in enumerate(playbook["steps"]):
            v = verdicts.get(i + 1, {})
            (kept if v.get("keep") is True else dropped).append({**s, "note": str(v.get("note", "not reviewed"))[:80]})
        if data.get("script_is_scam") is not True or len(kept) < MIN_STEPS:
            return None, dropped
        return {**playbook, "steps": [{"tactic": s["tactic"], "line": s["line"]} for s in kept]}, dropped


def learn(caller_lines: list[str], protected_names: Iterable[str] = (), writer: PlaybookWriter | None = None,
          reviewer: PlaybookReviewer | None = None, observer=None) -> tuple[dict | None, dict]:
    """Write, verify and review a playbook from a stopped scam. ``(playbook or None, receipt)``."""
    started = time.time()
    try:
        playbook, receipt = (writer or PlaybookWriter()).write(caller_lines, protected_names, observer)
    except Exception as exc:  # e.g. an empty or malformed model reply: nothing is learned
        return None, {"outcome": f"writer failed ({type(exc).__name__})", "seconds": round(time.time() - started, 1)}
    if playbook is None:
        return None, {**receipt, "outcome": "not enough verified steps", "seconds": round(time.time() - started, 1)}
    try:
        reviewed, dropped = (reviewer or PlaybookReviewer()).review(playbook, observer)
    except Exception as exc:  # no second opinion, no learning: memory must not grow on one model's word
        return None, {**receipt, "outcome": f"reviewer unavailable ({type(exc).__name__})", "seconds": round(time.time() - started, 1)}
    receipt["reviewer_dropped"] = [d["line"] for d in dropped]
    if reviewed is None:
        return None, {**receipt, "outcome": "reviewer: not a scam script, or fewer than 3 steps left", "seconds": round(time.time() - started, 1)}
    return reviewed, {**receipt, "outcome": "learned", "steps": len(reviewed["steps"]), "seconds": round(time.time() - started, 1)}


class Recall:
    """Recognises a stored script in a live call. One instance per call: it remembers what it already checked."""

    MAX_CHECKS_PER_PLAYBOOK = 3

    def __init__(self, playbooks: Callable[[], list[dict]], client: ModelClient | None = None, observer=None) -> None:
        self.playbooks = playbooks
        self.client = _label(client or ModelClient.for_provider("baseten"), "Scam Memory · recognise a learned scam script", observer)
        self._checked: dict[str, tuple[int, float]] = {}  # playbook id -> (checks so far, best word score when last checked)
        self.matched: set[str] = set()

    def check(self, transcript: list[tuple[str, str]], signals: set[str] = frozenset()) -> list[dict]:
        """New confirmed matches for the call so far. ``transcript``: ``[(speaker_label, text)]``, caller = "A"."""
        caller = [text for who, text in transcript if who == "A"]
        found = []
        for pb, s in candidates([p for p in self.playbooks() if p["id"] not in self.matched], caller, signals):
            checks, last = self._checked.get(pb["id"], (0, 0.0))
            if checks >= self.MAX_CHECKS_PER_PLAYBOOK or s <= last:
                continue  # ask the model again only when the call has moved closer to the script
            self._checked[pb["id"]] = (checks + 1, s)
            match = self._confirm(pb, transcript, caller)
            if match:
                self.matched.add(pb["id"])
                found.append(match)
        return found

    def _confirm(self, pb: dict, transcript: list[tuple[str, str]], caller: list[str]) -> dict | None:
        lines = "\n".join(f"{'caller' if who == 'A' else 'other'}: {text}" for who, text in transcript[-40:])
        data = self.client.chat_json([{"role": "system", "content": RECALL_PROMPT},
                                      {"role": "user", "content": f"<playbook>\n{describe(pb)}\n</playbook>\n<transcript>\n{lines}\n</transcript>"}],
                                     max_tokens=1500)
        if data.get("same_script") is not True:
            return None
        steps, used = [], set()
        for m in data.get("matches", []) if isinstance(data.get("matches"), list) else []:
            try:
                n = int(m.get("step"))
            except (TypeError, ValueError, AttributeError):
                continue
            source = supported(str(m.get("line", "")), caller)  # only the caller's own words, really said
            if source is None or n in used or not 1 <= n <= len(pb["steps"]):
                continue
            used.add(n)
            steps.append((n, source))
        if len(steps) < 2:
            return None
        steps.sort()
        quotes = "; ".join(f'step {n} ({pb["steps"][n - 1]["tactic"].replace("_", " ")}): "{q[:160]}"' for n, q in steps)
        seen = pb.get("seen", 1)
        evidence = (f'Scam Memory: the caller is following a scam script Tripwire learned from {seen} stopped scam{"s" if seen != 1 else ""} '
                    f'("{pb["title"]}"), {len(steps)} of {len(pb["steps"])} steps so far: {quotes}')
        return {"playbook": pb["id"], "title": pb["title"], "seen": seen, "steps": steps, "evidence": evidence}
