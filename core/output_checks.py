"""Deterministic checks on what Tripwire writes for people: no invented facts.

The CaseJudge's reasons are verified quote by quote (:mod:`core.grounding`).
The recovery agent also *writes*: a fraud report the family will file and a
message to the family. Those are checked here before they leave, inside the
tool that sends them, so an output that fails is never delivered:

* **No invented numbers.** Every phone number, ID or amount must appear in the
  record. An invented number in a fraud report is worse than none.
* **Grounded identity.** "The scammer claimed to be ..." must name something
  actually said or shown.
* **Coverage.** The report must cover at least 80% of the key facts the record
  establishes (who they claimed to be, how they got in, what they asked for,
  how to reach them), so a family member can file it without re-reading the case.

A failed check returns the list of issues; the tool hands them back to the
agent, which fixes the draft and submits again (verify, give feedback, retry).
"""

from __future__ import annotations

import re

from core.grounding import ground_truth, normalize

MIN_COVERAGE = 0.8
_NUMBER = re.compile(r"[+$]?\d[\d,.\s()-]*\d|\$\d")

# what to look for in the report when the record establishes each fact
_REMOTE_WORDS = ("remote", "remotedesk", "anydesk", "teamviewer", "access", "control", "connected")
_PAYMENT_SIGNALS = {
    "gift_card_request": ("gift card", "gift cards"),
    "crypto_request": ("bitcoin", "crypto", "cryptocurrency"),
    "wire_transfer_request": ("wire", "transfer"),
    "cash_withdrawal_request": ("cash",),
    "advance_fee_request": ("fee", "tax", "processing", "shipping"),
    "overpayment_refund_story": ("refund", "send back", "overpaid"),
}
_REMOTE_SIGNALS = {"remote_tool_install_request", "remote_access_code_shared", "remote_tool_launched", "remote_session_active", "remote_control_input"}
_TIMES = re.compile(r"\b\d{1,2}:\d{2}(:\d{2})?\b")


def observed(snapshot: dict) -> list[str]:
    """What an output may state: the record, plus the evidence read off the screen and the system.

    A phone number on a scam pop-up is often only in the screen evidence (the
    analyst copies it out), not in the timeline's one-line description.
    """
    return ground_truth(snapshot) + [s.get("evidence", "") for s in snapshot.get("signals", [])]


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def invented_numbers(text: str, record: list[str]) -> list[str]:
    """Numbers in ``text`` (3+ digits, or money amounts) that appear nowhere in the record."""
    seen = " ".join(_digits(line) for line in record) + " " + " ".join(normalize(line) for line in record)
    out = []
    for raw in _NUMBER.findall(_TIMES.sub(" ", text)):
        d = _digits(raw)
        if len(d) < 3 and "$" not in raw:
            continue  # "2 gift cards", "3 steps": counts, not identifiers
        if d and d not in seen.replace(" ", "") and d not in seen:
            out.append(raw.strip())
    return out


def required_facts(snapshot: dict) -> dict[str, tuple[str, ...]]:
    """The facts the record establishes, each with the words that show the report mentions it."""
    names = {s["name"] for s in snapshot.get("signals", [])}
    facts: dict[str, tuple[str, ...]] = {}
    claimed = tuple(b for b in snapshot.get("brands", {}).get("call", []) if b not in ("windows", "security", "support"))
    if claimed:
        facts["who they claimed to be"] = claimed
    if names & _REMOTE_SIGNALS or snapshot.get("remote_active"):
        facts["remote access to the computer"] = _REMOTE_WORDS
    for signal, words in _PAYMENT_SIGNALS.items():
        if signal in names:
            facts[f"what they asked for ({words[0]})"] = words
    phones = [_digits(n) for t in snapshot.get("timeline", []) if t.get("source") in ("call", "screen")
              for n in re.findall(r"\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}", t.get("text", ""))]
    if phones:
        facts["the number they used"] = tuple(dict.fromkeys(p[-10:] for p in phones))
    return facts


def coverage(text: str, facts: dict[str, tuple[str, ...]]) -> tuple[float, list[str]]:
    """Share of ``facts`` the text mentions, and the ones it misses."""
    if not facts:
        return 1.0, []
    norm, digits = normalize(text), _digits(text)
    missing = [name for name, words in facts.items()
               if not any((w.isdigit() and w in digits) or (not w.isdigit() and normalize(w) in norm) for w in words)]
    return round(1 - len(missing) / len(facts), 2), missing


def check_report(report: dict, snapshot: dict, record: list[str]) -> dict:
    """Verify a fraud report draft; ``{"ok", "issues", "coverage", "numbers_checked"}``."""
    text = " ".join(str(v) for v in report.values())
    issues = [f'the number "{n}" is not in the record: remove it or copy it exactly' for n in invented_numbers(text, record)]
    claimed = normalize(str(report.get("scammer_claimed_to_be", "")))
    record_words = set(normalize(" ".join(record)).split())
    if claimed and not any(w in record_words for w in claimed.split() if len(w) > 3):
        issues.append(f'"{report.get("scammer_claimed_to_be")}" is not named anywhere in the record')
    lost = normalize(str(report.get("money_lost", "")))
    if lost and lost not in ("none", "no", "0", "nothing", "none sent", "no money") and not snapshot.get("money_sent"):
        if _digits(lost):
            issues.append("money_lost: the record shows no payment was completed; write 'none' unless one was")
    share, missing = coverage(text, required_facts(snapshot))
    if share < MIN_COVERAGE:
        issues.append(f"coverage {share:.0%} is below {MIN_COVERAGE:.0%}: also mention {', '.join(missing)}")
    return {"ok": not issues, "issues": issues, "coverage": share, "missing": missing,
            "numbers_checked": len(_NUMBER.findall(text))}


def check_message(text: str, record: list[str]) -> dict:
    """Verify the family message: plain words, no invented numbers."""
    bad = invented_numbers(text, record)
    issues = [f'the number "{n}" is not in the record' for n in bad]
    return {"ok": not issues, "issues": issues, "numbers_checked": len(_NUMBER.findall(text))}
