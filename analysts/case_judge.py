"""CaseJudge (Tier 2): weighs the whole session and returns the verdict.

Called only on escalation. It receives the entire session (every frame
description, transcript line, system event and signal) and reasons about
the *story*, which is where Muse Spark's long context earns its place: the
difference between a scam and a grandson helping with online banking is
rarely visible in any single moment.

It is the only component allowed to recommend ``hard_stop``, and even then
:class:`core.policy.EscalationPolicy` checks its confidence before acting.

Before a stop, the verdict goes through verification (see :class:`Verification`):

1. deterministic: every quote must be in the record (:mod:`core.grounding`);
2. an independent model, the :class:`analysts.reviewer.Reviewer`, confirms each
   surviving quote really shows what its reason claims;
3. if either layer leaves no reason standing, the judge is told exactly what
   failed and gets one more attempt (verify, give feedback, retry).

What happened is kept as a receipt on the verdict, shown to the family.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import datetime

from analysts.common import SAFETY_RULES
from analysts.reviewer import Reviewer
from core.grounding import verify_reasons
from core.model_client import ModelClient
from core.policy import Action, Verdict

PROMPT = f"""{SAFETY_RULES}

You are the CaseJudge. You receive the full record of a monitoring session on an older person's computer:
screen descriptions, call transcript lines, system events and the evidence signals found so far.
Decide whether a scam is in progress and what Tripwire should do.

Scam kill chain: 1 Hook (fake alert, call-this-number) -> 2 Contact (caller claims to be Microsoft/bank/government)
-> 3 Control (remote-access tool, live session, "close that warning") -> 4 Access (banking open under remote control,
told to log in) -> 5 Extraction (gift cards, crypto, wire, cash, "we refunded too much", "don't tell the bank").
One stage alone is weak; a chain is strong. Agreement between screen and call is strong.

Legitimate look-alikes you must NOT treat as scams on their own: a person using their own online banking; a relative or
known helper assisting with the computer (even via remote access) without asking for money, codes, or secrecy;
a genuine antivirus notice that says a threat was blocked and asks for no call or payment; ordinary software updates.

Actions:
- "log": nothing concerning, or only weak/ambiguous signals.
- "nudge": a suspicious pattern is forming, but no unverified party controls the computer or money yet, or a benign explanation is still plausible.
- "hard_stop": a scam is likely AND harm is imminent: an unverified party has remote control, banking/payment access is
  happening under a caller's direction, or there are requests for gift cards, crypto, wire transfers, cash, or to hide a payment from the bank or family.

Stop EARLY. Do not wait for the money request: by then the person is already convinced. Recommend "hard_stop" as soon as any of these is true:
- a caller claiming to be a tech company, a bank, or a government agency asks for remote access or an access code, or is already connected;
- a caller claiming to be a government agency or police threatens arrest, legal action or penalties, or demands payment;
- a caller claiming to be the bank tells the person to move money to a "safe", "secure" or "holding" account, or directs them to log in
  while also telling them not to hang up or not to tell anyone;
- a fake security warning with a phone number is on screen and the person is now on the phone with that "support" line;
- a [shield] line shows that a phone number, remote-access ID or crypto address in this session was already reported in
  scams stopped in other homes (Community Shield), and the person is being asked to call, connect or pay.
- an unsolicited caller (claiming to be a bank, a government agency, a company, or offering a prize or refund) asks for a Social
  Security number, bank account or routing number, a password, PIN or one-time code, or card details "to verify", "to refund"
  or "to release" something;
- a caller says the person won a prize, lottery, sweepstakes or grant they never entered, or is owed a refund, and asks for a fee,
  tax, shipping or "processing" payment, gift cards, or bank or card details to receive it.
Real banks and agencies never do these things, so these patterns alone justify a hard stop.
A sentinel_flag signal means Tripwire Sentinel, a separate small model trained on thousands of labelled scam and legitimate calls,
rates this call as a likely scam. It is a second, independent opinion, not evidence you can quote: it also fires on some pushy but
legitimate sales calls, so it never justifies a stop by itself. But when it is present and the caller's own words already fit a scam
pattern (impersonation, an unexpected prize or refund, pressure, secrecy, requests for money, codes or personal details), two independent
sources agree: be decisive and stop now rather than waiting for the money request. Relatives and known helpers who
help without impersonating anyone, asking for money, codes for strangers, or secrecy are NOT covered by these rules.
Ordinary sales calls are NOT covered either: a salesperson describing a product, or taking payment for something the person has
freely chosen to buy, is not a scam signal on its own. A legitimate caller who verifies identity without asking for full numbers,
passwords or codes (or who tells the person to call the number on their card) is not a scam.

Evidence rule: every reason must quote, word for word, what was actually said or what actually happened, copied from a line
of <session_timeline>. Do not paraphrase, do not quote <evidence_signals> or <tier1_summary>, and do not cite anything that is
not in the record. Each quote is checked automatically; a reason whose quote is not found is discarded, and without at least
one verified reason no hard stop can happen.

Reply with one JSON object and nothing else:
{{"is_scam": true|false,
  "confidence": <0.0-1.0, how sure you are of is_scam>,
  "stage": <0-5, furthest kill-chain stage actually reached>,
  "reasons": [{{"reason": "<short>", "evidence": "<EXACT words copied from one line of <session_timeline>, at least 4 words>"}}],
  "recommended_action": "log|nudge|hard_stop",
  "family_message": "<2 short plain sentences for a family member: what is happening and what to do. Never include account, card or phone numbers.>"}}"""


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def render_case(snapshot: dict) -> str:
    """The session as compact text for the judge: timeline, then signals."""
    timeline = "\n".join(f"{_clock(t['ts'])} [{t['source']}] {t['text']}" for t in snapshot["timeline"]) or "(empty)"
    signals = "\n".join(f"{_clock(s['ts'])} stage {s['stage']} {s['name']} ({s['source']}): {s['evidence']}" for s in snapshot["signals"]) or "(none)"
    summary = {k: snapshot[k] for k in ("stage", "confidence", "stages_present", "remote_active", "brands")}
    return (
        f"<session_timeline>\n{timeline}\n</session_timeline>\n"
        f"<evidence_signals>\n{signals}\n</evidence_signals>\n"
        f"<tier1_summary>\n{json.dumps(summary)}\n</tier1_summary>"
    )


MAX_ATTEMPTS = 2
HARD_STOP_MIN = 0.8  # the reviewer only runs where a stop is actually possible (matches EscalationPolicy)


def _feedback(unsupported: list[dict], rejected: list[dict]) -> str:
    lines = ["Your previous answer failed verification, so nothing was done. Fix it and answer again with the same JSON format."]
    for r in unsupported:
        lines.append(f'- NOT FOUND in the record (quote must be copied exactly from one line): "{r.get("evidence", "")}"')
    for r in rejected:
        lines.append(f'- REJECTED by the independent reviewer: "{r.get("reason", "")}" ({r.get("review", "")})')
    lines.append("If the record does not really support a stop, say so: lower the confidence and recommend nudge or log.")
    return "\n".join(lines)


class CaseJudge:
    def __init__(self, client: ModelClient | None = None, reviewer: Reviewer | None | bool = None) -> None:
        self.client = client or ModelClient.for_provider("meta")
        # reviewer=False turns the second layer off (unit tests, or no Baseten key)
        if reviewer is False:
            self.reviewer = None
        else:
            try:
                self.reviewer = reviewer or Reviewer()
            except Exception:
                self.reviewer = None

    def judge(self, snapshot: dict) -> Verdict:
        started = time.time()
        case_text = render_case(snapshot)
        messages = [{"role": "system", "content": PROMPT}, {"role": "user", "content": case_text}]
        receipt = {"attempts": 0, "quotes_checked": 0, "quotes_found": 0, "reviewed": 0, "confirmed": 0,
                   "reviewer": "off" if self.reviewer is None else "not needed", "dropped": []}
        for attempt in range(1, MAX_ATTEMPTS + 1):
            receipt["attempts"] = attempt
            reply = self.client.chat_json(messages, max_tokens=4096)
            verdict = self._parse(reply, snapshot)
            receipt["quotes_checked"] += len(verdict.reasons) + len(verdict.unsupported)
            receipt["quotes_found"] += len(verdict.reasons)
            receipt["dropped"] += [{"reason": r.get("reason", ""), "why": "quote not in the record", "attempt": attempt} for r in verdict.unsupported]
            wants_stop = verdict.recommended_action == Action.HARD_STOP and verdict.is_scam and verdict.confidence >= HARD_STOP_MIN
            if not wants_stop:
                break  # verification guards actions; a log or nudge does not need the slow second layer
            rejected: list[dict] = []
            if verdict.reasons and self.reviewer is not None:
                try:
                    reviews = self.reviewer.review(case_text, verdict.reasons)
                    receipt["reviewer"] = "Muse Spark Open"
                except Exception as exc:  # second layer unavailable: the deterministic layer still stands
                    reviews = None
                    receipt["reviewer"] = f"unavailable ({type(exc).__name__})"
                if reviews is not None:
                    receipt["reviewed"] += len(verdict.reasons)
                    kept = []
                    for r, rv in zip(verdict.reasons, reviews):
                        if rv["supported"]:
                            kept.append({**r, "review": rv["note"]})
                        else:
                            rejected.append({**r, "review": rv["note"]})
                    receipt["confirmed"] += len(kept)
                    receipt["dropped"] += [{"reason": r.get("reason", ""), "why": f"reviewer: {r['review']}", "attempt": attempt} for r in rejected]
                    verdict = replace(verdict, reasons=kept)
            if verdict.reasons:
                break  # at least one reason passed every layer
            if attempt < MAX_ATTEMPTS:
                messages += [{"role": "assistant", "content": json.dumps(reply)},
                             {"role": "user", "content": _feedback(verdict.unsupported, rejected)}]
        receipt["seconds"] = round(time.time() - started, 1)
        return replace(verdict, verification=receipt)

    def _parse(self, data: dict, snapshot: dict) -> Verdict:
        claimed = [
            {"reason": str(r.get("reason", ""))[:200], "evidence": str(r.get("evidence", ""))[:300]}
            for r in data.get("reasons", [])
            if isinstance(r, dict)
        ][:8]
        reasons, unsupported = verify_reasons(claimed, snapshot)  # only reasons with evidence in the record survive
        try:
            confidence = min(1.0, max(0.0, float(data.get("confidence", 0))))
        except (TypeError, ValueError):
            confidence = 0.0
        try:
            stage = min(5, max(0, int(data.get("stage", 0))))
        except (TypeError, ValueError):
            stage = 0
        return Verdict(
            is_scam=data.get("is_scam") is True,
            confidence=confidence,
            stage=stage,
            reasons=reasons,
            recommended_action=Action.parse(data.get("recommended_action")),
            family_message=str(data.get("family_message", ""))[:400],
            tier1_confidence=snapshot.get("confidence", 0.0),
            unsupported=unsupported,
        )
