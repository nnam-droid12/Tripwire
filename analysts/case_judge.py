"""CaseJudge (Tier 2): weighs the whole session and returns the verdict.

Called only on escalation. It receives the entire session (every frame
description, transcript line, system event and signal) and reasons about
the *story*, which is where Muse Spark's long context earns its place: the
difference between a scam and a grandson helping with online banking is
rarely visible in any single moment.

It is the only component allowed to recommend ``hard_stop``, and even then
:class:`core.policy.EscalationPolicy` checks its confidence before acting.
"""

from __future__ import annotations

import json
from datetime import datetime

from analysts.common import SAFETY_RULES
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

Reply with one JSON object and nothing else:
{{"is_scam": true|false,
  "confidence": <0.0-1.0, how sure you are of is_scam>,
  "stage": <0-5, furthest kill-chain stage actually reached>,
  "reasons": [{{"reason": "<short>", "evidence": "<quote or event from the record>"}}],
  "recommended_action": "log|nudge|hard_stop",
  "family_message": "<2 short plain sentences for a family member: what is happening and what to do. Never include account, card or phone numbers.>",
  "senior_message": "<one calm, kind sentence to be spoken aloud to the protected person, e.g. 'Just so you know, Microsoft never phones people about viruses.' No numbers.>"}}"""


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


class CaseJudge:
    def __init__(self, client: ModelClient | None = None) -> None:
        self.client = client or ModelClient.for_provider("meta")

    def judge(self, snapshot: dict) -> Verdict:
        messages = [{"role": "system", "content": PROMPT}, {"role": "user", "content": render_case(snapshot)}]
        data = self.client.chat_json(messages, max_tokens=4096)
        reasons = [
            {"reason": str(r.get("reason", ""))[:200], "evidence": str(r.get("evidence", ""))[:300]}
            for r in data.get("reasons", [])
            if isinstance(r, dict)
        ][:8]
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
            senior_message=str(data.get("senior_message", ""))[:300],
            tier1_confidence=snapshot.get("confidence", 0.0),
        )
