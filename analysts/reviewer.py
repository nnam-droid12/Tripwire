"""The Reviewer: a second, independent model checks the judge's reasons.

Verification has two layers. The first is deterministic (:mod:`core.grounding`):
the quote behind every reason must really be in the record. That proves the
judge did not invent evidence, but not that the evidence *means* what the judge
says: "send me the code" is a real line in both a scam and a grandson asking
for a Wi-Fi password. The second layer asks a different model, Muse Spark Open,
which never saw the judge's reasoning, whether each quote supports its reason in
context.

It runs only at the crucial checkpoint, when the judge's verdict would stop the
call, because each check adds latency. The reviewer can only remove reasons,
never add them; if it is unreachable, the deterministic layer still stands and
the receipt says so.
"""

from __future__ import annotations

from analysts.common import SAFETY_RULES
from core.model_client import ModelClient

PROMPT = f"""{SAFETY_RULES}

You are the Reviewer, an independent check on another model's decision to stop a phone call as a scam.
You get the record of the session and a numbered list of claims. Each claim is a reason plus the exact line of the record it rests on.
For each claim decide only one thing: read in the context of the whole record, does that line really show what the reason says?
- Supported: the line, in context, is evidence for the reason (who said it and what they asked for matter).
- Not supported: the line is about something else, was said by the protected person rather than the caller, is a harmless request
  from a known relative or helper, or the reason exaggerates it.
Do not judge whether the call is a scam overall; judge each claim on its own.

Reply with one JSON object and nothing else:
{{"claims": [{{"n": <claim number>, "supported": true|false, "note": "<at most 12 words>"}}]}}"""


class Reviewer:
    def __init__(self, client: ModelClient | None = None) -> None:
        self.client = client or ModelClient.for_provider("baseten")

    def review(self, case_text: str, reasons: list[dict]) -> list[dict]:
        """Return ``[{"supported": bool, "note": str}]``, one per reason, in order."""
        claims = "\n".join(f"{i + 1}. reason: {r.get('reason', '')}\n   line: {r.get('source') or r.get('evidence', '')}" for i, r in enumerate(reasons))
        messages = [
            {"role": "system", "content": PROMPT},
            {"role": "user", "content": f"{case_text}\n<claims>\n{claims}\n</claims>"},
        ]
        data = self.client.chat_json(messages, max_tokens=3000)
        by_n = {}
        for c in data.get("claims", []):
            if isinstance(c, dict):
                try:
                    by_n[int(c.get("n"))] = c
                except (TypeError, ValueError):
                    continue
        # a claim the reviewer skipped is not confirmed
        return [
            {"supported": by_n.get(i + 1, {}).get("supported") is True, "note": str(by_n.get(i + 1, {}).get("note", "not reviewed"))[:120]}
            for i in range(len(reasons))
        ]
