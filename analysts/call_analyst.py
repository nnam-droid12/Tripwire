"""CallAnalyst (Tier 1): turns call transcript lines into signals.

Each new transcript turn is analysed together with the recent conversation,
because coercion is usually spread over several lines ("I'm from Microsoft"
... "download this" ... "don't tell your bank"). Besides kill-chain signals it
works out which diarized speaker is the caller and which is the protected
person, so a scam line is never attributed to the victim.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from analysts.common import SAFETY_RULES, clean_brands, clean_risk, clean_signals, signal_menu
from core.model_client import ModelClient

PROMPT = f"""{SAFETY_RULES}

You are analysing a phone call on speakerphone between the protected person (usually an older adult) and a caller.
Speaker labels (A, B, ...) come from automatic diarization and may occasionally be wrong.

{signal_menu()}

Judge the NEWEST line in the context of the recent lines. Report a signal only if the newest line provides evidence for it
(it may complete a pattern begun earlier). Pay special attention to coercion: urgency, secrecy, coaching the person what
to say, claims of authority, and instructions to close warnings or turn off protection.

Reply with one JSON object and nothing else:
{{"risk": "none|low|med|high",
  "roles": {{"<speaker label>": "caller|protected_person|unknown"}},
  "brands": ["<organisations the CALLER claims to represent>"],
  "signals": [{{"signal": "<allowed name>", "evidence": "<short quote>"}}],
  "note": "<one short sentence on what is happening>"}}"""


@dataclass(frozen=True)
class CallFinding:
    risk: str
    roles: dict[str, str]
    brands: list[str]
    signals: list[tuple[str, str]]
    note: str


class CallAnalyst:
    def __init__(self, client: ModelClient | None = None, context_turns: int = 12) -> None:
        self.client = client or ModelClient.for_provider("baseten")
        self.history: deque[str] = deque(maxlen=context_turns)

    def analyze(self, speaker: str | None, text: str) -> CallFinding:
        earlier = "\n".join(self.history) or "(none)"
        line = f"{speaker or '?'}: {text}"
        self.history.append(line)
        messages = [
            {"role": "system", "content": PROMPT},
            {"role": "user", "content": f"<transcript_earlier>\n{earlier}\n</transcript_earlier>\n<transcript_newest>\n{line}\n</transcript_newest>"},
        ]
        data = self.client.chat_json(messages)
        roles = data.get("roles") if isinstance(data.get("roles"), dict) else {}
        return CallFinding(
            risk=clean_risk(data.get("risk")),
            roles={str(k): str(v) for k, v in roles.items()},
            brands=clean_brands(data.get("brands")),
            signals=clean_signals(data.get("signals")),
            note=str(data.get("note", ""))[:300],
        )
