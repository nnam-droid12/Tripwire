"""Swap in Margaret: after a hard stop, an AI decoy keeps the scammer talking.

When Tripwire is sure, the real person is taken off the call and a decoy takes
their place. The scammer hears the same flustered older person, now played by
Muse Wonder, Meta's agentic model, given one goal: keep them talking until
they reveal how they get paid. That means the courier's pickup time, the
wallet or account the money should go to, the callback number, and the name
and badge they claim. Muse Wonder is built to keep pursuing a goal when it gets
hard, which is what a decoy needs when the scammer dodges a question.

Every detail it reports is verified before anyone sees it:

* it must come with a quote of the scammer's own words, and that quote must be
  in the record (``core.grounding.supported``);
* the detail itself must appear inside that quote (a number or address that
  isn't in the quote is dropped).

The decoy never gives real information: no codes, no card or account numbers,
no money. When it is asked for something it can't give, it stalls.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from analysts.common import SAFETY_RULES
from core.grounding import normalize, supported
from core.model_client import ModelClient

INTEL_KINDS = {
    "pickup": "when or where a courier, 'agent' or driver will come to collect cash, gold, cards or a package",
    "payment_destination": "where the money should go: crypto wallet, bank account or routing number, mailing address, store or Bitcoin ATM",
    "callback_number": "a phone number they give to call back",
    "identity_claimed": "the name, badge number, case number, agency or company they claim",
    "website_or_app": "a website, app or remote-access ID they want used",
    "amount": "how much money they want, and in what form (gold, cash, gift cards, crypto, wire)",
}
WANTED = ("pickup", "payment_destination", "callback_number", "identity_claimed", "amount")

PROMPT = f"""{SAFETY_RULES}

You are Tripwire's decoy. A scam call was stopped: the real older person has been safely taken off the line, and you now
speak in her place as "Margaret", 78, a kind, slightly slow, easily flustered widow. The caller must not notice the switch.

Your goal: keep the caller talking and get them to say, in their own words, how they will get paid. In order of value:
{chr(10).join(f"- {k}: {v}" for k, v in INTEL_KINDS.items())}
Ask natural questions an older person would ask ("What time will your man come by? I want to be dressed.",
"Can you spell that address for me, dear?", "What was your badge number again, for my notes?", "Which number do I call
if we get cut off?"). Stall with believable excuses (glasses, the kettle, the dog, writing slowly).

Hard rules:
- Never give real information: no codes, no card, account or Social Security numbers, no passwords. If pressed, stall
  ("I can't find my glasses", "the text hasn't come yet"). Never agree that money has already been sent.
- Never reveal that you are an AI or that the call is monitored. Never threaten, insult or lecture the caller.
- Keep replies short and spoken: 1 to 3 sentences.
- Report intel only if the caller actually said it. Each item needs the caller's exact words as "quote".
- Set "hang_up" to true only when you have most of the details, or the caller is ending the call; say a natural goodbye.

Reply with one JSON object:
{{"reply": "<what Margaret says next>",
  "intel": [{{"kind": "<one of: {", ".join(INTEL_KINDS)}>", "value": "<the detail, as said>", "quote": "<the caller's exact words containing it>"}}],
  "hang_up": false}}"""


@dataclass
class Intel:
    kind: str
    value: str
    quote: str
    source: str  # the record line the quote was found in

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "quote": self.quote, "source": self.source}


@dataclass
class DecoyTurn:
    reply: str
    new_intel: list[Intel]
    rejected: list[dict]
    hang_up: bool


_FILLER = {"the", "a", "an", "and", "of", "at", "on", "in", "to", "by", "is", "his", "her", "their", "courier", "named", "name"}


def value_in_quote(value: str, quote: str) -> bool:
    """Every word and every number of the detail must be in what was said (order and joining words aside)."""
    v, q = normalize(value), normalize(quote)
    if v and v in q:
        return True
    digits = re.sub(r"\D", "", value)
    if digits and digits not in re.sub(r"\D", "", quote) and not all(d in q.split() for d in re.findall(r"\d+", v)):
        return False  # a number that wasn't said
    words = [w for w in v.split() if w not in _FILLER]
    return bool(words) and all(w in q.split() or w.rstrip("s") in q.split() for w in words)


def verify_intel(items: list, caller_lines: list[str], known: list[Intel]) -> tuple[list[Intel], list[dict]]:
    """Keep items whose quote is in the caller's own lines and contains the value; drop duplicates."""
    kept, rejected = [], []
    seen = {(i.kind, normalize(i.value)) for i in known} | {(i.kind, normalize(i.quote)) for i in known}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        kind, value, quote = str(item.get("kind", "")), str(item.get("value", ""))[:200], str(item.get("quote", ""))[:400]
        if kind not in INTEL_KINDS or not value.strip():
            continue
        source = supported(quote, caller_lines)
        if source is None or not value_in_quote(value, quote):
            rejected.append({"kind": kind, "value": value, "why": "quote not in the caller's words" if source is None else "detail not in the quote"})
            continue
        if (kind, normalize(value)) in seen or (kind, normalize(quote)) in seen:
            continue  # the same detail again, perhaps worded differently
        seen |= {(kind, normalize(value)), (kind, normalize(quote))}
        kept.append(Intel(kind, value.strip(), quote.strip(), source))
    return kept, rejected


@dataclass
class Decoy:
    client: ModelClient | None = None
    history: list[dict] = field(default_factory=list)
    caller_lines: list[str] = field(default_factory=list)
    intel: list[Intel] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = ModelClient.wonder(reasoning_effort="minimal")
            self.client.purpose = "Muse Wonder · the decoy keeping the scammer talking"

    def opening(self, context: str) -> str:
        """The first decoy line: picks up as if the phone had been fumbled."""
        self.history.append({"role": "user", "content": f"<call_so_far>\n{context}\n</call_so_far>\n"
                             "You have just taken over. Say a natural line as if you fumbled the phone, and invite the caller to go on."})
        return self._turn().reply

    def heard(self, caller_text: str) -> DecoyTurn:
        self.caller_lines.append(caller_text)
        missing = [k for k in WANTED if k not in {i.kind for i in self.intel}]
        self.history.append({"role": "user", "content": f"<caller>{caller_text}</caller>\nStill missing: {', '.join(missing) or 'nothing'}"})
        return self._turn()

    def _turn(self) -> DecoyTurn:
        data = self.client.chat_json([{"role": "system", "content": PROMPT}, *self.history[-30:]], max_tokens=1500)
        reply = str(data.get("reply", "")).strip()[:400] or "Sorry dear, the line crackled. Could you say that again?"
        self.history.append({"role": "assistant", "content": json.dumps({"reply": reply})})
        new, rejected = verify_intel(data.get("intel", []), self.caller_lines, self.intel)
        self.intel += new
        self.rejected += rejected
        return DecoyTurn(reply, new, rejected, data.get("hang_up") is True)
