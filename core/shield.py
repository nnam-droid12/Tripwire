"""Community Shield: what one stopped scam teaches every other home.

When Tripwire stops a scam, the *scammer's* identifiers seen during it (the
phone number to call back, the remote-access ID they connect from, the crypto
address they want paid) are added to a shared list. Nothing about the
victim is ever added: no names, account or card numbers, and no text.

Afterwards, whenever one of those identifiers appears on another person's
screen or in their call, Tripwire flags it at once. It is an exact match
against reports, so it is ground truth, not a model's opinion.

This module is pure logic (extract, normalise, match); storage lives in
``backend/shield.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# phone numbers as people write or say them: +1 (555) 013-4477, 555-013-4477, 1 555 013 4477
_PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
# remote-access IDs read out or shown: 9 to 10 digits in groups of 3 ("482 113 907")
_REMOTE_ID = re.compile(r"(?<!\d)\d{3}[\s-]\d{3}[\s-]\d{3,4}(?!\d)")
_CRYPTO = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")


@dataclass(frozen=True)
class Indicator:
    kind: str  # phone | remote_id | crypto
    value: str  # normalised form used for matching

    @property
    def display(self) -> str:
        if self.kind == "phone":
            v = self.value
            return f"+1 ({v[:3]}) {v[3:6]}-{v[6:]}"
        if self.kind == "remote_id":
            return " ".join(self.value[i:i + 3] for i in range(0, len(self.value), 3))
        return f"{self.value[:6]}…{self.value[-4:]}"


def extract(text: str) -> set[Indicator]:
    """Scammer-side identifiers in a line of text (call transcript, screen description, system event)."""
    found: set[Indicator] = set()
    for m in _PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))[-10:]
        if len(digits) == 10:
            found.add(Indicator("phone", digits))
    for m in _REMOTE_ID.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if not any(i.kind == "phone" and digits in i.value for i in found):
            found.add(Indicator("remote_id", digits))
    for m in _CRYPTO.finditer(text):
        found.add(Indicator("crypto", m.group(0)))
    return found


def from_incident(timeline: list[dict], protected_ids: set[str] = frozenset()) -> set[Indicator]:
    """Indicators to learn from a stopped scam: the scammer's side only.

    The protected person's own words are skipped (they may read out their own
    phone number or remote-access address), and remote-access IDs are taken
    only from the screen or connection data, never from speech. ``protected_ids``
    are identifiers known to belong to the protected person; they are never shared.
    """
    found: set[Indicator] = set()
    for t in timeline:
        source, text = t.get("source"), t.get("text", "")
        if source == "call":
            if "(protected_person)" in text:
                continue
            found |= {i for i in extract(text) if i.kind != "remote_id"}
        elif source in ("screen", "network", "process", "clipboard"):
            found |= extract(text)
    return {i for i in found if i.value not in protected_ids}
