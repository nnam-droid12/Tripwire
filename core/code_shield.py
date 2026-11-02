"""Code Shield: the one-time code is the key to the account; it must never be read out to a caller.

"Read me the code we just sent you" is how most bank accounts are drained: the
scammer is logging in as the victim, the bank texts the victim a one-time code,
and the victim reads it to the "bank" on the phone. No legitimate caller ever
needs that code, so this is a deterministic rule, not a model's judgement: it
fires on the caller's own words, in milliseconds, before the person has time
to answer.

``code_request`` matches the caller asking for a code. ``code_message`` matches
a text message that carries a one-time code (for "a code arrived during a call
with a stranger").
"""

from __future__ import annotations

import re

_CODE_WORDS = r"(?:(?:one[- ]time|verification|security|confirmation|authori[sz]ation|access|login|log-in|sign[- ]in|bank|six[- ]digit|6[- ]digit|four[- ]digit|4[- ]digit|texted|text|sms)\s*(?:code|passcode|pin)|(?:one[- ]time|verification)\s*number|passcode|otp)"
_CODE_NOUN = r"(?:code|passcode|one[- ]time (?:pin|password)|otp|pin)"
_ASK = r"(?:read|tell|give|say|send|share|provide|confirm|repeat|verify|need|want|what(?:'s| is)|got|received|get)"

_REQUEST = [
    re.compile(rf"\b{_ASK}\b(?!\s+you\b)[^.?!]{{0,60}}\b{_CODE_WORDS}\b", re.I),  # "give you our code" is an offer, not a request
    re.compile(rf"\b{_ASK}\b[^.?!]{{0,40}}\bthe {_CODE_NOUN}\b[^.?!]{{0,40}}\b(?:sent|texted|received|got|on your (?:phone|screen)|we (?:just )?sent)", re.I),
    re.compile(rf"\b{_CODE_NOUN}\b[^.?!]{{0,40}}\b(?:we|i|the bank) (?:just )?(?:sent|texted)\b", re.I),
    re.compile(r"\b(?:digits|numbers) (?:we|i) (?:just )?(?:sent|texted)\b", re.I),
    re.compile(rf"\b(?:sent|texted|sending|texting) you (?:a|the|an)\b[^.?!]{{0,25}}\b{_CODE_NOUN}\b[^.?!]{{0,40}}(?:\bwhat\b|\bread\b|\btell me\b|\bgive me\b|\?)", re.I),
]
_MESSAGE = re.compile(rf"\b(?:{_CODE_NOUN}|code is|verification)\b[^\n]{{0,60}}\b\d{{4,8}}\b|\b\d{{4,8}}\b[^\n]{{0,40}}\b(?:is your|code)\b", re.I)


_SENT_CODE = re.compile(rf"\b(?:sent|texted|sending|texting)\b[^?!]{{0,40}}\b{_CODE_NOUN}\b", re.I)
_READ_IT = re.compile(r"\b(?:read|repeat)\s+(?:it|them|that|those|the (?:code|numbers|digits))\b"
                      r"|\b(?:tell|give|say|confirm)\s+(?:it|them|that|those|the (?:code|numbers|digits))\s+(?:to me|back|out)\b", re.I)


def code_request(text: str) -> bool:
    """The caller is asking for a one-time / verification code."""
    if any(p.search(text) for p in _REQUEST):
        return True
    # "I've just sent a code to your phone. Read it to me." (the request in the next sentence)
    return bool(_SENT_CODE.search(text) and _READ_IT.search(text))


def code_message(text: str) -> bool:
    """A text message that carries a one-time code."""
    return bool(_MESSAGE.search(text))
