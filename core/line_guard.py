"""Line Lock: rules against scams that turn the phone line itself against the victim.

Two telephone tricks get around "never read a code to anyone":

* **Call merging.** The scammer has the bank send a voice one-time code, then
  asks the victim to merge "the verification department" into the call. That
  incoming call is the bank's own automated voice reading the code, and once
  merged the scammer hears it. The victim never says a digit.
* **Call forwarding.** The scammer has the victim dial a "security code" that is
  really a carrier forwarding code (``*72`` + number, ``**21*``...). From then on
  the bank's verification calls ring the scammer's phone.

These are rules, not model judgements (no legitimate caller asks for either),
so they fire on the words themselves:

* ``merge_request``: the caller asks to merge, add or conference in a call;
* ``forwarding_instruction``: the caller asks to dial a forwarding code or to
  forward calls;
* ``bank_code_voice``: an automated bank voice starts announcing a code. It is
  checked on partial transcripts of what the *scammer can hear*, so it fires on
  the opening words, before the digits are read.
"""

from __future__ import annotations

import re

_MERGE = [
    re.compile(r"\b(?:merge|merging)\b[^.?!]{0,40}\b(?:call|calls|line|lines|it|them|in|together)\b", re.I),
    re.compile(r"\b(?:tap|press|hit|click|touch)\b[^.?!]{0,15}\bmerge\b", re.I),
    re.compile(r"\b(?:add|conference|patch|join|bring)\b(?: (?:the|this|that|them|it|him|her|my colleague|our department))?[^.?!]{0,20}\b(?:in|into|to) (?:the|this|our) (?:call|line|conversation)\b", re.I),
    re.compile(r"\b(?:add call|conference call|three[- ]way call)\b", re.I),
    re.compile(r"\b(?:accept|answer|pick up)\b[^.?!]{0,40}\b(?:other|second|incoming|new) call\b[^.?!]{0,40}\b(?:merge|add|join|together|stay on)\b", re.I),
]
_STAR_CODE = r"(?:\*|star)\s*(?:7\s*2|seven\s+two|2\s*1|two\s+one|6\s*[127]|six\s+(?:one|two|seven)|0\s*0\s*4|zero\s+zero\s+four|4\s*0\s*1|four\s+zero\s+one)\b"
_FORWARD = [
    re.compile(rf"\b(?:dial|press|type|enter|key in|punch in|put in)\b[^.?!]{{0,40}}{_STAR_CODE}", re.I),
    re.compile(r"(?:\*\s*\*|star\s+star)\s*(?:2\s*1|two\s+one|6\s*[127]|0\s*0\s*[24])", re.I),
    re.compile(r"\b(?:set up|turn on|activate|enable)\b[^.?!]{0,30}\b(?:call forwarding|forwarding)\b", re.I),
    re.compile(r"\bforward (?:your|all your|all) (?:calls|phone calls|incoming calls)\b", re.I),
]
_BANK_VOICE = [
    re.compile(r"\b(?:this is an? |an )?automated (?:call|message|security call|verification call|voice)\b[^.?!]{0,60}\b(?:bank|card|account|credit union|verification|security|code|passcode)\b", re.I),
    re.compile(r"\byour (?:one[- ]time |verification |security |authentication |access )?(?:passcode|pass code|code|password|pin) is\b", re.I),
    re.compile(r"\b(?:one[- ]time|verification|security) (?:passcode|code|password)\b[^.?!]{0,20}\b(?:is|for your)\b", re.I),
]


def merge_request(text: str) -> bool:
    """The caller asks to merge, add or conference another call into this one."""
    return any(p.search(text) for p in _MERGE)


def forwarding_instruction(text: str) -> bool:
    """The caller asks to dial a call-forwarding code, or to forward calls."""
    return any(p.search(text) for p in _FORWARD)


def bank_code_voice(text: str) -> bool:
    """An automated bank voice is announcing a code (works on partial transcripts)."""
    return any(p.search(text) for p in _BANK_VOICE)


UNDO_FORWARDING = "dial star seven three, or pound pound zero zero two pound, to switch call forwarding off"
