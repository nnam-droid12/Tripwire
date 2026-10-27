"""Scammer-resistance rules for an active hard stop.

* The warning can be dismissed with the family PIN at any time, or by the
  senior after a cooldown (60 s by default). The cooldown gives the senior
  time to hear the warning and hang up before anyone can talk them past it.
* If the call contains an instruction to close or disable Tripwire while the
  warning is up ("close that box", "turn it off", "uninstall it"), that is
  itself scam evidence: the cooldown restarts and Tripwire says so out loud.
"""

from __future__ import annotations

import re
import time
from typing import Callable

from core.settings import Settings

_VERB = r"(?:close|shut|ignore|dismiss|uninstall|remove|delete|disable|kill|exit|quit|x\s*out)"
_NOUN = r"(?:program|app|application|software|window|box|warning|message|alert|screen|pop-?up|antivirus|security|protection|tripwire|thing)s?"
_PRONOUN_END = r"(?:it|that|this|them|those)(?=\s*(?:[.,!?;]|$|now|down|off|out|please|right|for\b|and\b|so\b))"
DISABLE_PATTERN = re.compile(
    rf"\b{_VERB}\b\s+(?:(?:of\s+)?(?:the|that|this|those|your)\s+)?(?:\w+\s+)?{_NOUN}\b"  # "close that box", "x out of that window"
    rf"|\b{_VERB}\b\s+{_PRONOUN_END}"  # "uninstall it now", "close that, it's the virus"
    rf"|\b(?:turn|switch)\s+(?:it|that|this|the\s+\w+|your\s+\w+)\s+off\b"
    rf"|\bdon'?t\s+(?:listen\s+to|worry\s+about|pay\s+attention\s+to)\s+(?:it|that|this|the)\b",
    re.I,
)


def is_disable_instruction(text: str) -> bool:
    """True if a call line tells the person to close, ignore or disable something."""
    return bool(DISABLE_PATTERN.search(text))


class DismissGate:
    """Decides when an active hard stop may be dismissed."""

    def __init__(self, settings: Settings, clock: Callable[[], float] = time.monotonic) -> None:
        self.settings = settings
        self.clock = clock
        self._started = clock()

    def restart_cooldown(self) -> None:
        self._started = self.clock()

    def seconds_left(self) -> float:
        return max(0.0, self.settings.cooldown_s - (self.clock() - self._started))

    def can_self_dismiss(self) -> bool:
        return self.seconds_left() <= 0

    def try_pin(self, pin: str) -> bool:
        return self.settings.check_pin(pin)
