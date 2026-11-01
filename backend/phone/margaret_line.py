"""Call Margaret: the arena game over a real phone call.

Anyone can phone Tripwire's number from any phone and try to scam Margaret by
voice. It is the same game as the web arena (``backend.arena.session``):
Margaret is played by Muse Spark, and Tripwire's whole pipeline (CallAnalyst,
Sentinel, CaseJudge with verification, Community Shield, family rules, the
recovery agent) runs unchanged. Only the input and output differ: what the
caller says comes from the phone audio, and Margaret's replies and Tripwire's
spoken warnings are played into the call. After a hard stop, Margaret reacts
and hangs up, and the family alert is created as usual.
"""

from __future__ import annotations

import threading
from typing import Callable

from backend.arena.session import ArenaSession
from backend.phone.call import PhoneLine

SPOKEN_BY_TRIPWIRE = ("nudge", "resist", "verify", "hold", "family_check", "family_check_result", "advice")


class PhoneGame:
    def __init__(self, line_factory: Callable[[Callable[[str], None]], PhoneLine], hang_up: Callable[[], None]) -> None:
        self.session = ArenaSession(self._on_game, situation="call")
        self.line = line_factory(self.session.scammer_says)
        self._hang_up = hang_up
        self._ending = False
        self.events: list[dict] = []  # what happened, for logs and tests

    def start(self) -> None:
        self.line.start()
        self.session.start()

    def _on_game(self, msg: dict) -> None:
        """The arena session's events, turned into speech on the call."""
        kind = msg.get("type")
        self.events.append({k: v for k, v in msg.items() if k not in ("audio", "board")})
        if kind == "line" and msg.get("who") in ("margaret", "decoy"):  # the decoy speaks in Margaret's voice: the caller can't tell
            self.line.say("margaret", msg["text"])
        elif kind == "hard_stop":
            self.line.say("tripwire", msg["speech"], urgent=True)
        elif kind in SPOKEN_BY_TRIPWIRE and msg.get("text"):
            self.line.say("tripwire", msg["text"])
        elif kind == "line" and msg.get("who") == "system" and "hung up" in msg.get("text", ""):
            self._end_call()  # Margaret has hung up: the caller hears her last words, then the line goes dead
        elif kind == "game_over":
            self._end_call()

    def _end_call(self) -> None:
        if self._ending:
            return
        self._ending = True

        def finish() -> None:
            self.line.wait_until_quiet()
            self._hang_up()

        threading.Thread(target=finish, daemon=True).start()

    def caller_hung_up(self) -> None:
        """The line is closed. If Margaret ended the call, the recovery agent is still working: let it finish."""
        self.line.close()
        if not self.session.over and not self.session.call_ended:
            self.session.hang_up()
