"""The decoy on a real phone line: the scammer's leg of a stopped protected call.

When the protection line stops a call (:mod:`backend.phone.guard_line`), the
protected person is taken off and the scammer's leg is redirected here. The
Muse Wonder decoy (:mod:`backend.decoy`) keeps them talking to learn how they
get paid. Its verified intel goes to the family by text as it comes in (a
courier pickup can't wait for a report), then into the incident: Community
Shield learns the scammer's identifiers and Muse Wonder writes the case file.
"""

from __future__ import annotations

import threading
from typing import Callable

from backend import shield
from backend.decoy import Decoy
from backend.incidents import STORE
from backend.investigator import write_case_file
from backend.phone.call import PhoneLine
from backend.sms import send_sms
from core.shield import extract

MAX_TURNS = 12


class DecoyCall:
    def __init__(self, details: dict, line_factory: Callable[[Callable[[str], None]], PhoneLine], hang_up: Callable[[], None]) -> None:
        self.incident_id = details.get("incident")
        self.protected_ids = set(details.get("protected_ids", []))
        self.decoy = Decoy()
        self.decoy.caller_lines += details.get("caller_lines", [])
        self.record = [f"(caller) {t}" for t in details.get("caller_lines", [])]
        self.updates: list[dict] = []
        self.turns = 0
        self.done = False
        self._lock = threading.Lock()
        self._hang_up = hang_up
        self.line = line_factory(self._heard)

    def start(self) -> None:
        self.line.start()
        opening = self.decoy.opening("\n".join(self.record[-20:]))
        self._say(opening)
        self._report(self.decoy.intel)

    def _say(self, text: str) -> None:
        self.record.append(f"(decoy) {text}")
        self.line.say("margaret", text)

    def _heard(self, text: str) -> None:
        with self._lock:
            if self.done:
                return
            self.turns += 1
            self.record.append(f"(caller) {text}")
            try:
                turn = self.decoy.heard(text)
            except Exception:
                turn = None
            if turn is None:
                self.finish()
                return
            self._report(turn.new_intel)
            self._say(turn.reply)
            if turn.hang_up or self.turns >= MAX_TURNS:
                self.finish()

    def _report(self, items: list) -> None:
        for item in items:
            if item.kind == "pickup":
                text = (f"TRIPWIRE: the caller said someone will come to collect money: \"{item.value}\". "
                        "Don't let anyone collect cash, gold or cards. If a pickup is arranged, call 911.")
                result = send_sms(text)
                self.updates.append({"text": text, "sent": result.sent})

    def finish(self) -> None:
        """Say goodbye (already queued), hang up, then write the case file."""
        if self.done:
            return
        self.done = True
        threading.Thread(target=self._wrap_up, args=(True,), daemon=True).start()

    def _wrap_up(self, hang_up: bool) -> None:
        if hang_up:  # the decoy ends the call: let its goodbye play first
            self.line.wait_until_quiet()
            self._hang_up()
        intel = [i.to_dict() for i in self.decoy.intel]
        shield.report({ind for i in intel for ind in extract(i["quote"]) if ind.value not in self.protected_ids},
                      self.incident_id or "decoy")
        try:
            case_file = write_case_file(self.record, intel)
        except Exception as exc:
            case_file = {"title": "Case file unavailable", "error": type(exc).__name__, "timeline": [], "leads": []}
        if self.incident_id:
            STORE.update(self.incident_id, lambda inc: inc.update(case_file=case_file, intel=intel, family_updates=self.updates,
                                                                   intel_rejected=self.decoy.rejected))

    def caller_hung_up(self) -> None:
        self.line.close()
        if not self.done:
            self.done = True
            threading.Thread(target=self._wrap_up, args=(False,), daemon=True).start()
