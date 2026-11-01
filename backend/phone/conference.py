"""The protected call as a conference: the scammer and the protected person, with Tripwire in control.

A plain bridged call can only be listened to. A conference lets Tripwire act
on one side without the other knowing:

* **whisper**: an announcement only the protected person hears (the opening
  check, gentle nudges mid-call, the explanation after a stop);
* **hold** the caller while Tripwire speaks privately;
* **mute** the protected person's side, so the caller stops hearing anything
  from their phone, including a bank's code call merged in on the handset.

Every call is one REST request; failures are reported, never raised, because
the person's safety never depends on a single request succeeding.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from backend.phone import twilio_api

JOIN_WAIT_S = 45


class ConferenceLine:
    def __init__(self, name: str, caller_sid: str, tripwire_number: str, protected_number: str,
                 clip_url: Callable[[str], str | None], on_error: Callable[[str], None] = lambda _: None) -> None:
        self.name, self.caller_sid = name, caller_sid
        self.tripwire_number, self.protected_number = tripwire_number, protected_number
        self.clip_url, self.on_error = clip_url, on_error
        self.sid: str | None = None  # the conference, once it has started
        self.protected_sid: str | None = None  # the protected person's leg
        self.joined = threading.Event()

    def _try(self, what: str, fn: Callable[[], object]) -> bool:
        try:
            fn()
            return True
        except Exception as exc:
            self.on_error(f"conference {what} failed: {type(exc).__name__}")
            return False

    def connect(self, whisper: str) -> None:
        """Ring the protected person; when they join, hold the caller and whisper the opening check."""
        def dial() -> None:
            self.protected_sid = twilio_api.add_participant(
                self.name, self.tripwire_number, self.protected_number, Label="protected", Beep="false",
                StartConferenceOnEnter="true", EndConferenceOnExit="false", Timeout="25")
        if not self._try("dial", dial):
            return
        deadline = time.time() + JOIN_WAIT_S
        while time.time() < deadline and not self.joined.is_set():
            try:
                self.sid = self.sid or twilio_api.conference_sid(self.name)
                if self.sid and self.protected_sid in twilio_api.participant_sids(self.sid):
                    self.joined.set()
                    break
            except Exception:
                pass
            time.sleep(1)
        if not self.joined.is_set():
            return
        self.hold_caller(True)
        self.whisper(whisper)
        time.sleep(6)  # the opening check is about five seconds long
        self.hold_caller(False)

    def whisper(self, text: str) -> bool:
        """Say something only the protected person hears."""
        url = self.clip_url(text)
        if not (url and self.sid and self.protected_sid):
            return False
        return self._try("whisper", lambda: twilio_api.update_participant(self.sid, self.protected_sid, AnnounceUrl=url,
                                                                          AnnounceMethod="GET"))

    def hold_caller(self, on: bool) -> bool:
        if not self.sid:
            return False
        return self._try("hold", lambda: twilio_api.update_participant(self.sid, self.caller_sid, Hold="true" if on else "false"))

    def mute_protected(self) -> bool:
        """The caller stops hearing anything from the protected phone, a merged call included."""
        if not (self.sid and self.protected_sid):
            return False
        return self._try("mute", lambda: twilio_api.update_participant(self.sid, self.protected_sid, Muted="true"))

    def take_protected_out(self, twiml: str) -> bool:
        """The protected person leaves the call (to a spoken warning); the caller stays, alone."""
        if not self.protected_sid:
            return False
        return self._try("remove", lambda: twilio_api.redirect(self.protected_sid, twiml))

    def redirect_caller(self, twiml: str) -> bool:
        return self._try("redirect caller", lambda: twilio_api.redirect(self.caller_sid, twiml))
