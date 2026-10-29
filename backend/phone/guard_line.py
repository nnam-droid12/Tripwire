"""The protection line: Tripwire on a real person's phone, any phone, no app.

Calls to the protected person reach Tripwire's number first (in practice, by
forwarding unknown callers to it). Tripwire checks the caller's number against
Community Shield, tells the caller the call is protected, and connects the call
to the protected person's real phone, with a short whisper only they hear
before the call connects. While the two talk, both sides stream to Tripwire and
run through the same pipeline as everywhere else: each side transcribed,
CallAnalyst, Sentinel, the CaseJudge with verification, and the policy.

Two defences act on their own, without waiting for the judge:

* **Code Shield**: the moment the caller asks for a one-time code, the call is
  stopped by rule, before the person can read it out;
* **Call Tom**: when the caller claims to be a relative in trouble, the family
  member (``FAMILY_PHONE_NUMBER``) is texted a link: "someone says they're you,
  are you OK?". "That's not me" stops the call.

On a hard stop, Tripwire takes the protected person out of the call: their
phone leg is redirected to a spoken warning and hung up. The scammer's leg is
handed to the decoy (:mod:`backend.phone.decoy_line`), which keeps them talking
to learn how they get paid. The family gets the incident, and Community Shield
learns the scammer's number. There are no nudges on this line: Twilio cannot speak
into a connected two-way call without interrupting it, so Tripwire only steps
in when it is sure.
"""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Callable

from backend import family_check, shield
from backend.arena.session import voice_clip
from backend.incidents import PUBLIC_BASE_URL, create_incident
from backend.phone import twilio_api
from backend.phone.call import Utterances
from backend.sms import send_sms
from core import sentinel_client
from core.code_shield import code_request
from core.casefile import CaseFile
from core.events import Event, EventBus
from core.orchestrator import Orchestrator

STOP_SPEECH = ("This is Tripwire. I ended that call because the caller was trying to scam you. "
               "Please don't call them back, and don't send money, gift cards or codes to anyone. "
               "If you're worried about your bank account, call the number on the back of your card. "
               "I've let your family know.")


def whisper_text(caller_number: str) -> str:
    """What the protected person hears before the call connects (the caller doesn't hear it)."""
    hits = shield.lookup(caller_number)
    if hits:
        n = sum(h["reports"] for h in hits)
        return (f"Tripwire warning: this caller's number was reported in {n} scam{'s' if n != 1 else ''} stopped in other homes. "
                "Be very careful. Never give codes, card numbers or money.")
    return "Tripwire is listening to protect you on this call."


class _NoScreen:
    """Phone calls have no screen; the ScreenAnalyst is never called."""


CHECK_WAIT_S = 180


class GuardCall:
    def __init__(self, call_sid: str, caller_number: str, protected_number: str, protected_name: str = "",
                 decoy_twiml: Callable[[dict], str] | None = None) -> None:
        self.call_sid, self.caller_number = call_sid, caller_number
        self.protected_ids = {re.sub(r"\D", "", protected_number)[-10:]} if protected_number else set()
        self.protected_name = protected_name
        self.bus, self.case = EventBus(), CaseFile()
        sentinel = sentinel_client.shared()
        self.sentinel = sentinel
        self.orchestrator = Orchestrator(self.bus, self.case, screen=_NoScreen(), analyze_screen=False, log=lambda _: None,
                                         shield=shield.lookup, sentinel=sentinel.score if sentinel else None,
                                         sentinel_threshold=sentinel_client.threshold())
        self.caller = Utterances(lambda text: self._said("A", text))
        self.protected = Utterances(lambda text: self._said("B", text))
        self.stopped = False
        self.incident: tuple[str, str] | None = None
        self.decoy_twiml = decoy_twiml  # TwiML that hands the scammer's leg to the decoy (minted by the routes)
        self.family_checked = False
        self.case.on_update(self._on_case)
        self._lock = threading.Lock()
        self.bus.subscribe(self._on_event)

    def start(self) -> None:
        if self.sentinel:
            self.sentinel.warm()
        self.orchestrator.start()
        if self.caller_number:
            # the caller ID is a fact from the phone network: ground truth, and what Community Shield learns from a stop
            line = f"Incoming call from {self.caller_number}"
            self.case.note("network", line)
            self.orchestrator.check_shield(line)

    def audio(self, track: str, mulaw: bytes) -> None:
        """Twilio's ``inbound`` track is the caller; ``outbound`` is what the caller hears: the protected person."""
        if self.stopped:
            return
        (self.caller if track == "inbound" else self.protected).frame(mulaw)

    def _said(self, speaker: str, text: str) -> None:
        who = "Caller" if speaker == "A" else "Protected person"
        self.bus.publish(Event("audio", "transcript", {"speaker": speaker, "text": text, "summary": f'{who}: "{text}"'}))
        if speaker == "A" and code_request(text):  # Code Shield: by rule, before the code can be read out
            self.case.add_signals("call", [("code_request", text)])
            threading.Thread(target=self._stop, args=({"reasons": [{
                "reason": "Code Shield: the caller asked for a one-time code. No real bank or company ever asks for it.",
                "evidence": text}]},), daemon=True).start()

    def _on_case(self, update) -> None:
        claim = next((s for s in update.new_signals if s.name == "family_emergency_claim"), None)
        if claim and not self.family_checked and not self.stopped and os.environ.get("FAMILY_PHONE_NUMBER"):
            self.family_checked = True
            threading.Thread(target=self._call_family, args=(claim.evidence,), daemon=True).start()

    def _call_family(self, claim: str) -> None:
        """Ask the real relative by text. "That's not me" is a fact no voice clone can fake."""
        relative = os.environ.get("FAMILY_NAME", "your family member")
        check = family_check.create(self.protected_name or "your relative", relative, claim, source="phone")
        send_sms(f"TRIPWIRE: someone on the phone with {self.protected_name or 'your relative'} says they're you. "
                 f"Are you OK? Answer here: {PUBLIC_BASE_URL}/check/{check['id']}")
        self.case.note("intervention", "Tripwire texted the family a safety check: the caller claims to be a relative")
        deadline = time.time() + CHECK_WAIT_S
        while not self.stopped and time.time() < deadline:
            answer = family_check.get(check["id"])
            if answer and answer["status"] == "safe":
                fact = f'{relative} answered Tripwire\'s safety check: "That\'s not me. I\'m safe." They did not make this call.'
                self.bus.publish(Event("family", "denied", {"summary": fact}))
                self._stop({"reasons": [{"reason": f"The real {relative} confirmed they are safe and did not call", "evidence": fact}]})
                return
            if answer and answer["status"] != "pending":
                return
            time.sleep(2)

    def _on_event(self, event: Event) -> None:
        if event.source == "decision" and event.kind == "hard_stop":
            threading.Thread(target=self._stop, args=(event.data.get("verdict", {}),), daemon=True).start()

    def _stop(self, verdict: dict) -> None:
        with self._lock:
            if self.stopped:
                return
            self.stopped = True
        clip = voice_clip("tripwire", STOP_SPEECH)
        say = f"<Play>{PUBLIC_BASE_URL}/arena/voice/{clip}.mp3</Play>" if clip else f"<Say>{STOP_SPEECH}</Say>"
        for leg in twilio_api.child_calls(self.call_sid):  # the protected person leaves the call first
            twilio_api.redirect(leg, f"<Response>{say}<Hangup/></Response>")
        self.case.note("intervention", "Tripwire ended the call and warned the protected person")
        self.incident = create_incident(verdict, self.case.snapshot(), [], self.protected_name, redact_frames=False,
                                        source="phone", protected_ids=self.protected_ids)
        if self.decoy_twiml:  # the scammer's leg goes to the decoy instead of a dead line
            caller_lines = [t["text"] for t in self.case.snapshot()["timeline"] if t["source"] == "call"]
            try:
                twilio_api.redirect(self.call_sid, self.decoy_twiml({"incident": self.incident[0], "caller_lines": caller_lines,
                                                                     "protected_ids": sorted(self.protected_ids)}))
            except Exception:
                pass  # the protected person is already safe; the decoy is a bonus

    def end(self) -> None:
        self.caller.end()
        self.protected.end()
