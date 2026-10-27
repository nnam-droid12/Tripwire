"""Interventionist: carries out the decided action.

* ``nudge``     - one calm spoken sentence. Nothing blocks the screen.
* ``hard_stop`` - full-screen warning, the warning spoken aloud (heard even if
  a scammer controls the screen), remote-access tools terminated, and a
  family alert requested (sent by the backend, Stage F).

While a hard stop is up, the call is checked for instructions to close or
disable Tripwire; one restarts the cooldown, is said out loud, and is added to
the CaseFile as evidence.

When the warning is dismissed (PIN or cooldown) the orchestrator's action is
lowered to ``nudge`` so that new evidence can escalate again; the CaseFile
records how it was dismissed so the judge can weigh it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent.overlay import WarningOverlay
from agent.remote_kill import terminate_remote_tools
from agent.tts import Speaker
from core.casefile import CaseFile
from core.events import Event, EventBus
from core.guard import DismissGate, is_disable_instruction
from core.settings import Settings

if TYPE_CHECKING:
    from core.orchestrator import Orchestrator

DEFAULT_NUDGE = "Just so you know, Microsoft and banks never phone people out of the blue about viruses or refunds. It is okay to hang up."
GENERIC_BRANDS = {"windows", "security", "support", "technical support", "tech support"}


def hard_stop_speech(brand: str | None) -> str:
    who = f"The person on the phone is not from {brand}. " if brand else ""
    return (
        f"Stop. This is a scam. {who}Hang up the phone now. "
        "Do not buy gift cards, do not send money, and do not give anyone a code. "
        "If you are worried about your account, call your bank using the number on the back of your card."
    )


def _sentence_case(text: str) -> str:
    """Upper-case the first letter only (str.capitalize would turn "Microsoft" into "microsoft")."""
    text = text.strip()
    return text[:1].upper() + text[1:]


class Interventionist:
    def __init__(
        self,
        bus: EventBus,
        case: CaseFile,
        orchestrator: "Orchestrator",
        settings: Settings | None = None,
        *,
        speaker: Speaker | None = None,
        show_overlay: bool = True,
        kill_mode: str = "live",  # live | dry | off
        kill_only: set[str] | None = None,
        extra_tools: dict[str, str] | None = None,
        overlay_auto_hide_s: float | None = None,
    ) -> None:
        self.bus, self.case, self.orchestrator = bus, case, orchestrator
        self.settings = settings or Settings.load()
        self.speaker = speaker or Speaker()
        self.gate = DismissGate(self.settings)
        self.overlay = WarningOverlay(self.gate, self._on_dismiss, overlay_auto_hide_s) if show_overlay else None
        self.kill_mode, self.kill_only, self.extra_tools = kill_mode, kill_only, extra_tools
        self.active = False
        self.trusted_tools: set[str] = set()

    def start(self) -> None:
        self.speaker.start()
        if self.overlay:
            self.overlay.start()
            self.overlay.wait_ready()
        self.bus.subscribe(self.handle)

    def stop(self) -> None:
        self.speaker.stop()

    # -- routing -------------------------------------------------------------------

    def handle(self, event: Event) -> None:
        if event.source == "decision" and event.kind == "nudge":
            verdict = event.data.get("verdict", {})
            self.speaker.say(verdict.get("senior_message") or DEFAULT_NUDGE)
            self._publish("nudge_spoken", "Spoke a calm nudge")
        elif event.source == "decision" and event.kind == "hard_stop":
            self._hard_stop(event.data.get("verdict", {}))
        elif event.source == "network" and event.kind == "trusted_remote_session":
            self.trusted_tools.add(event.data.get("tool", ""))
        elif event.source == "audio" and event.kind == "transcript" and self.active:
            text = event.data.get("text", "")
            if is_disable_instruction(text):
                self._resist(text)

    # -- actions -------------------------------------------------------------------

    def _hard_stop(self, verdict: dict) -> None:
        self.active = True
        brand = self._claimed_brand()
        reasons = [_sentence_case(r["reason"]) for r in verdict.get("reasons", []) if r.get("reason", "").strip()]
        if self.overlay:
            self.overlay.show("STOP. This looks like a scam.", reasons, self.settings.family_name)
        self.speaker.say(hard_stop_speech(brand), urgent=True)
        self._publish("warning_shown", "Full-screen warning shown and spoken aloud")
        self._end_remote_sessions()
        self._publish("family_alert_requested", f"Family alert requested: {verdict.get('family_message', '')}", message=verdict.get("family_message", ""))

    def _end_remote_sessions(self) -> None:
        if self.kill_mode == "off" or not self.settings.kill_remote_on_hard_stop:
            return
        results = terminate_remote_tools(
            trusted_tools=self.trusted_tools, only=self.kill_only, extra_tools=self.extra_tools, dry_run=self.kill_mode == "dry"
        )
        if not results:
            self._publish("remote_tools_terminated", "No remote-access tool was running")
            return
        summary = ", ".join(f"{r.tool} pid {r.pid}: {r.outcome}" for r in results)
        self._publish("remote_tools_terminated", f"Remote access ended ({summary})", results=[r.__dict__ for r in results])

    def _resist(self, text: str) -> None:
        self.gate.restart_cooldown()
        if self.overlay:
            self.overlay.restart_cooldown()
        self.speaker.say("Do not close this warning. The person on the phone is trying to stop me from protecting you. Please hang up.", urgent=True)
        self.case.add_signals("call", [("disable_protection", text)])
        self._publish("disable_attempt_resisted", f'Caller tried to get the warning closed: "{text[:120]}"')

    def _on_dismiss(self, how: str) -> None:
        self.active = False
        self._publish("dismissed", f"Warning dismissed by {how}", how=how)
        self.orchestrator.reset_action()

    # -- helpers -------------------------------------------------------------------

    def _claimed_brand(self) -> str | None:
        for brand in sorted(self.case.brands.get("call", set())):
            if brand not in GENERIC_BRANDS:
                return brand.title() if brand.islower() else brand
        return None

    def _publish(self, kind: str, summary: str, **data) -> None:
        self.bus.publish(Event("intervention", kind, {"summary": summary, **data}))
