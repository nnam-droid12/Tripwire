"""Orchestrator: routes Tier-0 events to analysts and into the CaseFile.

* Tier-0 system events (remote tool launched, crypto address copied...) map
  to signals by fixed rules; no model needed.
* Kept frames go to the ScreenAnalyst on a "latest only" worker: if frames
  arrive faster than the model answers, stale ones are skipped, because the
  current screen is what matters.
* Transcript turns go to the CallAnalyst on an ordered worker: the call
  must be read in sequence.
* Whenever the CaseFile changes and the escalation policy agrees, the
  CaseJudge is asked for a verdict on the whole session. That worker is also
  "latest only", so a burst of new evidence produces one judge call on the
  newest snapshot, not a backlog. Its verdict, clamped by the policy, becomes
  the session's action (published as a ``decision`` event).

Model calls never run on watcher threads, so capture never stalls.
"""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Callable

from agent.redact import redact_text
from analysts.call_analyst import CallAnalyst
from analysts.case_judge import CaseJudge
from analysts.screen_analyst import ScreenAnalyst
from core.casefile import CaseFile, CaseUpdate
from core.events import Event, EventBus
from core.policy import Action, EscalationPolicy, Verdict

# (source, kind) of a Tier-0 event -> signal name
TIER0_RULES: dict[tuple[str, str], str] = {
    ("process", "process_launched"): "remote_tool_launched",
    ("network", "remote_session_suspected"): "remote_session_active",
    ("clipboard", "bitcoin_address"): "crypto_address_copied",
    ("clipboard", "ethereum_address"): "crypto_address_copied",
    ("clipboard", "money_amount"): "money_amount_copied",
    ("clipboard", "card_number"): "card_number_copied",
}


class _Worker(threading.Thread):
    """Runs jobs one at a time. ``latest_only`` drops queued jobs in favour of the newest."""

    def __init__(self, name: str, handle: Callable[[Event], None], on_error: Callable[[str], None], latest_only: bool = False) -> None:
        super().__init__(name=name, daemon=True)
        self.handle, self.on_error, self.latest_only = handle, on_error, latest_only
        self.jobs: queue.Queue[Event | None] = queue.Queue()

    def submit(self, event: Event) -> None:
        if self.latest_only:
            while True:
                try:
                    self.jobs.get_nowait()
                except queue.Empty:
                    break
                self.jobs.task_done()  # a dropped job counts as handled, or drain() never returns
        self.jobs.put(event)

    def run(self) -> None:
        while (event := self.jobs.get()) is not None:
            try:
                self.handle(event)
            except Exception as exc:  # one bad model reply must not stop analysis
                self.on_error(f"{self.name}: {type(exc).__name__}: {exc}")
            finally:
                self.jobs.task_done()

    def drain(self) -> None:
        self.jobs.join()


class Orchestrator:
    def __init__(
        self,
        bus: EventBus,
        case: CaseFile | None = None,
        screen: ScreenAnalyst | None = None,
        call: CallAnalyst | None = None,
        judge: CaseJudge | None = None,
        policy: EscalationPolicy | None = None,
        log: Callable[[str], None] = print,
        analyze_screen: bool = True,
    ) -> None:
        self.bus = bus
        self.case = case or CaseFile()
        self.screen = screen or ScreenAnalyst()
        self.call = call or CallAnalyst()
        self.judge = judge or CaseJudge()
        self.policy = policy or EscalationPolicy()
        self.log = log
        self.analyze_screen = analyze_screen
        self.action = Action.LOG
        self.paused = False  # set from the tray; capture keeps running but nothing is analysed
        self.verdicts: list[Verdict] = []
        self.decisions: list[tuple[Action, Verdict]] = []
        self._screen_worker = _Worker("screen-analyst", self._analyze_frame, self._error, latest_only=True)
        self._call_worker = _Worker("call-analyst", self._analyze_turn, self._error)
        self._judge_worker = _Worker("case-judge", self._run_judge, self._error, latest_only=True)
        self.case.on_update(self._on_case_update)

    def start(self) -> None:
        self._screen_worker.start()
        self._call_worker.start()
        self._judge_worker.start()
        self.bus.subscribe(self.handle)

    def drain(self) -> None:
        """Block until every submitted frame, turn and judge request has been handled."""
        self._screen_worker.drain()
        self._call_worker.drain()
        self._judge_worker.drain()

    # -- routing -------------------------------------------------------------------

    def handle(self, event: Event) -> None:
        if self.paused and event.source != "intervention":
            return
        if event.source == "screen" and event.kind == "frame_kept":
            if self.analyze_screen:
                self._screen_worker.submit(event)
        elif event.source == "audio" and event.kind == "transcript":
            self._call_worker.submit(event)
        elif event.source in ("process", "network", "clipboard"):
            self._apply_tier0(event)
        elif event.source == "intervention":
            self.case.note("intervention", event.data.get("summary", event.kind), ts=event.ts)

    def _apply_tier0(self, event: Event) -> None:
        summary = event.data.get("summary", event.kind)
        self.case.note(event.source, summary, ts=event.ts)
        if event.kind == "remote_session_suspected":
            self.case.set_remote_active(True, ts=event.ts)
        elif event.kind == "remote_session_ended":
            self.case.set_remote_active(False, ts=event.ts)
        signal = TIER0_RULES.get((event.source, event.kind))
        if signal:
            self.case.add_signals(event.source, [(signal, summary)], ts=event.ts)

    def _analyze_frame(self, event: Event) -> None:
        finding = self.screen.analyze(Path(event.data["path"]))
        self.case.note("screen", finding.description, finding.risk, ts=event.ts)
        self.log(f"  screen [{finding.risk}] {finding.description}")
        self.case.add_brands("screen", finding.brands, ts=event.ts)
        self.case.add_signals("screen", finding.signals, ts=event.ts)

    def _analyze_turn(self, event: Event) -> None:
        speaker, text = event.data.get("speaker"), redact_text(event.data["text"])  # spoken card numbers, access codes
        finding = self.call.analyze(speaker, text)
        role = finding.roles.get(speaker or "", "unknown")
        self.case.note("call", f"{speaker or '?'} ({role}): {text}", finding.risk, ts=event.ts)
        self.log(f"  call   [{finding.risk}] {speaker or '?'} ({role}): {finding.note}")
        self.case.add_brands("call", finding.brands, ts=event.ts)
        self.case.add_signals("call", finding.signals, ts=event.ts)

    # -- escalation ----------------------------------------------------------------

    def _on_case_update(self, update: CaseUpdate) -> None:
        new = {s.name for s in update.new_signals}
        if self.action < Action.HARD_STOP and self.policy.should_judge(update.confidence, len(update.stages_present), new):
            self._judge_worker.submit(Event("judge", "request", {"tier1_confidence": update.confidence}))

    def reset_action(self, to: Action = Action.NUDGE) -> None:
        """After a hard stop is dismissed: let fresh evidence escalate again."""
        self.action = min(self.action, to)

    def _run_judge(self, _request: Event) -> None:
        if self.action == Action.HARD_STOP:
            return
        verdict = self.judge.judge(self.case.snapshot())
        self.verdicts.append(verdict)
        action = self.policy.decide(verdict)
        top = verdict.reasons[0]["reason"] if verdict.reasons else ""
        summary = f"is_scam={verdict.is_scam} conf={verdict.confidence:.2f} stage={verdict.stage} -> {action.label} (recommended {verdict.recommended_action.label}). {top}"
        self.case.note("judge", summary, ts=verdict.ts)
        self.bus.publish(Event("judge", "verdict", {**verdict.to_dict(), "action": action.label, "summary": summary}, ts=verdict.ts))
        if action > self.action:
            self.action = action
            self.decisions.append((action, verdict))
            self.bus.publish(
                Event("decision", action.label, {"verdict": verdict.to_dict(), "summary": f"ACTION {action.label.upper()}: {verdict.family_message}"}, ts=verdict.ts)
            )

    def _error(self, message: str) -> None:
        self.log(f"  ! {message}")
        self.case.note("system", f"analysis error: {message}")
