"""Orchestrator: routes Tier-0 events to analysts and into the CaseFile.

* Tier-0 system events (remote tool launched, crypto address copied...) map
  to signals by fixed rules; no model needed.
* Kept frames go to the ScreenAnalyst on a "latest only" worker: if frames
  arrive faster than the model answers, stale ones are skipped, because the
  current screen is what matters.
* Transcript turns go to the CallAnalyst on an ordered worker: the call
  must be read in sequence.

Model calls never run on watcher threads, so capture never stalls.
"""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Callable

from analysts.call_analyst import CallAnalyst
from analysts.screen_analyst import ScreenAnalyst
from core.casefile import CaseFile
from core.events import Event, EventBus

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
        log: Callable[[str], None] = print,
        analyze_screen: bool = True,
    ) -> None:
        self.bus = bus
        self.case = case or CaseFile()
        self.screen = screen or ScreenAnalyst()
        self.call = call or CallAnalyst()
        self.log = log
        self.analyze_screen = analyze_screen
        self._screen_worker = _Worker("screen-analyst", self._analyze_frame, self._error, latest_only=True)
        self._call_worker = _Worker("call-analyst", self._analyze_turn, self._error)

    def start(self) -> None:
        self._screen_worker.start()
        self._call_worker.start()
        self.bus.subscribe(self.handle)

    def drain(self) -> None:
        """Block until every submitted frame and turn has been analysed."""
        self._screen_worker.drain()
        self._call_worker.drain()

    # -- routing -------------------------------------------------------------------

    def handle(self, event: Event) -> None:
        if event.source == "screen" and event.kind == "frame_kept":
            if self.analyze_screen:
                self._screen_worker.submit(event)
        elif event.source == "audio" and event.kind == "transcript":
            self._call_worker.submit(event)
        elif event.source in ("process", "network", "clipboard"):
            self._apply_tier0(event)

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
        speaker, text = event.data.get("speaker"), event.data["text"]
        finding = self.call.analyze(speaker, text)
        role = finding.roles.get(speaker or "", "unknown")
        self.case.note("call", f"{speaker or '?'} ({role}): {text}", finding.risk, ts=event.ts)
        self.log(f"  call   [{finding.risk}] {speaker or '?'} ({role}): {finding.note}")
        self.case.add_brands("call", finding.brands, ts=event.ts)
        self.case.add_signals("call", finding.signals, ts=event.ts)

    def _error(self, message: str) -> None:
        self.log(f"  ! {message}")
        self.case.note("system", f"analysis error: {message}")
