"""The CaseFile: the running story of one session.

Analysts and Tier-0 rules write into it; the CaseJudge (Tier 2) reads the
whole thing. It keeps:

* a **timeline** of everything observed (frame descriptions, transcript
  lines, system events), in plain language;
* the **signals** found, each tied to a kill-chain stage and evidence;
* derived state: current stage, confidence, and whether a remote session is
  active, all computed over a sliding session window (~40 min).

It also derives two cross-cutting signals itself, because no single analyst
can see both sides: ``cross_modal_brand_match`` (screen and caller claim the
same organisation) and ``bank_open_during_remote``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

from core.killchain import SIGNALS, Stage, score

SESSION_WINDOW_S = 40 * 60


@dataclass(frozen=True)
class Signal:
    name: str
    stage: int
    source: str  # screen | call | process | network | clipboard | casefile
    evidence: str
    ts: float = field(default_factory=time.time)


@dataclass(frozen=True)
class TimelineEntry:
    ts: float
    source: str
    text: str
    risk: str = "none"


@dataclass
class CaseUpdate:
    """What changed after an update; handed to listeners (console, judge trigger)."""

    new_signals: list[Signal]
    stage: Stage
    confidence: float
    stages_present: set[Stage]


class CaseFile:
    """Thread-safe evidence store for one monitoring session."""

    def __init__(self, window_s: float = SESSION_WINDOW_S, clock: Callable[[], float] = time.time) -> None:
        self.window_s = window_s
        self.clock = clock
        self.timeline: list[TimelineEntry] = []
        self.signals: list[Signal] = []
        self.remote_active = False
        self.brands: dict[str, set[str]] = {"screen": set(), "call": set()}
        self._listeners: list[Callable[[CaseUpdate], None]] = []
        self._lock = threading.RLock()

    # -- writing -------------------------------------------------------------------

    def on_update(self, callback: Callable[[CaseUpdate], None]) -> None:
        self._listeners.append(callback)

    def note(self, source: str, text: str, risk: str = "none", ts: float | None = None) -> None:
        with self._lock:
            self.timeline.append(TimelineEntry(ts or self.clock(), source, text, risk))

    def add_signals(self, source: str, items: list[tuple[str, str]], ts: float | None = None) -> list[Signal]:
        """Record ``(signal_name, evidence)`` pairs. Unknown names are ignored."""
        ts = ts or self.clock()
        with self._lock:
            new = [Signal(name, int(SIGNALS[name].stage), source, evidence, ts) for name, evidence in items if name in SIGNALS]
            self.signals.extend(new)
            new.extend(self._derive(ts))
        if new:
            self._notify(new)
        return new

    def add_brands(self, source: str, brands: list[str], ts: float | None = None) -> None:
        """Record organisations claimed on screen or in the call (for cross-modal matching)."""
        with self._lock:
            self.brands.setdefault(source, set()).update(b.strip().lower() for b in brands if b.strip())
        self.add_signals(source, [], ts)

    def set_remote_active(self, active: bool, ts: float | None = None) -> None:
        with self._lock:
            self.remote_active = active
        self.add_signals("network", [], ts)

    # -- reading -------------------------------------------------------------------

    def active_signals(self) -> list[Signal]:
        cutoff = self.clock() - self.window_s
        with self._lock:
            return [s for s in self.signals if s.ts >= cutoff]

    def assess(self) -> tuple[Stage, float, set[Stage]]:
        """Current ``(stage, confidence, stages_present)`` over the session window."""
        names = {s.name for s in self.active_signals()}
        confidence, stages = score(names)
        return (max(stages) if stages else Stage.NONE), confidence, stages

    def snapshot(self) -> dict:
        """Serializable view for the judge, dashboard and eval."""
        stage, confidence, stages = self.assess()
        with self._lock:
            return {
                "stage": int(stage),
                "stage_name": stage.name,
                "confidence": confidence,
                "stages_present": sorted(int(s) for s in stages),
                "remote_active": self.remote_active,
                "brands": {k: sorted(v) for k, v in self.brands.items()},
                "signals": [asdict(s) for s in self.active_signals()],
                "timeline": [asdict(t) for t in self.timeline],
            }

    # -- internals -----------------------------------------------------------------

    def _has(self, name: str) -> bool:
        return any(s.name == name for s in self.active_signals())

    def _derive(self, ts: float) -> list[Signal]:
        """Cross-cutting signals that need more than one analyst's view."""
        derived: list[Signal] = []
        shared = self.brands.get("screen", set()) & self.brands.get("call", set())
        if shared and not self._has("cross_modal_brand_match"):
            derived.append(Signal("cross_modal_brand_match", int(Stage.CONTACT), "casefile", f"screen and caller both claim: {', '.join(sorted(shared))}", ts))
        remote = self.remote_active or self._has("remote_session_active")
        if remote and self._has("bank_site_open") and not self._has("bank_open_during_remote"):
            derived.append(Signal("bank_open_during_remote", int(Stage.ACCESS), "casefile", "banking site on screen while a remote session is active", ts))
        self.signals.extend(derived)
        return derived

    def _notify(self, new: list[Signal]) -> None:
        stage, confidence, stages = self.assess()
        update = CaseUpdate(new, stage, confidence, stages)
        for callback in self._listeners:
            callback(update)
