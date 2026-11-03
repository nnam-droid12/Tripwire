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
from analysts.playbook import Recall
from analysts.case_judge import CaseJudge
from analysts.screen_analyst import ScreenAnalyst
from core import site_check
from core.casefile import CaseFile, CaseUpdate
from core.events import Event, EventBus
from core.policy import Action, EscalationPolicy, Verdict

# Site Check and Device Trust findings that stop at once, like Code Shield: facts about the real address or the computer, not
# opinions. (A brand on the wrong address rests on the model's reading of the page, so it goes through the judge instead.)
SITE_STOPS = {"fake_browser_window", "hosts_file_hijack", "rogue_certificate"}
SENSITIVE_ASKS = ("login", "payment", "personal")

# (source, kind) of a Tier-0 event -> signal name
TIER0_RULES: dict[tuple[str, str], str] = {
    ("process", "process_launched"): "remote_tool_launched",
    ("network", "remote_session_suspected"): "remote_session_active",
    ("control", "remote_input"): "remote_control_input",
    ("clipboard", "bitcoin_address"): "crypto_address_copied",
    ("clipboard", "ethereum_address"): "crypto_address_copied",
    ("clipboard", "money_amount"): "money_amount_copied",
    ("clipboard", "card_number"): "card_number_copied",
    ("sms", "code_received"): "code_received_during_call",
    ("family", "denied"): "family_denied_call",
    ("device", "hosts_file_hijack"): "hosts_file_hijack",
    ("device", "rogue_certificate"): "rogue_certificate",
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
        shield: Callable[[str], list[dict]] | None = None,
        sentinel: Callable[[list[tuple[str, str]]], float | None] | None = None,
        sentinel_threshold: float = 0.96,
        memory: Recall | None = None,
    ) -> None:
        self.bus = bus
        self.case = case or CaseFile()
        self.screen = screen or ScreenAnalyst()
        self.call = call or CallAnalyst()
        self.judge = judge or CaseJudge()
        self.policy = policy or EscalationPolicy()
        self.log = log
        self.analyze_screen = analyze_screen
        self.shield = shield  # Community Shield lookup: known scammer identifiers in a line of text
        self._shield_seen: set[str] = set()
        self._site_seen: set[tuple[str, str]] = set()
        # Tripwire Sentinel: P(scam) for the call so far, from our fine-tuned small model. Supporting evidence only:
        # it raises a signal the judge weighs, but it is never ground truth and can never be quoted as a reason.
        self.sentinel = sentinel
        self.sentinel_threshold = sentinel_threshold
        self._turns: list[tuple[str, str]] = []
        # Scam Memory: scripts learned from earlier stopped scams, recognised in this call (see analysts.playbook)
        self.memory = memory
        self._transcript: list[tuple[str, str]] = []
        self._sentinel_flagged = False
        self.action = Action.LOG
        self.paused = False  # set from the tray; capture keeps running but nothing is analysed
        self.verdicts: list[Verdict] = []
        self.decisions: list[tuple[Action, Verdict]] = []
        self._screen_worker = _Worker("screen-analyst", self._analyze_frame, self._error, latest_only=True)
        self._call_worker = _Worker("call-analyst", self._analyze_turn, self._error)
        self._judge_worker = _Worker("case-judge", self._run_judge, self._error, latest_only=True)
        self._sentinel_worker = _Worker("sentinel", self._run_sentinel, self._error, latest_only=True)
        self._memory_worker = _Worker("scam-memory", self._run_memory, self._error, latest_only=True)
        self.case.on_update(self._on_case_update)

    def start(self) -> None:
        self._screen_worker.start()
        self._call_worker.start()
        self._judge_worker.start()
        self._sentinel_worker.start()
        self._memory_worker.start()
        self.bus.subscribe(self.handle)

    def drain(self) -> None:
        """Block until every submitted frame, turn and judge request has been handled."""
        self._screen_worker.drain()
        self._call_worker.drain()
        self._sentinel_worker.drain()
        self._memory_worker.drain()
        self._judge_worker.drain()

    # -- routing -------------------------------------------------------------------

    def handle(self, event: Event) -> None:
        if self.paused and event.source != "intervention":
            return
        if event.source == "screen" and event.kind == "frame_kept":
            if event.data.get("url"):
                self._precheck_url(event.data["url"], event.ts)  # no model needed: before the page is even read
            if self.analyze_screen:
                self._screen_worker.submit(event)
        elif event.source == "audio" and event.kind == "transcript":
            if self.sentinel and not self._sentinel_flagged:
                self._turns.append((event.data.get("speaker") or "?", redact_text(event.data["text"])))
                self._sentinel_worker.submit(Event("sentinel", "score", {"turns": list(self._turns)}))
            self._call_worker.submit(event)
            if self.memory is not None:
                self._transcript.append((event.data.get("speaker") or "?", redact_text(event.data["text"])))
                self._memory_worker.submit(Event("memory", "check", {"transcript": list(self._transcript)}))
        elif event.source in ("process", "network", "clipboard", "control", "sms", "family", "device"):
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
            if signal in SITE_STOPS:
                self.rule_stop("Device Trust", summary, "device")

    def check_shield(self, *texts: str) -> None:
        """Exact matches against identifiers reported in other homes' stopped scams: ground truth, not a model."""
        if not self.shield:
            return
        for text in texts:
            try:
                hits = self.shield(text)
            except Exception:  # the shield is a bonus; never let it break analysis
                continue
            for hit in hits:
                if hit["display"] in self._shield_seen:
                    continue
                self._shield_seen.add(hit["display"])
                line = f"Community Shield: {hit['display']} was reported in {hit['reports']} scam(s) stopped in other homes"
                self.case.note("shield", line)
                self.case.add_signals("shield", [("known_scam_indicator", line)])

    def _run_memory(self, event: Event) -> None:
        signals = {s["name"] for s in self.case.snapshot()["signals"]}
        for match in self.memory.check(event.data["transcript"], signals):
            self.log(f"  memory {match['evidence']}")
            self.case.note("memory", match["evidence"])
            self.case.add_signals("memory", [("known_scam_playbook", match["evidence"])])

    def _run_sentinel(self, event: Event) -> None:
        turns = event.data["turns"]
        p = self.sentinel(turns)
        if p is None or p < self.sentinel_threshold or self._sentinel_flagged:
            return
        self._sentinel_flagged = True
        self.case.add_signals("sentinel", [("sentinel_flag", f"Sentinel rates the call a likely scam (p={p:.2f}) after {len(turns)} turns")])

    def _analyze_frame(self, event: Event) -> None:
        finding = self.screen.analyze(Path(event.data["path"]))
        self.case.note("screen", finding.description, finding.risk, ts=event.ts)
        self.check_shield(finding.description, *(evidence for _, evidence in finding.signals))
        self.log(f"  screen [{finding.risk}] {finding.description}")
        self.case.add_brands("screen", finding.brands, ts=event.ts)
        self.case.add_signals("screen", finding.signals, ts=event.ts)
        if event.data.get("url"):
            self.check_site(event.data["url"], finding, ts=event.ts)

    def _precheck_url(self, url: str, ts: float | None = None) -> None:
        """The address alone: foreign look-alike letters in a brand's name stop at once, before any model reads the page."""
        host = site_check.host_of(url)
        look = site_check.lookalike(host)
        if not look or not look[3] or ("lookalike_domain", host) in self._site_seen:
            return
        self._site_seen.add(("lookalike_domain", host))
        evidence = f"The browser's real address is {host}, made to look like {look[1]}: {look[2]}"
        self.log(f"  site   {evidence}")
        self.case.note("site", f"Site Check: {evidence}", ts=ts)
        self.case.add_signals("site", [("lookalike_domain", evidence)], ts=ts)
        self.rule_stop("Site Check", f"Site Check: {evidence}", "site")

    def check_site(self, url: str, finding, ts: float | None = None) -> None:
        """Site Check: what the page claims (the vision model) against where the browser really is (the browser itself)."""
        host = site_check.host_of(url)
        findings = site_check.check_page(url, finding.page_brand, finding.asks_for, finding.drawn_urls)
        if findings or finding.asks_for in ("login", "payment", "personal"):
            aged = site_check.age_finding(host, site_check.domain_age_days(host))
            findings += [aged] if aged else []
        for f in findings:
            if (f.signal, host) in self._site_seen:
                continue
            self._site_seen.add((f.signal, host))
            self.log(f"  site   {f.evidence}")
            self.case.note("site", f"Site Check: {f.evidence}", ts=ts)
            self.case.add_signals("site", [(f.signal, f.evidence)], ts=ts)
            if f.signal in SITE_STOPS or (f.signal == "lookalike_domain" and finding.asks_for in SENSITIVE_ASKS):
                self.rule_stop("Site Check", f"Site Check: {f.evidence}", "site")

    def _analyze_turn(self, event: Event) -> None:
        speaker, text = event.data.get("speaker"), redact_text(event.data["text"])  # spoken card numbers, access codes
        finding = self.call.analyze(speaker, text)
        role = finding.roles.get(speaker or "", "unknown")
        self.case.note("call", f"{speaker or '?'} ({role}): {text}", finding.risk, ts=event.ts)
        self.check_shield(text)
        self.log(f"  call   [{finding.risk}] {speaker or '?'} ({role}): {finding.note}")
        self.case.add_brands("call", finding.brands, ts=event.ts)
        self.case.add_signals("call", finding.signals, ts=event.ts)

    # -- escalation ----------------------------------------------------------------

    def _on_case_update(self, update: CaseUpdate) -> None:
        new = {s.name for s in update.new_signals}
        if self.action < Action.HARD_STOP and self.policy.should_judge(update.confidence, len(update.stages_present), new):
            self._judge_worker.submit(Event("judge", "request", {"tier1_confidence": update.confidence}))

    def rule_stop(self, defence: str, evidence: str, kind: str) -> None:
        """A hard stop on a fact Tripwire checked itself (the real address, the computer), without waiting for the judge."""
        if self.action >= Action.HARD_STOP:
            return
        verdict = Verdict(
            is_scam=True, confidence=1.0, stage=4,
            reasons=[{"reason": f"{defence}: this is not the website it pretends to be", "evidence": evidence, "source": evidence, "source_kind": kind}],
            recommended_action=Action.HARD_STOP,
            family_message="Tripwire stopped a fake website that was asking for a password or payment details. Nothing was typed into it.",
            verification={"rule": defence, "attempts": 0, "reviewer": "not needed: a checked fact, not a model's opinion"},
        )
        self.verdicts.append(verdict)
        self.action = Action.HARD_STOP
        self.decisions.append((Action.HARD_STOP, verdict))
        self.case.note("judge", f"{defence} stopped the session: {evidence[:200]}", ts=verdict.ts)
        self.bus.publish(Event("decision", Action.HARD_STOP.label,
                               {"verdict": {**verdict.to_dict(), "defence": defence, "how": "the browser's real address and this computer, checked directly"},
                                "summary": f"ACTION HARD_STOP: {verdict.family_message}"}, ts=verdict.ts))

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
