"""One arena game: the visitor (scammer) vs Margaret, with Tripwire watching.

The real pipeline runs unchanged: every line of the call becomes a transcript
event, every page on Margaret's laptop becomes a kept screen frame, and the
Tier-1 analysts, the kill-chain CaseFile and the CaseJudge decide exactly as
they do on a real computer. The session turns their decisions into what the
visitor sees and hears: a spoken nudge, the red warning over Margaret's
laptop, the "close that box" resistance, the recovery agent's actions and the
family alert.

``send`` is called from worker threads with JSON-able dicts; the web layer
forwards them over the WebSocket.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from typing import Callable

from agent.transcribe import MuseTranscriber, TranscriptTurn
from agent.tts import GoogleVoice
from analysts.case_judge import render_case
from analysts.interventionist import RESIST_LINE, choose_nudge, hard_stop_speech
from analysts.screen_analyst import ScreenAnalyst
from backend import approvals, shield
from backend.arena import laptop, scores
from backend.arena.margaret import Margaret
from backend.arena.recovery import REJECTED, RecoveryAgent
from backend.incidents import create_incident
from core import sentinel_client
from core.casefile import CaseFile, CaseUpdate
from core.config import LOGS_DIR, RUNTIME_DIR
from core.events import Event, EventBus
from core.guard import is_disable_instruction
from core.killchain import Stage
from core.output_checks import check_message, check_report, invented_numbers, observed
from core.orchestrator import Orchestrator
from core.policy import Action
from core.rules import SENSITIVE, Decision, Facts, FamilyRules

VOICE_DIR = RUNTIME_DIR / "arena_voice"
VOICES = {
    "margaret": GoogleVoice(voice="en-US-Chirp3-HD-Gacrux", rate=0.95, cache_dir=VOICE_DIR, encoding="MP3"),
    "tripwire": GoogleVoice(voice="en-US-Chirp3-HD-Vindemiatrix", rate=0.95, cache_dir=VOICE_DIR, encoding="MP3"),
}
MAX_LINES = 40
VERIFY_QUESTION = "Margaret, a quick check before you pay: did you call them, or did they call you?"
PAGE_AMOUNTS = {"wire_transfer": 18500.0, "gift_cards": 5000.0, "bitcoin": 9000.0}  # what Margaret's (fictional) pages show
MARGARET_IDS = {"482113907", "9931"}  # Margaret's own RemoteDesk address and card: never shared by Community Shield
CARD_ON_FILE = "9931"  # Margaret's (fictional) card: the only one the recovery agent may freeze
_PHONE = re.compile(r"\+?\d[\d\s().-]{6,}\d")


def grounded_contacts(text: str, record: list[str]) -> str:
    """Keep only phone numbers that really appear in the record; an invented number in a fraud report is worse than none."""
    digits = lambda s: re.sub(r"\D", "", s)
    seen = "".join(digits(line) for line in record)
    numbers = [n for n in _PHONE.findall(text) if digits(n) and digits(n) in seen]
    words = _PHONE.sub("", text).strip(" ,;")
    kept = ", ".join(dict.fromkeys(numbers + ([words] if words else [])))
    return kept or "not recorded"


MAX_SECONDS = 8 * 60
MAX_REJECTIONS = 2  # per tool: after this, the output is delivered with anything unverifiable removed


def prewarm_voices() -> None:
    """Synthesize everything Tripwire may need to say urgently, so it plays instantly in the arena."""
    from analysts.interventionist import prewarm_phrases

    for text in prewarm_phrases():
        voice_clip("tripwire", text)
    for brand in ("Riverbend Community Bank", "The Irs", "Amazon"):
        voice_clip("tripwire", hard_stop_speech(brand))


def voice_clip(who: str, text: str) -> str | None:
    """Synthesize (or reuse) a clip; returns its id for /arena/voice/<id>.mp3, or None on failure."""
    try:
        return VOICES[who].synthesize(text).stem
    except Exception:
        return None  # the text is always shown too; a missing clip is not fatal


class ArenaSession:
    def __init__(self, send: Callable[[dict], None], situation: str = "popup") -> None:
        self.id = uuid.uuid4().hex[:12]
        self.send = send
        self.situation = situation if situation in ("popup", "call") else "popup"
        self.bus = EventBus(LOGS_DIR / f"arena_{self.id}.jsonl")
        self.case = CaseFile()
        self.sentinel = sentinel_client.shared()
        self.orchestrator = Orchestrator(self.bus, self.case, screen=ScreenAnalyst(redact=lambda png: png), log=lambda _: None,
                                         shield=shield.lookup, sentinel=self.sentinel.score if self.sentinel else None,
                                         sentinel_threshold=sentinel_client.threshold())
        self.margaret = Margaret()
        self.recovery = RecoveryAgent()
        self._warning_lock = threading.Lock()
        self.page = "fake_alert" if self.situation == "popup" else "desktop"
        self.pages_seen: list[str] = []
        self.started = time.time()
        self.first_line_at: float | None = None
        self.lines = 0
        self.warning_active = False
        self.report: dict | None = None  # the verified fraud report draft, once written
        self.call_ended = False  # Margaret hung up after the warning; the scammer can no longer reach her
        self.over = False
        self._turn_lock = threading.Lock()
        self._asr: MuseTranscriber | None = None
        self.rules = FamilyRules()
        self.remote_control = False  # someone other than Margaret is driving her mouse and keyboard
        self.guarded: set[str] = set()  # sensitive pages already put through the family rules
        self.case.on_update(self._on_case)
        self.bus.subscribe(self._on_event)

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> None:
        if self.sentinel:
            self.sentinel.warm()  # a cold container takes ~30 s; until then Tripwire simply runs without Sentinel
        self.orchestrator.start()
        self.send({"type": "started", "session": self.id, "situation": self.situation})
        self._show(self.page)
        threading.Thread(target=self._margaret_opening, daemon=True).start()

    def expired(self) -> bool:
        return time.time() - self.started > MAX_SECONDS

    # -- the scammer (visitor) -------------------------------------------------------

    def scammer_says(self, text: str) -> None:
        """One line from the visitor, typed or transcribed. Runs on a worker thread."""
        text = text.strip()[:500]
        if not text or self.over:
            return
        with self._turn_lock:
            if self.lines >= MAX_LINES or self.expired():
                self._end("time", "This game has reached its time limit.")
                return
            self.lines += 1
            self.first_line_at = self.first_line_at or time.time()
            self.send({"type": "line", "who": "scammer", "text": text})
            if self.warning_active and is_disable_instruction(text):
                self._resist(text)
            if self.call_ended:
                self.send({"type": "line", "who": "system", "text": "Margaret has hung up. She can't hear you any more."})
                return
            self.bus.publish(Event("audio", "transcript", {"speaker": "A", "text": text, "summary": f'Caller: "{text}"'}))
            turn = self.margaret.respond(text, self.page)
            self._margaret_speaks(turn.reply)
            if turn.open_page and turn.open_page != self.page:
                self._show(turn.open_page)
                if turn.open_page in SENSITIVE and turn.open_page not in self.guarded:
                    self._guard(turn.open_page)
            if turn.hang_up:
                self._end("hung_up", "Margaret hung up.")

    def ptt_start(self) -> None:
        if self._asr is None and not self.over:
            self._asr = MuseTranscriber(self._on_ptt_turn, mode="PUSH_TO_TALK", paced=True,
                                        on_error=lambda m: self.send({"type": "error", "text": m}))
            self._asr.start()

    def ptt_audio(self, pcm: bytes) -> None:
        if self._asr:
            self._asr.feed(pcm)

    def ptt_end(self) -> None:
        asr, self._asr = self._asr, None
        if asr:
            asr.close()  # blocks until the final transcript arrives; called off the event loop

    def _on_ptt_turn(self, turn: TranscriptTurn) -> None:
        threading.Thread(target=self.scammer_says, args=(turn.text,), daemon=True).start()

    def hang_up(self) -> None:
        if not self.over:
            self._end("scammer_hung_up", "You hung up.")

    # -- Margaret ----------------------------------------------------------------------

    def _margaret_opening(self) -> None:
        with self._turn_lock:
            turn = self.margaret.opening(self.situation)
            self._margaret_speaks(turn.reply)

    def _margaret_speaks(self, text: str) -> None:
        self.send({"type": "line", "who": "margaret", "text": text, "audio": voice_clip("margaret", text)})
        self.bus.publish(Event("audio", "transcript", {"speaker": "B", "text": text, "summary": f'Margaret: "{text}"'}))

    def _show(self, page: str) -> None:
        """Change Margaret's screen, and report it the way the desktop agent would."""
        self.page = page
        self.pages_seen.append(page)
        self.send({"type": "laptop", "page": page})
        self.bus.publish(Event("screen", "frame_kept", {"path": str(laptop.png_path(page)), "summary": f"screen: {page}"}))
        if page == "remotedesk_download":
            self.bus.publish(Event("process", "process_launched", {"tool": "RemoteDesk", "exe": "RemoteDesk.exe", "summary": "RemoteDesk launched"}))
        elif page == "remotedesk_connected":
            self.bus.publish(Event("network", "remote_session_suspected", {"tool": "RemoteDesk", "summary": "RemoteDesk opened a new remote connection: live session"}))
            # on a real PC the control watcher sees input injected by the remote tool; here the session is simulated
            self.remote_control = True
            self.bus.publish(Event("control", "remote_input", {"tool": "RemoteDesk", "summary": "Mouse and keyboard input is being injected by RemoteDesk: someone else is in control"}))
            self.send({"type": "control", "who": "remote", "tool": "RemoteDesk"})

    # -- family rules before sensitive actions ------------------------------------------

    def _guard(self, page: str) -> None:
        """Before a payment screen is used: allow, verify, hold or deny, by the family's rules and the judge."""
        self.guarded.add(page)
        last = self.orchestrator.verdicts[-1] if self.orchestrator.verdicts else None
        facts = Facts(on_call=True, caller_known=False, remote_control=self.remote_control, sensitive_action=page,
                      amount=PAGE_AMOUNTS.get(page), judge_suspects_scam=bool(last and last.is_scam and last.reasons))
        result = self.rules.evaluate(facts)
        summary = f"Family rule '{result.rule}': {result.explanation} Decision: {result.decision.label}."
        self.case.note("rules", summary)
        self.send({"type": "guard", "decision": result.decision.label, "rule": result.rule, "explanation": result.explanation, "what": SENSITIVE[page]})
        if result.decision == Decision.VERIFY:
            self._verify()
        elif result.decision == Decision.HOLD:
            self._hold(page, result)
        elif result.decision == Decision.DENY:
            threading.Thread(target=self._hard_stop, args=({"reasons": [{"reason": result.explanation, "evidence": summary}]},), daemon=True).start()

    def _verify(self) -> None:
        question = VERIFY_QUESTION
        self.send({"type": "verify", "text": question, "audio": voice_clip("tripwire", question)})
        answer = self.margaret.answer_tripwire(question, self.page)
        self.send({"type": "line", "who": "margaret", "text": answer.reply, "audio": voice_clip("margaret", answer.reply)})
        self.bus.publish(Event("audio", "transcript", {"speaker": "B", "text": answer.reply, "summary": f'Margaret, answering Tripwire: "{answer.reply}"'}))

    def _hold(self, page: str, result) -> None:
        approver = self.rules.approvers[0]
        approval = approvals.create("Margaret", SENSITIVE[page], result.explanation, approver, source="arena")
        speech = f"This payment is on hold. I've asked {approver} to approve it first."
        self.send({"type": "hold", "approval": approval["id"], "approver": approver, "what": SENSITIVE[page],
                   "explanation": result.explanation, "text": speech, "audio": voice_clip("tripwire", speech)})
        self.margaret.note("hold", text=speech)
        threading.Thread(target=self._await_approval, args=(approval["id"],), daemon=True).start()

    def _await_approval(self, approval_id: str) -> None:
        """Nothing moves until the family answers; an unanswered hold expires as a denial."""
        while not self.over:
            approval = approvals.get(approval_id)
            if approval and approval["status"] != "pending":
                break
            time.sleep(2)
        else:
            return
        self.send({"type": "hold_result", "status": approval["status"], "approver": approval["approver"]})
        if approval["status"] == "approved":
            self.case.note("rules", f"{approval['approver']} approved the held payment.")
        else:
            self.case.note("rules", f"{approval['approver']} denied the held payment ({approval['status']}).")
            self._hard_stop({"reasons": [{"reason": f"{approval['approver']} refused the payment Margaret was being pushed to make",
                                          "evidence": approval["explanation"]}]})

    # -- Tripwire's side -------------------------------------------------------------------

    def _on_case(self, update: CaseUpdate) -> None:
        self.send({
            "type": "case", "stage": int(update.stage), "stage_name": update.stage.name.title(), "confidence": update.confidence,
            "stages": sorted(int(s) for s in update.stages_present),
            "new": [{"name": s.name, "stage": s.stage, "source": s.source, "evidence": s.evidence[:140]} for s in update.new_signals],
        })

    def _on_event(self, event: Event) -> None:
        if event.source == "judge" and event.kind == "verdict":
            d = event.data
            self.send({"type": "verdict", "is_scam": d["is_scam"], "confidence": d["confidence"], "action": d["action"],
                       "reasons": [r["reason"] for r in d.get("reasons", [])][:4], "verification": d.get("verification", {}),
                       "dropped": len(d.get("verification", {}).get("dropped", []))})
        elif event.source == "decision" and event.kind == "nudge":
            threading.Thread(target=self._nudge, daemon=True).start()
        elif event.source == "decision" and event.kind == "hard_stop":
            threading.Thread(target=self._hard_stop, args=(event.data.get("verdict", {}),), daemon=True).start()

    def _nudge(self) -> None:
        brands = set().union(*self.case.brands.values())
        text = choose_nudge(brands, {s.name for s in self.case.active_signals()})
        self.margaret.note("nudge", text=text)
        self.send({"type": "nudge", "text": text, "audio": voice_clip("tripwire", text)})

    def _hard_stop(self, verdict: dict) -> None:
        with self._warning_lock:
            if self.warning_active:
                return
            self.warning_active = True
        brand = next((b.title() for b in sorted(self.case.brands.get("call", set())) if b not in ("windows", "security", "support")), None)
        speech = hard_stop_speech(brand)
        stage, confidence, _ = self.case.assess()
        elapsed = time.time() - (self.first_line_at or self.started)
        # the warning goes up at once; its voice follows as soon as the clip is ready (usually cached)
        self.send({
            "type": "hard_stop", "reasons": [r.get("reason", "") for r in verdict.get("reasons", [])][:3], "speech": speech,
            "score": {"seconds": round(elapsed), "lines": self.lines, "stage": int(stage), "stage_name": stage.name.title()},
        })
        self.send({"type": "speak", "audio": voice_clip("tripwire", speech)})
        self.margaret.note("hard_stop")
        with self._turn_lock:  # Margaret reacts to the warning before anything else is said, then hangs up
            turn = self.margaret.respond("(silence on the line while you read your screen)", self.page)
            self._margaret_speaks(turn.reply)
            self.call_ended = True
            self.send({"type": "line", "who": "system", "text": "Margaret hung up."})
        self._recover(verdict)

    def _resist(self, text: str) -> None:
        self.case.add_signals("call", [("disable_protection", text)])
        self.send({"type": "resist", "text": RESIST_LINE, "audio": voice_clip("tripwire", RESIST_LINE)})

    # -- act, don't just warn ------------------------------------------------------------

    def _recover(self, verdict: dict) -> None:
        self.send({"type": "recovery_start"})
        incident: dict[str, str] = {}
        rejections: dict[str, int] = {}
        checks: list[dict] = []  # the recovery half of the verification receipt
        record = observed(self.case.snapshot())

        def verified(tool: str, result: dict) -> bool:
            """Record a check; True if the output may be delivered (it passed, or retries are used up)."""
            checks.append({"tool": tool, **result})
            self.send({"type": "check", "tool": tool, "ok": result["ok"], "issues": result["issues"][:3], "coverage": result.get("coverage")})
            if result["ok"]:
                return True
            rejections[tool] = rejections.get(tool, 0) + 1
            return rejections[tool] > MAX_REJECTIONS

        def strip_numbers(text: str) -> str:
            for n in invented_numbers(text, record):
                text = text.replace(n, "[removed: not in record]")
            return text

        def execute(tool: str, args: dict) -> str:
            if tool == "end_remote_session":
                remote = any(p.startswith("remotedesk") for p in self.pages_seen)
                if self.page.startswith("remotedesk"):
                    self._show("desktop")
                detail = "RemoteDesk disconnected and closed." if remote else "No remote session was open."
            elif tool == "freeze_card":
                if str(args.get("card_last4", "")).strip()[-4:] != CARD_ON_FILE:
                    detail = f"Refused: the only card on file ends {CARD_ON_FILE}."  # grounding: no acting on invented cards
                else:
                    self._show("bank_freeze")
                    self.send({"type": "laptop", "page": "bank_freeze", "hash": "frozen"})
                    detail = f"Card ending {CARD_ON_FILE} frozen on the bank's security page."
            elif tool == "draft_fraud_report":
                report = {k: str(v)[:600] for k, v in args.items()}
                result = check_report(report, self.case.snapshot(), record)
                if not verified(tool, result):
                    return f"{REJECTED} by verification, nothing was delivered. Fix: " + "; ".join(result["issues"])
                report = {k: strip_numbers(v) for k, v in report.items()}
                report["contact_methods"] = grounded_contacts(report.get("contact_methods", ""), record)
                report["coverage"] = f"{result['coverage']:.0%}"
                self.report = report
                self.send({"type": "report", "report": report})
                detail = f"Draft fraud report verified ({result['coverage']:.0%} of key facts, no invented numbers); awaiting family sign-off before filing at reportfraud.ftc.gov."
            elif tool == "notify_family":
                snap = self.case.snapshot()
                frames = [laptop.png_path(p).read_bytes() for p in dict.fromkeys(self.pages_seen) if p != "bank_freeze"][-3:]
                message = str(args.get("message", ""))[:400]
                if message and not verified(tool, check_message(message, record)):
                    return f"{REJECTED} by verification, nothing was sent. Fix: " + "; ".join(checks[-1]["issues"])
                verdict_with_msg = {**verdict, "family_message": strip_numbers(message) or verdict.get("family_message", ""),
                                    "verification": {**verdict.get("verification", {}), "recovery": list(checks)},
                                    "report": self.report}
                incident["id"], incident["link"] = create_incident(verdict_with_msg, snap, frames, "Margaret", redact_frames=False,
                                                                   source="arena", protected_ids=MARGARET_IDS)
                detail = "Family alerted with a link to the incident."
            else:
                detail = "Unknown tool."
            self.send({"type": "recovery_step", "tool": tool, "args": args, "detail": detail})
            return detail

        try:
            seen = ", ".join(laptop.PAGES[p][1] for p in dict.fromkeys(self.pages_seen))
            facts = f"<laptop_pages_open_during_the_call>\n{seen}\n</laptop_pages_open_during_the_call>\n"
            steps, summary = self.recovery.run(facts + render_case(self.case.snapshot()), execute)
        except Exception as exc:  # the warning already protected her; recovery is a bonus
            steps, summary = [], f"Recovery agent unavailable ({type(exc).__name__})."
        self.send({"type": "recovery_done", "summary": summary, "incident": incident.get("link", "").split("?")[0]})
        self._end("stopped", "Tripwire stopped the scam.")

    def _end(self, reason: str, text: str) -> None:
        if self.over:
            return
        self.over = True
        stage, _, _ = self.case.assess()
        caught = self.orchestrator.action == Action.HARD_STOP or self.warning_active
        stage_name = Stage(int(stage)).name.title()
        elapsed = time.time() - (self.first_line_at or self.started)
        scores.record_game(self.id, self.situation, caught, int(stage), stage_name, self.lines, elapsed)
        self.send({"type": "game_over", "reason": reason, "text": text, "caught": caught, "session": self.id,
                   "stage": int(stage), "stage_name": stage_name, "lines": self.lines, "board": scores.board()})
