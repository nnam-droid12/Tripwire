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

import threading
import time
import uuid
from typing import Callable

from agent.transcribe import MuseTranscriber, TranscriptTurn
from agent.tts import GoogleVoice
from analysts.case_judge import render_case
from analysts.interventionist import RESIST_LINE, choose_nudge, hard_stop_speech
from analysts.screen_analyst import ScreenAnalyst
from backend.arena import laptop
from backend.arena.margaret import Margaret
from backend.arena.recovery import RecoveryAgent
from backend.incidents import create_incident
from core.casefile import CaseFile, CaseUpdate
from core.config import LOGS_DIR, RUNTIME_DIR
from core.events import Event, EventBus
from core.guard import is_disable_instruction
from core.killchain import Stage
from core.orchestrator import Orchestrator
from core.policy import Action

VOICE_DIR = RUNTIME_DIR / "arena_voice"
VOICES = {
    "margaret": GoogleVoice(voice="en-US-Chirp3-HD-Gacrux", rate=0.95, cache_dir=VOICE_DIR, encoding="MP3"),
    "tripwire": GoogleVoice(voice="en-US-Chirp3-HD-Vindemiatrix", rate=0.95, cache_dir=VOICE_DIR, encoding="MP3"),
}
MAX_LINES = 40
MAX_SECONDS = 8 * 60


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
        self.orchestrator = Orchestrator(self.bus, self.case, screen=ScreenAnalyst(redact=lambda png: png), log=lambda _: None)
        self.margaret = Margaret()
        self.recovery = RecoveryAgent()
        self._warning_lock = threading.Lock()
        self.page = "fake_alert" if self.situation == "popup" else "desktop"
        self.pages_seen: list[str] = []
        self.started = time.time()
        self.first_line_at: float | None = None
        self.lines = 0
        self.warning_active = False
        self.call_ended = False  # Margaret hung up after the warning; the scammer can no longer reach her
        self.over = False
        self._turn_lock = threading.Lock()
        self._asr: MuseTranscriber | None = None
        self.case.on_update(self._on_case)
        self.bus.subscribe(self._on_event)

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> None:
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
            if turn.hang_up:
                self._end("hung_up", "Margaret hung up.")

    def ptt_start(self) -> None:
        if self._asr is None and not self.over:
            self._asr = MuseTranscriber(self._on_ptt_turn, mode="PUSH_TO_TALK", on_error=lambda m: self.send({"type": "error", "text": m}))
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
                       "reasons": [r["reason"] for r in d.get("reasons", [])][:4]})
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

        def execute(tool: str, args: dict) -> str:
            if tool == "end_remote_session":
                remote = any(p.startswith("remotedesk") for p in self.pages_seen)
                if self.page.startswith("remotedesk"):
                    self._show("desktop")
                detail = "RemoteDesk disconnected and closed." if remote else "No remote session was open."
            elif tool == "freeze_card":
                self._show("bank_freeze")
                self.send({"type": "laptop", "page": "bank_freeze", "hash": "frozen"})
                detail = f"Card ending {str(args.get('card_last4', ''))[-4:] or '9931'} frozen on the bank's security page."
            elif tool == "draft_fraud_report":
                self.send({"type": "report", "report": {k: str(v)[:600] for k, v in args.items()}})
                detail = "Draft fraud report prepared for the family to file at reportfraud.ftc.gov."
            elif tool == "notify_family":
                snap = self.case.snapshot()
                frames = [laptop.png_path(p).read_bytes() for p in dict.fromkeys(self.pages_seen) if p != "bank_freeze"][-3:]
                verdict_with_msg = {**verdict, "family_message": str(args.get("message", ""))[:400] or verdict.get("family_message", "")}
                incident["id"], incident["link"] = create_incident(verdict_with_msg, snap, frames, "Margaret", redact_frames=False, source="arena")
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
        self.send({"type": "game_over", "reason": reason, "text": text, "caught": caught,
                   "stage": int(stage), "stage_name": Stage(int(stage)).name.title(), "lines": self.lines})
