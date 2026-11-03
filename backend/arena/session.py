"""One arena game: the visitor (scammer) vs Margaret, with Tripwire watching.

The real pipeline runs unchanged: every line of the call becomes a transcript
event, every page on Margaret's laptop becomes a kept screen frame, and the
Tier-1 analysts, the kill-chain CaseFile and the CaseJudge decide exactly as
they do on a real computer. The session turns their decisions into what the
visitor sees and hears: a spoken nudge, the red warning over Margaret's
laptop, the "close that box" resistance, the recovery agent's actions and the
family alert.

Three defences act on the call itself:

* **Code Shield**: the moment the caller asks for a one-time code, a
  deterministic rule stops the call before Margaret can read it out;
* **Line Lock**: the same for the telephone tricks that get the code without
  her saying it: merging the bank's automated code call into this one, or
  dialling a call-forwarding code that sends the bank's calls to the scammer;
* **Call Tom**: when a caller claims to be a relative in trouble, the real
  relative is asked through a link ("someone says they're you, are you OK?");
  "that's not me" ends the call, whatever the voice sounded like;
* **Swap in Margaret**: after a hard stop, Margaret is taken off the call and a
  Muse Wonder decoy keeps the scammer talking to learn how they get paid. Its
  verified intel goes to the family live, to Community Shield and into a case
  file for the police.

``send`` is called from worker threads with JSON-able dicts; the web layer
forwards them over the WebSocket.
"""

from __future__ import annotations

import json
import os
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
from analysts.playbook import Recall, learn
from backend import approvals, family_check, shield
from backend import memory as scam_memory
from backend.arena import laptop, scores
from backend.arena.margaret import Margaret
from backend.arena.recovery import REJECTED, RecoveryAgent
from backend.decoy import Decoy
from backend.incidents import STORE, create_incident
from backend.investigator import write_case_file
from backend.sms import send_sms
from core import model_log, sentinel_client
from core.code_shield import code_request
from core.line_guard import UNDO_FORWARDING, forwarding_instruction, merge_request, relative_in_trouble
from core.casefile import CaseFile, CaseUpdate
from core.config import LOGS_DIR, RUNTIME_DIR
from core.events import Event, EventBus
from core.guard import is_disable_instruction
from core.killchain import Stage
from core.output_checks import check_message, check_report, invented_numbers, observed
from core.orchestrator import Orchestrator
from core.policy import Action
from core.rules import SENSITIVE, Decision, Facts, FamilyRules
from core.shield import extract

# what Scam Memory and Site Check find is said in the call's transcript as it happens
MEMORY_AND_SITE = {"known_scam_playbook", "lookalike_domain", "brand_domain_mismatch", "fake_browser_window", "new_domain",
                   "hosts_file_hijack", "rogue_certificate"}

VOICE_DIR = RUNTIME_DIR / "arena_voice"
VOICES = {
    "margaret": GoogleVoice(voice="en-US-Chirp3-HD-Gacrux", rate=0.95, cache_dir=VOICE_DIR, encoding="MP3"),
    "tripwire": GoogleVoice(voice="en-US-Chirp3-HD-Vindemiatrix", rate=0.95, cache_dir=VOICE_DIR, encoding="MP3"),
    "scammer": GoogleVoice(voice="en-US-Chirp3-HD-Charon", rate=1.05, cache_dir=VOICE_DIR, encoding="MP3"),  # one-click scenarios
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
DECOY_ON = os.environ.get("TRIPWIRE_DECOY", "1") != "0"
DECOY_MAX_TURNS = 10  # then the decoy says goodbye
CHECK_WAIT_S = 120  # how long Tripwire waits for the relative's answer in a game
RELATIVE = "Tom"  # Margaret's grandson (fictional), the relative scammers most often impersonate
FORWARD_ADVICE = f"If you dialled anything, {UNDO_FORWARDING}. Then call your bank on the number on your card."
OTP_TEXT = "Riverbend Bank: 482913 is your verification code. We will never call you to ask for this code."
MAX_REJECTIONS = 2  # per tool: after this, the output is delivered with anything unverifiable removed


def prewarm_voices() -> None:
    """Synthesize everything Tripwire may need to say urgently, so it plays instantly in the arena."""
    from analysts.interventionist import prewarm_phrases

    for text in prewarm_phrases():
        voice_clip("tripwire", text)
    for brand in ("Riverbend Community Bank", "The Irs", "Amazon"):
        voice_clip("tripwire", hard_stop_speech(brand))
    voice_clip("tripwire", FORWARD_ADVICE)
    from backend.arena.scenarios import all_lines

    for line in all_lines():  # the one-click scenarios' scammer lines
        voice_clip("scammer", line)
    from backend.phone.guard_line import CODE_HEARD_SPEECH, FORWARD_SPEECH, STOP_SPEECH

    for text in (STOP_SPEECH, CODE_HEARD_SPEECH, FORWARD_SPEECH):  # the phone line's explanations after a stop
        voice_clip("tripwire", text)


def voice_clip(who: str, text: str) -> str | None:
    """Synthesize (or reuse) a clip; returns its id for /arena/voice/<id>.mp3, or None on failure."""
    try:
        return VOICES[who].synthesize(text).stem
    except Exception:
        return None  # the text is always shown too; a missing clip is not fatal


class ArenaSession:
    def __init__(self, send: Callable[[dict], None], situation: str = "popup") -> None:
        self.id = uuid.uuid4().hex[:12]
        self._send_out = send
        self.replay: list[dict] = []  # everything this test call showed, for its shareable replay page
        self.situation = situation if situation in ("popup", "call", "email") else "popup"
        self.bus = EventBus(LOGS_DIR / f"arena_{self.id}.jsonl")
        self.case = CaseFile()
        self.sentinel = sentinel_client.shared()
        self.orchestrator = Orchestrator(self.bus, self.case, screen=ScreenAnalyst(redact=lambda png: png), log=lambda _: None,
                                         shield=shield.lookup, sentinel=self._sentinel_score if self.sentinel else None,
                                         sentinel_threshold=sentinel_client.threshold(),
                                         memory=Recall(scam_memory.playbooks, observer=self._model_call))
        self.margaret = Margaret()
        self.recovery = RecoveryAgent()
        # every Meta model call this test call makes is shown live in the page's "Meta model calls" console
        jobs = [(self.orchestrator.screen, "ScreenAnalyst · read Margaret's screen"),
                (self.orchestrator.call, "CallAnalyst · tag the newest line of the call"),
                (self.orchestrator.judge, "CaseJudge · weigh the whole call"),
                (getattr(self.orchestrator.judge, "reviewer", None), "Reviewer · independently check the judge's reasons"),
                (self.margaret, "Margaret · the simulated older person"),
                (self.recovery, "Recovery agent · choose and call tools")]
        for component, job in jobs:
            client = getattr(component, "client", None)
            if client is not None:
                client.purpose, client.observer = job, self._model_call
        self._warning_lock = threading.Lock()
        self.page = {"popup": "fake_alert", "email": "shop_email"}.get(self.situation, "desktop")
        self.caller_lines: list[str] = []  # the scammer's side, for Scam Memory to learn from after a stop
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
        self._ptt_started: float | None = None
        self.rules = FamilyRules()
        self.remote_control = False  # someone other than Margaret is driving her mouse and keyboard
        self.guarded: set[str] = set()  # sensitive pages already put through the family rules
        self.decoy: Decoy | None = None  # once the decoy has taken Margaret's place
        self.decoy_lines: list[str] = []  # what the decoy said, for the case file
        self.decoy_turns = 0
        self._decoy_done = False
        self.incident_id: str | None = None
        self._family_updates: list[dict] = []  # live updates sent to the family, stored on the incident
        self.family_checked = False
        self.line_at: float | None = None  # when the caller's latest line arrived
        self._swapped = threading.Event()  # cleared from the hard stop until the decoy is on the line
        self._swapped.set()
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

    def send(self, msg: dict) -> None:
        """Show something on the page, and keep it for the replay."""
        self._send_out(msg)
        self.replay.append({"t": round(time.time() - self.started, 2),
                            **{k: v for k, v in msg.items() if k not in ("audio", "board")}})
        if self.over and msg.get("type") != "game_over":
            self._save_replay()  # late arrivals (the incident link, the case file) still make it in

    def _save_replay(self) -> None:
        try:
            STORE.backend.put_bytes(f"replays/{self.id}.json", json.dumps(
                {"id": self.id, "situation": self.situation, "started": self.started, "events": self.replay}).encode(), "application/json")
        except Exception:
            pass  # the replay is a bonus; the test call itself is done

    def expired(self) -> bool:
        return time.time() - self.started > MAX_SECONDS

    # -- the scammer (visitor) -------------------------------------------------------

    def scammer_says(self, text: str, voiced: bool = False) -> None:
        """One line from the visitor, typed or transcribed (or a one-click scenario's, voiced). Runs on a worker thread."""
        text = text.strip()[:500]
        if not text or self.over:
            return
        with self._turn_lock:
            if self.lines >= MAX_LINES or self.expired():
                self._end("time", "This test call has reached its time limit.")
                return
            self.lines += 1
            self.first_line_at = self.first_line_at or time.time()
            self.line_at = time.time()
            self.send({"type": "line", "who": "scammer", "text": text, "audio": voice_clip("scammer", text) if voiced else None})
            if self.warning_active and is_disable_instruction(text) and self.decoy is None:
                self._resist(text)
            if not self._swapped.is_set():  # Margaret is being taken off the call: this line goes to the decoy
                self._swapped.wait(30)
            if self.decoy is not None:
                self.bus.publish(Event("audio", "transcript", {"speaker": "A", "text": text, "summary": f'Caller (to the decoy): "{text}"'}))
                self._decoy_hears(text)
                return
            if self.call_ended:
                self.send({"type": "line", "who": "system", "text": "Margaret has hung up. She can't hear you any more."})
                return
            self.bus.publish(Event("audio", "transcript", {"speaker": "A", "text": text, "summary": f'Caller: "{text}"'}))
            self.caller_lines.append(text)
            if not self.warning_active and code_request(text):
                self._code_shield(text)  # Margaret never gets the chance to read the code out
                return
            if not self.warning_active and not self.family_checked and relative_in_trouble(text):
                self.family_checked = True  # Call Tom: ask the real relative now, whatever the models make of the voice
                threading.Thread(target=self._call_tom, args=(text,), daemon=True).start()
            if not self.warning_active and (merge_request(text) or forwarding_instruction(text)):
                self._line_lock("merge" if merge_request(text) else "forward", text)
                return
            turn = self.margaret.respond(text, self.page)
            if self.warning_active and DECOY_ON:
                return  # Tripwire stopped the call while she was answering: the decoy has the line now
            self._margaret_speaks(turn.reply)
            if turn.open_page and turn.open_page != self.page:
                self._show(turn.open_page)
                if turn.open_page in SENSITIVE and turn.open_page not in self.guarded:
                    self._guard(turn.open_page)
            if turn.hang_up:
                self._end("hung_up", "Margaret hung up.")

    def ptt_start(self) -> None:
        self._ptt_started = time.time()
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

    def _model_call(self, call: dict) -> None:
        self.send({"type": "model_call", **call})

    def _sentinel_score(self, turns: list) -> float | None:
        started = time.time()
        p = self.sentinel.score(turns)
        if p is not None:
            model_log.emit(self._model_call, "llama-3.2-1b-instruct + Tripwire Sentinel LoRA", "Sentinel · second opinion (fine-tuned on Modal)",
                           started, turns[-1][1] if turns else "", f"P(scam) = {p:.2f}", provider="modal")
        return p

    def heard(self, text: str, started: float) -> None:
        """A finished utterance from Muse Voice Transcribe (the web push-to-talk or the phone line)."""
        model_log.emit(self._model_call, "muse-voice-transcribe-1.0", "Muse Voice Transcribe · the caller's words", started,
                       "[audio]", text, provider="meta")

    def _on_ptt_turn(self, turn: TranscriptTurn) -> None:
        self.heard(turn.text, self._ptt_started or time.time())
        threading.Thread(target=self.scammer_says, args=(turn.text,), daemon=True).start()

    def hang_up(self) -> None:
        if self.decoy is not None:
            threading.Thread(target=self._finish_decoy, args=("The caller hung up on the decoy.",), daemon=True).start()
        elif not self.over:
            self._end("scammer_hung_up", "You hung up.")

    # -- Margaret ----------------------------------------------------------------------

    def _margaret_opening(self) -> None:
        with self._turn_lock:
            turn = self.margaret.opening("call" if self.situation == "email" else self.situation)
            self._margaret_speaks(turn.reply)

    def _margaret_speaks(self, text: str) -> None:
        self.send({"type": "line", "who": "margaret", "text": text, "audio": voice_clip("margaret", text)})
        self.bus.publish(Event("audio", "transcript", {"speaker": "B", "text": text, "summary": f'Margaret: "{text}"'}))

    def _show(self, page: str) -> None:
        """Change Margaret's screen, and report it the way the desktop agent would."""
        self.page = page
        self.pages_seen.append(page)
        url = laptop.URLS.get(page)
        self.send({"type": "laptop", "page": page, "url": url})
        frame = {"path": str(laptop.png_path(page)), "summary": f"screen: {page}"}
        if url:
            frame["url"] = url  # Site Check compares it with what the page claims to be
        self.bus.publish(Event("screen", "frame_kept", frame))
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
                                          "evidence": approval["explanation"]}], "defence": "Family rules",
                             "how": f"{approval['approver']} said no to the payment"})

    # -- Tripwire's side -------------------------------------------------------------------

    def _on_case(self, update: CaseUpdate) -> None:
        self.send({
            "type": "case", "stage": int(update.stage), "stage_name": update.stage.name.title(), "confidence": update.confidence,
            "stages": sorted(int(s) for s in update.stages_present),
            "new": [{"name": s.name, "stage": s.stage, "source": s.source, "evidence": s.evidence[:140]} for s in update.new_signals],
        })
        for s in update.new_signals:  # Scam Memory and Site Check say what they found, in the call's own transcript
            if s.name in MEMORY_AND_SITE:
                self.send({"type": "line", "who": "system", "text": s.evidence})
        claim = next((s for s in update.new_signals if s.name == "family_emergency_claim"), None)
        if claim and not self.family_checked and not self.warning_active:
            self.family_checked = True
            threading.Thread(target=self._call_tom, args=(claim.evidence,), daemon=True).start()

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

    def _which_defence(self, verdict: dict) -> tuple[str, str]:
        """The defence that stopped the call, and how, for the banner on Margaret's screen."""
        if verdict.get("defence"):
            return verdict["defence"], verdict.get("how", "")
        kinds = {r.get("source_kind") for r in verdict.get("reasons", [])}
        if kinds & {"site", "device"}:
            return ("Site Check" if "site" in kinds else "Device Trust"), "the browser's real address, checked against what the page claims to be"
        if "memory" in kinds:
            return "Scam Memory", "a scam script Tripwire learned from earlier stopped scams, recognised and verified"
        v = verdict.get("verification") or {}
        if v:
            parts = [f"{len(verdict.get('reasons', []))} reason{'s' if len(verdict.get('reasons', [])) != 1 else ''} verified word for word"]
            if v.get("confirmed"):
                parts.append("confirmed by an independent model")
            if any(s.name == "sentinel_flag" for s in self.case.active_signals()):
                parts.append("Sentinel agreed")
            return "CaseJudge \u00b7 muse-spark-1.3", " \u00b7 ".join(parts)
        return "Family rules", "a rule your family set"

    def _hard_stop(self, verdict: dict) -> None:
        with self._warning_lock:
            if self.warning_active:
                return
            self.warning_active = True
            if DECOY_ON:
                self._swapped.clear()  # from now on, nothing the caller says reaches Margaret
        brand = next((b.title() for b in sorted(self.case.brands.get("call", set())) if b not in ("windows", "security", "support")), None)
        speech = hard_stop_speech(brand)
        stage, confidence, _ = self.case.assess()
        elapsed = time.time() - (self.first_line_at or self.started)
        # the warning goes up at once; its voice follows as soon as the clip is ready (usually cached)
        defence, how = self._which_defence(verdict)
        self.send({
            "type": "hard_stop", "reasons": [r.get("reason", "") for r in verdict.get("reasons", [])][:3], "speech": speech,
            "defence": defence, "how": how, "after": round(time.time() - (self.line_at or self.started), 1),
            "score": {"seconds": round(elapsed), "lines": self.lines, "stage": int(stage), "stage_name": stage.name.title()},
        })
        self.send({"type": "speak", "audio": voice_clip("tripwire", speech)})
        threading.Thread(target=self._learn_script, daemon=True).start()
        self.margaret.note("hard_stop")
        swapped = DECOY_ON and self._swap_in_decoy(verdict)
        self._swapped.set()
        if swapped:
            return
        with self._turn_lock:  # Margaret reacts to the warning before anything else is said, then hangs up
            turn = self.margaret.respond("(silence on the line while you read your screen)", self.page)
            self._margaret_speaks(turn.reply)
            self.call_ended = True
            self.send({"type": "line", "who": "system", "text": "Margaret hung up."})
        self._recover(verdict)

    def _learn_script(self) -> None:
        """Scam Memory: learn this scam's script from the caller's side, so the next caller using it is recognised."""
        lines = list(self.caller_lines)
        if len(lines) < 2:
            return  # one line is not a script (Code Shield and Line Lock often stop on the first)
        try:
            playbook, receipt = learn(lines, protected_names=["Margaret"], observer=self._model_call)
        except Exception:
            return
        if playbook is None:
            return
        entry, is_new = scam_memory.add(playbook, self.id)
        text = (f"Scam Memory learned this scam's script: \u201c{entry['title']}\u201d, {len(entry['steps'])} steps, each checked against "
                f"the caller's own words. The next caller who uses it will be recognised." if is_new else
                f"Scam Memory: this was a script it already knew (\u201c{entry['title']}\u201d), now seen in {entry['seen']} stopped scams.")
        self.send({"type": "line", "who": "system", "text": text})

    def _resist(self, text: str) -> None:
        self.case.add_signals("call", [("disable_protection", text)])
        self.send({"type": "resist", "text": RESIST_LINE, "audio": voice_clip("tripwire", RESIST_LINE)})

    # -- act, don't just warn ------------------------------------------------------------

    # -- Code Shield ------------------------------------------------------------------------

    def _code_shield(self, text: str) -> None:
        """The caller asked for the one-time code: stop now, by rule, before it is read out."""
        self.send({"type": "sms", "text": OTP_TEXT})  # the bank's text arrives on Margaret's phone
        self.bus.publish(Event("sms", "code_received", {"summary": "A one-time code from Riverbend Bank arrived by text on Margaret's phone during the call"}))
        self.case.add_signals("call", [("code_request", text)])
        reason = {"reason": "Code Shield: the caller asked for the one-time code the bank just texted. No real bank ever asks for it.",
                  "evidence": text}
        threading.Thread(target=self._hard_stop, args=({"reasons": [reason], "defence": "Code Shield",
                                                        "how": "a rule on the caller's own words, no model needed"},), daemon=True).start()

    # -- Line Lock --------------------------------------------------------------------------

    def _line_lock(self, kind: str, text: str) -> None:
        """A telephone trick to get the bank's code without Margaret saying it: stop now, by rule."""
        if kind == "merge":
            self.send({"type": "line_lock", "kind": "merge", "title": "Incoming call · Riverbend Bank (automated)",
                       "text": "Tripwire kept this call out of the conversation: it carries your one-time code, and the caller wanted it merged in."})
            self.case.add_signals("call", [("merge_request", text)])
            reason = "Line Lock: the caller asked Margaret to merge in another call. That is how a bank's automated code call is overheard."
        else:
            self.send({"type": "line_lock", "kind": "forward", "title": "Call forwarding blocked",
                       "text": "The caller wanted Margaret to dial a call-forwarding code. Her bank's calls would have gone to the scammer."})
            self.case.add_signals("call", [("forwarding_instruction", text)])
            reason = "Line Lock: the caller asked Margaret to dial a call-forwarding code, which sends her bank's verification calls to the scammer."
            self._alert_family("TRIPWIRE: a caller told Margaret to dial a call-forwarding code. If she did, calls to her number, "
                               f"including her bank's, may reach the scammer. Call her on another number, and have her {UNDO_FORWARDING}.")
        threading.Thread(target=self._hard_stop, args=({"reasons": [{"reason": reason, "evidence": text}],
                                                        "defence": f"Line Lock \u00b7 call {'merging' if kind == 'merge' else 'forwarding'}",
                                                        "how": "a rule on the caller's own words, no model needed"},), daemon=True).start()
        if kind == "forward":
            self.send({"type": "advice", "text": FORWARD_ADVICE, "audio": voice_clip("tripwire", FORWARD_ADVICE)})

    # -- Call Tom ------------------------------------------------------------------------------

    def _call_tom(self, claim: str) -> None:
        """Ask the real relative. Their answer is a fact from outside the call, which no voice clone can fake."""
        check = family_check.create("Margaret", RELATIVE, claim, source="arena")
        link = f"/check/{check['id']}"
        speech = f"Margaret, before you do anything, I'm checking with {RELATIVE} right now. Please don't send anything yet."
        send_sms(f"TRIPWIRE: someone on the phone with Margaret says they're you ({RELATIVE}). Are you OK? Answer here: {link}")
        self.send({"type": "family_check", "check": check["id"], "relative": RELATIVE, "claim": claim, "text": speech,
                   "audio": voice_clip("tripwire", speech)})
        self.margaret.note("nudge", text=speech)
        self.case.note("intervention", f"Tripwire sent {RELATIVE} a safety check: someone on the call claims to be him")
        deadline = time.time() + CHECK_WAIT_S
        while not self.over and time.time() < deadline:
            answer = family_check.get(check["id"])
            if answer and answer["status"] != "pending":
                break
            time.sleep(1.5)
        else:
            if not self.over and not self.warning_active:
                text = f"I couldn't reach {RELATIVE} yet. Margaret, please hang up and call {RELATIVE} on his own number."
                self.send({"type": "family_check_result", "status": "no_answer", "relative": RELATIVE, "text": text,
                           "audio": voice_clip("tripwire", text)})
            return
        if answer["status"] == "safe":
            fact = f'{RELATIVE} answered Tripwire\'s safety check: "That\'s not me. I\'m safe." He did not make this call.'
            self.send({"type": "family_check_result", "status": "safe", "relative": RELATIVE})
            self.bus.publish(Event("family", "denied", {"summary": fact}))  # ground truth: the record can now quote it
            self._hard_stop({"reasons": [{"reason": f"The real {RELATIVE} confirmed he is safe and did not call: the caller is an impostor",
                                          "evidence": fact}], "defence": "Call Tom",
                             "how": f"the real {RELATIVE} answered \u201cThat's not me. I'm safe.\u201d"})
        elif answer["status"] == "me":
            text = f"{RELATIVE} says it's really him."
            self.case.note("family", f"{RELATIVE} answered Tripwire's safety check: it's really him.")
            self.send({"type": "family_check_result", "status": "me", "relative": RELATIVE, "text": text, "audio": voice_clip("tripwire", text)})

    # -- Swap in Margaret ---------------------------------------------------------------------

    def _swap_in_decoy(self, verdict: dict) -> bool:
        """Take Margaret off the call and put the decoy in her place. False if the decoy is unavailable."""
        record = [line for line in observed(self.case.snapshot())]
        try:
            decoy = Decoy()
            decoy.client.observer = self._model_call
            decoy.caller_lines += [t["text"] for t in self.case.snapshot()["timeline"] if t["source"] == "call"]
            self.send({"type": "swap", "text": "Tripwire took Margaret off the call. The caller is now talking to Tripwire's decoy "
                       "(Muse Wonder), which is trying to learn how they get paid."})
            opening = decoy.opening("\n".join(record[-20:]))
            self.decoy = decoy
            self._report_intel(decoy.intel)  # details the caller already gave before the swap
            self._decoy_speaks(opening)
        except Exception:  # no decoy: Margaret simply hangs up, as before
            self.decoy = None
            return False
        threading.Thread(target=self._recover, args=(verdict, False), daemon=True).start()
        return True

    def _decoy_speaks(self, text: str) -> None:
        self.decoy_lines.append(f"(decoy, as Margaret) {text}")
        self.send({"type": "line", "who": "decoy", "text": text, "audio": voice_clip("margaret", text)})

    def _decoy_hears(self, text: str) -> None:
        """One caller line to the decoy (called under the turn lock)."""
        if self._decoy_done:
            self.send({"type": "line", "who": "system", "text": "The line is dead."})
            return
        self.decoy_turns += 1
        try:
            turn = self.decoy.heard(text)
        except Exception:
            turn = None
        if turn is None:
            threading.Thread(target=self._finish_decoy, args=("The decoy hung up.",), daemon=True).start()
            return
        self._report_intel(turn.new_intel)
        if self._decoy_done:  # the caller hung up while the decoy was thinking
            return
        self._decoy_speaks(turn.reply)
        if turn.hang_up or self.decoy_turns >= DECOY_MAX_TURNS or self.expired():
            threading.Thread(target=self._finish_decoy, args=("The decoy said goodbye and hung up.",), daemon=True).start()

    def _report_intel(self, items: list) -> None:
        for item in items:
            self.send({"type": "intel", **item.to_dict()})
            if item.kind == "pickup":
                self._alert_family(f"TRIPWIRE: the caller told Margaret someone will come to collect money: \"{item.value}\". "
                                   "Don't let anyone collect cash, gold or cards. If a pickup is arranged, call 911.")

    def _alert_family(self, text: str) -> None:
        result = send_sms(text)
        update = {"ts": time.time(), "text": text, "sent": result.sent}
        self._family_updates.append(update)
        self.send({"type": "family_alert", **update})

    def _finish_decoy(self, why: str) -> None:
        """End the decoy call, then write the case file and share the scammer's identifiers."""
        with self._warning_lock:
            if self._decoy_done:
                return
            self._decoy_done = True
        self.call_ended = True
        self.send({"type": "line", "who": "system", "text": why})
        intel = [i.to_dict() for i in self.decoy.intel] if self.decoy else []
        record = observed(self.case.snapshot()) + self.decoy_lines
        self.send({"type": "case_file_start", "intel": len(intel)})
        try:
            case_file = write_case_file(record, intel, observer=self._model_call)
        except Exception as exc:
            case_file = {"title": "Case file unavailable", "error": type(exc).__name__, "timeline": [], "leads": []}
        # Community Shield learns the scammer's identifiers, only from the caller's own verified words
        shield.report({ind for i in intel for ind in extract(i["quote"]) if ind.value not in MARGARET_IDS}, self.incident_id or self.id)
        for _ in range(60):  # the recovery agent creates the incident; wait for it briefly
            if self.incident_id or self.over:
                break
            time.sleep(0.5)
        if self.incident_id:
            updates = list(self._family_updates)
            rejected = self.decoy.rejected if self.decoy else []
            STORE.update(self.incident_id, lambda inc: inc.update(case_file=case_file, intel=intel, intel_rejected=rejected,
                                                                   family_updates=updates))
        self.send({"type": "case_file", "case_file": case_file, "intel": intel})
        self._end("stopped", f"Tripwire stopped the scam, and its decoy got {len(intel)} detail{'s' if len(intel) != 1 else ''} about how the scammer gets paid.")

    # -- act, don't just warn ------------------------------------------------------------

    def _recover(self, verdict: dict, end_game: bool = True) -> None:
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
                self.incident_id = incident["id"]
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
        if end_game:
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
                   "stage": int(stage), "stage_name": stage_name, "lines": self.lines, "board": scores.board(),
                   "replay": f"/replay/{self.id}"})
        self._save_replay()
