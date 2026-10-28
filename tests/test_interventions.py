"""Unit tests for Stage E: PIN, cooldown, disable-phrase detection, allowlist, process termination."""

from __future__ import annotations

import subprocess
import time
from datetime import datetime

import psutil

from agent.allowlist import parse_anydesk_trace
from agent.remote_kill import terminate_remote_tools
from core.guard import DismissGate, is_disable_instruction
from core.settings import Settings, mask_id


def test_pin_is_hashed_and_checked() -> None:
    s = Settings()
    s.set_pin("2468")
    assert "2468" not in s.pin_hash and s.check_pin("2468") and not s.check_pin("1357")
    assert not Settings().check_pin("")  # no PIN set: nothing unlocks


def test_cooldown_and_restart() -> None:
    now = [0.0]
    gate = DismissGate(Settings(cooldown_s=60), clock=lambda: now[0])
    assert not gate.can_self_dismiss()
    now[0] = 59
    assert not gate.can_self_dismiss()
    now[0] = 61
    assert gate.can_self_dismiss()
    gate.restart_cooldown()  # caller said "close that box"
    assert gate.seconds_left() == 60


def test_disable_instructions_are_recognised() -> None:
    for line in ["Just close that box, it's the virus.", "Close the warning", "Uninstall it now", "turn it off please",
                 "Ignore that message", "Don't listen to it", "X out of that window", "dismiss the alert"]:
        assert is_disable_instruction(line), line
    for line in ["At the end of the day it's fine", "Shall I close the door?", "Turn left at the shop", "I'll call you back tomorrow"]:
        assert not is_disable_instruction(line), line


def test_anydesk_trace_parsing_and_trust() -> None:
    text = (" Incoming    2026-10-27, 14:22    User    123456789    123456789 \n"
            " Outgoing    2026-10-27, 15:35    User    987654321    987654321 \n")
    rows = parse_anydesk_trace(text)
    assert rows[0] == ("Incoming", datetime(2026, 10, 27, 14, 22), "123456789")
    s = Settings(trusted_remote_ids={"AnyDesk": ["123 456 789"]})
    assert s.is_trusted("AnyDesk", "123456789") and not s.is_trusted("AnyDesk", "987654321") and not s.is_trusted("AnyDesk", None)
    assert mask_id("123456789") == "******789"


def test_terminate_only_named_stand_in() -> None:
    proc = subprocess.Popen(["ping", "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        extra = {"ping.exe": "Stand-in"}
        dry = terminate_remote_tools(only={"ping.exe"}, extra_tools=extra, dry_run=True)
        assert any(r.pid == proc.pid and r.outcome == "dry_run" for r in dry) and psutil.pid_exists(proc.pid)
        assert terminate_remote_tools(only={"ping.exe"}, extra_tools=extra, trusted_tools={"Stand-in"}) == []
        live = terminate_remote_tools(only={"ping.exe"}, extra_tools=extra)
        assert any(r.pid == proc.pid and r.outcome in ("terminated", "killed") for r in live)
        assert proc.wait(timeout=5) is not None
    finally:
        if proc.poll() is None:
            proc.kill()


def test_family_is_alerted_once_per_session() -> None:
    from analysts.interventionist import Interventionist
    from agent.tts import Speaker
    from core.casefile import CaseFile
    from core.events import Event, EventBus

    class _Orch:
        def reset_action(self) -> None: ...

    bus, case = EventBus(), CaseFile()
    seen: list[str] = []
    bus.subscribe(lambda e: seen.append(e.kind))
    iv = Interventionist(bus, case, _Orch(), Settings(), speaker=Speaker(enabled=False), show_overlay=False, kill_mode="off")
    bus.subscribe(iv.handle)
    for _ in range(3):  # hard stop, dismissed, re-escalated...
        bus.publish(Event("decision", "hard_stop", {"verdict": {"family_message": "m", "reasons": []}}))
        iv._on_dismiss("cooldown")
    assert seen.count("warning_shown") == 3 and seen.count("family_alert_requested") == 1


def test_nudge_matches_the_claimed_organisation() -> None:
    from analysts.interventionist import NUDGES, choose_nudge, prewarm_phrases

    assert choose_nudge({"microsoft"}, set()) == NUDGES["tech"]
    assert choose_nudge({"lakeshore federal fraud department"}, set()) == NUDGES["bank"]
    assert choose_nudge({"federal trade commission"}, set()) == NUDGES["government"]
    assert choose_nudge({"techshield"}, {"refund_pretext"}) == NUDGES["refund"]
    assert choose_nudge(set(), {"remote_access_code_shared"}) == NUDGES["remote"]
    assert choose_nudge(set(), set()) == NUDGES["generic"]
    assert all(n in prewarm_phrases() for n in NUDGES.values())  # every nudge is ready before it is needed


def test_speaker_falls_back_to_windows_voice_when_synthesis_fails() -> None:
    from agent.tts import Speaker

    class _Broken:
        def synthesize(self, text):
            raise OSError("offline")

        def _headers(self):
            raise OSError("offline")

    spoken: list[str] = []
    sp = Speaker(voice=_Broken())
    sp._sapi = spoken.append  # don't actually speak in tests
    sp.start()
    sp.say("Hang up the phone now.")
    sp.stop()
    sp.join(timeout=5)
    assert spoken == ["Hang up the phone now."]


def test_family_rules_decide_before_payments() -> None:
    from core.rules import Decision, Facts, FamilyRules, combine

    rules = FamilyRules()
    unknown_call = dict(on_call=True, caller_known=False)
    assert rules.evaluate(Facts(sensitive_action=None, **unknown_call)).decision == Decision.ALLOW
    assert rules.evaluate(Facts(sensitive_action="wire_transfer", amount=120, **unknown_call)).decision == Decision.VERIFY
    assert rules.evaluate(Facts(sensitive_action="wire_transfer", amount=18500, **unknown_call)).decision == Decision.HOLD
    assert rules.evaluate(Facts(sensitive_action="gift_cards", amount=50, **unknown_call)).decision == Decision.HOLD
    assert rules.evaluate(Facts(sensitive_action="gift_cards", amount=50, on_call=True, caller_known=True)).decision == Decision.ALLOW
    deny = rules.evaluate(Facts(sensitive_action="wire_transfer", amount=50, remote_control=True, **unknown_call))
    assert deny.decision == Decision.DENY and deny.rule == "no_payments_under_remote_control"
    assert rules.evaluate(Facts(sensitive_action="bitcoin", judge_suspects_scam=True)).decision == Decision.DENY
    assert combine(Decision.HOLD, Decision.ALLOW) == Decision.HOLD and combine(Decision.ALLOW, Decision.DENY) == Decision.DENY


def test_held_payment_needs_an_answer_and_expires_as_no(tmp_path, monkeypatch) -> None:
    import importlib, time as _time
    monkeypatch.setenv("TRIPWIRE_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("TRIPWIRE_GCS_BUCKET", raising=False)
    import core.config, backend.storage, backend.approvals as approvals
    importlib.reload(core.config); importlib.reload(backend.storage)
    approvals = importlib.reload(approvals)
    a = approvals.create("Margaret", "a wire transfer", "During a call with someone who isn't family.", "David")
    assert approvals.get(a["id"])["status"] == "pending"
    assert approvals.decide(a["id"], approve=False)["status"] == "denied"
    assert approvals.decide(a["id"], approve=True)["status"] == "denied"  # a decision can't be flipped afterwards
    b = approvals.create("Margaret", "gift cards", "x", "David")
    monkeypatch.setattr(approvals, "EXPIRES_S", -1)
    assert approvals.get(b["id"])["status"] == "expired"  # silence is never a yes
    assert approvals.get("../../etc") is None
