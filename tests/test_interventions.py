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
