"""Unit tests for the pure Tier-0 logic: change detection, VAD, gating, watchers' matchers."""

from __future__ import annotations

import numpy as np
from PIL import Image, ImageDraw

from agent.capture_audio import FRAME_SAMPLES, AudioGate, EnergyVAD
from agent.capture_screen import FrameChangeDetector
from agent.watchers import match_remote_tool, scan_clipboard_text


def _desktop(popup: bool = False, cursor_x: int = 100) -> Image.Image:
    img = Image.new("RGB", (1280, 720), (30, 90, 160))
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 680, 1280, 720), fill=(20, 20, 20))  # taskbar
    draw.rectangle((cursor_x, 300, cursor_x + 4, 310), fill=(255, 255, 255))  # tiny cursor
    if popup:
        draw.rectangle((140, 80, 1140, 620), fill=(200, 0, 0))
        draw.text((400, 300), "VIRUS DETECTED - CALL NOW", fill=(255, 255, 255))
    return img


def test_frame_detector_keeps_first_and_big_changes_only() -> None:
    det = FrameChangeDetector()
    assert det.check(_desktop())[0] is True
    assert det.check(_desktop(cursor_x=104))[0] is False  # cursor wiggle
    assert det.check(_desktop(popup=True))[0] is True  # scam pop-up appears


def _tone(amplitude: float) -> np.ndarray:
    t = np.arange(FRAME_SAMPLES) / 24_000
    return (amplitude * np.sin(2 * np.pi * 220 * t)).astype(np.int16)


def test_vad_separates_speech_from_room_noise() -> None:
    vad = EnergyVAD()
    rng = np.random.default_rng(0)
    for _ in range(20):
        assert not vad.is_speech((rng.normal(0, 60, FRAME_SAMPLES)).astype(np.int16))
    assert vad.is_speech(_tone(4000))


def test_gate_opens_on_sustained_speech_and_closes_after_silence() -> None:
    log: list[str] = []
    gate = AudioGate(lambda: log.append("open"), lambda f: log.append("frame"), lambda: log.append("close"), start_frames=3, preroll_frames=5, hangover_s=0.4)
    gate.process(b"x", True)  # a single click: not enough
    gate.process(b"x", False)
    assert "open" not in log
    for _ in range(3):
        gate.process(b"x", True)
    assert log[0] == "open" and log.count("frame") == 5  # pre-roll replayed
    for _ in range(5):  # 0.4s hangover = 5 frames of 80 ms
        gate.process(b"x", False)
    assert log[-1] == "close" and not gate.active


def test_remote_tool_matching_is_case_insensitive() -> None:
    assert match_remote_tool("AnyDesk.exe") == "AnyDesk"
    assert match_remote_tool("QuickAssist.exe") == "Windows Quick Assist"
    assert match_remote_tool("chrome.exe") is None
    assert match_remote_tool("notepad.exe", {"notepad.exe": "Test"}) == "Test"


def test_clipboard_scan_finds_and_masks() -> None:
    found = {f.kind: f.masked for f in scan_clipboard_text(
        "send to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq or 0x52908400098527886E0F7030069857D2E4169EE7, $1,500.00, card 4111 1111 1111 1111"
    )}
    assert found["bitcoin_address"] == "bc1q…5mdq"
    assert found["ethereum_address"].startswith("0x52")
    assert found["money_amount"] == "$1,500.00"
    assert found["card_number"] == "****1111"


def test_clipboard_ignores_non_luhn_digit_runs() -> None:
    assert not [f for f in scan_clipboard_text("order 1234567890123") if f.kind == "card_number"]


def test_injected_input_counter_needs_sustained_injection() -> None:
    from agent.control import InjectionCounter

    now = [0.0]
    c = InjectionCounter(window_s=5, threshold=12, clock=lambda: now[0])
    for _ in range(50):  # the person using their own mouse: never "someone else"
        assert not c.add(False)
    for _ in range(11):
        now[0] += 0.1
        assert not c.add(True)  # a few stray injected events (e.g. an accessibility tool) are not enough
    now[0] += 0.1
    assert c.add(True)  # sustained injection: someone else is driving
    now[0] += 10
    assert not c.add(False)  # old injected events age out of the window
