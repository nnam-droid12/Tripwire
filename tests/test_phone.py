"""The phone line: audio conversion, Twilio signatures, utterance detection."""

from __future__ import annotations

import asyncio
import base64

import numpy as np

from backend.phone import call as phone_call
from backend.phone.audio import mulaw_decode, mulaw_encode, phone_to_asr, wav_payload
from backend.phone.routes import valid_signature


def test_mulaw_matches_g711_reference_values():
    assert mulaw_encode(np.array([0, -1], dtype=np.int16)) == b"\xff\x7f"
    assert list(mulaw_decode(b"\x00\x80")) == [-32124, 32124]
    x = (np.sin(np.arange(400) / 7) * 9000).astype(np.int16)
    assert np.max(np.abs(mulaw_decode(mulaw_encode(x)).astype(int) - x)) < 300
    assert len(phone_to_asr(mulaw_encode(x))) == 400 * 3 * 2  # 8 kHz -> 24 kHz PCM16


def test_wav_payload_strips_header():
    wav = b"RIFF" + b"\0" * 32 + b"data" + (3).to_bytes(4, "little") + b"abc"
    assert wav_payload(wav) == b"abc"


def test_twilio_signature():
    # the published example from Twilio's request-validation docs and SDK tests
    url = "https://mycompany.com/myapp.php?foo=1&bar=2"
    params = {"CallSid": "CA1234567890ABCDE", "Caller": "+12349013030", "Digits": "1234", "From": "+12349013030", "To": "+18005551212"}
    assert valid_signature(url, params, "0/KCTR6DLpKmkAf8muzZqo1nDgQ=", "12345")
    assert not valid_signature(url, params, "0/KCTR6DLpKmkAf8muzZqo1nDgQ=", "wrong")


def test_each_utterance_gets_its_own_asr_session(monkeypatch):
    sessions = []

    class FakeASR:
        def __init__(self, on_turn, **_):
            self.fed, self.closed = 0, False
            sessions.append(self)

        def start(self):
            pass

        def feed(self, pcm):
            self.fed += len(pcm)

        def close(self):
            self.closed = True

    monkeypatch.setattr(phone_call, "MuseTranscriber", FakeASR)
    line = phone_call.PhoneLine(lambda m: None, asyncio.new_event_loop(), "MZ", on_turn=lambda t: None)
    loud = base64.b64encode(mulaw_encode((np.sin(np.arange(160)) * 8000).astype(np.int16))).decode()
    quiet = base64.b64encode(b"\xff" * 160).decode()
    for burst in range(2):  # two utterances separated by a second of silence
        for _ in range(30):
            line.caller_audio(loud)
        for _ in range(50):
            line.caller_audio(quiet)
    assert len(sessions) == 2
    assert sessions[0].fed > 0
    for _ in range(100):  # silence alone never opens a session
        line.caller_audio(quiet)
    assert len(sessions) == 2


def test_guard_stop_takes_the_protected_person_out_of_the_call(monkeypatch):
    from backend.phone import guard_line, twilio_api

    redirected, incidents = [], []
    monkeypatch.setattr(twilio_api, "child_calls", lambda parent: ["CAchild"] if parent == "CAparent" else [])
    monkeypatch.setattr(twilio_api, "redirect", lambda sid, twiml: redirected.append((sid, twiml)))
    monkeypatch.setattr(guard_line, "voice_clip", lambda who, text: "clip")
    monkeypatch.setattr(guard_line, "create_incident", lambda *a, **k: incidents.append(k) or ("id", "link"))
    monkeypatch.setattr(guard_line.sentinel_client, "shared", lambda: None)
    guard = guard_line.GuardCall("CAparent", "+15550134477", "+1 (555) 000-1111", "Dorothy")
    guard._stop({"reasons": []})
    guard._stop({"reasons": []})  # a second hard stop does nothing
    assert len(redirected) == 1
    sid, twiml = redirected[0]
    assert sid == "CAchild" and "/arena/voice/clip.mp3" in twiml and twiml.endswith("<Hangup/></Response>")
    assert incidents[0]["protected_ids"] == {"5550001111"} and incidents[0]["source"] == "phone"
    assert guard.audio("inbound", b"\xff" * 160) is None  # nothing is analysed after the stop


def test_daily_minutes_cap(monkeypatch, tmp_path):
    from backend.phone import usage
    from backend.storage import LocalStore

    monkeypatch.setattr(usage.STORE, "backend", LocalStore(tmp_path))
    monkeypatch.setenv("TRIPWIRE_PHONE_DAILY_MINUTES", "1")
    assert usage.allowed()
    usage.add(45)
    assert usage.allowed()
    usage.add(30)
    assert not usage.allowed() and usage.today()["calls"] == 2
