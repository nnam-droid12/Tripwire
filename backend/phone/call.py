"""A phone call into Tripwire's number, carried over a Twilio Media Stream.

Twilio sends the caller's audio as 20 ms frames of 8 kHz mu-law over a
WebSocket and plays back whatever audio we send on the same socket. This
module turns that into the same interface the rest of Tripwire uses:

* the caller's audio goes to Muse Voice Transcribe, one finished turn at a time.
  Speech is detected here, on the phone audio, and each utterance gets its own
  push-to-talk session: its final text arrives ~0.4 s after the caller stops,
  where a continuous session waits for a long silence (~10 s measured);
* text to say goes out as speech (Google Chirp 3 HD voices, synthesized as
  8 kHz mu-law so no conversion is needed), queued in order, and an urgent line
  (the hard-stop warning) cuts off whatever is playing;
* hanging up waits until the last words have actually been played.

Twilio's "mark" messages tell us when queued audio has finished playing.
"""

from __future__ import annotations

import asyncio
import base64
import json
import queue
import threading
from collections import deque
from typing import Callable

from agent.transcribe import MuseTranscriber, TranscriptTurn
from agent.tts import GoogleVoice
from backend.phone.audio import energy, phone_to_asr, wav_payload
from core.config import RUNTIME_DIR

VOICE_DIR = RUNTIME_DIR / "phone_voice"
PHONE_VOICES = {
    "margaret": GoogleVoice(voice="en-US-Chirp3-HD-Gacrux", rate=0.95, cache_dir=VOICE_DIR, encoding="MULAW", sample_rate=8000),
    "tripwire": GoogleVoice(voice="en-US-Chirp3-HD-Vindemiatrix", rate=0.95, cache_dir=VOICE_DIR, encoding="MULAW", sample_rate=8000),
}
CHUNK = 8000  # bytes of mu-law per media message: one second of audio
FRAME_MS = 20  # Twilio sends 20 ms frames
SPEECH_RMS, SILENCE_RMS = 700.0, 450.0  # telephone speech is in the thousands; line silence near 0
START_FRAMES, END_FRAMES = 3, 40  # 60 ms of speech opens an utterance, 800 ms of quiet ends it
PRE_ROLL = 15  # frames kept from before the onset, so the first syllable isn't cut
MAX_FRAMES = 1000  # 20 s: a monologue is cut into turns


class Utterances:
    """One side of a call, as text: detects each utterance in the audio and transcribes it on its own."""

    def __init__(self, on_text: Callable[[str], None], on_error: Callable[[str], None] = lambda _: None) -> None:
        self.on_text, self.on_error = on_text, on_error
        self._asr: MuseTranscriber | None = None  # the open utterance, if this side is speaking
        self._recent: deque[bytes] = deque(maxlen=PRE_ROLL)
        self._loud = self._quiet = self._frames = 0

    def frame(self, mulaw: bytes) -> None:
        """One 20 ms frame of 8 kHz mu-law."""
        level = energy(mulaw)
        if self._asr is None:
            self._recent.append(mulaw)
            self._loud = self._loud + 1 if level > SPEECH_RMS else 0
            if self._loud >= START_FRAMES:
                self._asr = MuseTranscriber(self._heard, mode="PUSH_TO_TALK", paced=True, on_error=self.on_error)
                self._asr.start()
                self._asr.feed(phone_to_asr(b"".join(self._recent)))
                self._recent.clear()
                self._quiet = self._frames = 0
            return
        self._asr.feed(phone_to_asr(mulaw))
        self._frames += 1
        self._quiet = self._quiet + 1 if level < SILENCE_RMS else 0
        if self._quiet >= END_FRAMES or self._frames >= MAX_FRAMES:
            self.end()

    def end(self) -> None:
        asr, self._asr = self._asr, None
        self._loud = 0
        if asr:
            threading.Thread(target=asr.close, daemon=True).start()  # the final transcript arrives via _heard

    def _heard(self, turn: TranscriptTurn) -> None:
        threading.Thread(target=self.on_text, args=(turn.text,), daemon=True).start()


def speech(who: str, text: str) -> bytes:
    """8 kHz mu-law samples for one line (cached on disk)."""
    return wav_payload(PHONE_VOICES[who].synthesize(text).read_bytes())


class PhoneLine:
    """Both directions of one call. ``send_json`` is the WebSocket's coroutine, run on ``loop``."""

    def __init__(self, send_json: Callable[[dict], object], loop: asyncio.AbstractEventLoop, stream_sid: str,
                 on_turn: Callable[[str], None], on_error: Callable[[str], None] = lambda _: None) -> None:
        self._send_json, self._loop, self.stream_sid = send_json, loop, stream_sid
        self.on_turn, self.on_error = on_turn, on_error
        self._lines: queue.Queue[tuple[str, str] | None] = queue.Queue()
        self._playing: set[str] = set()  # marks sent but not yet played back
        self._played = threading.Condition()
        self._marks = 0
        self.closed = False
        self.caller = Utterances(on_turn, on_error)
        self._speaker = threading.Thread(target=self._speak_loop, name="phone-speaker", daemon=True)

    def start(self) -> None:
        self._speaker.start()

    # -- caller -> Tripwire ------------------------------------------------------------

    def caller_audio(self, mulaw_b64: str) -> None:
        if not self.closed:
            self.caller.frame(base64.b64decode(mulaw_b64))

    # -- Tripwire -> caller ------------------------------------------------------------

    def say(self, who: str, text: str, urgent: bool = False) -> None:
        if urgent:  # the warning must not wait behind Margaret's chatter
            while True:
                try:
                    self._lines.get_nowait()
                except queue.Empty:
                    break
                self._lines.task_done()
            self._send({"event": "clear", "streamSid": self.stream_sid})
            with self._played:
                self._playing.clear()
                self._played.notify_all()
        self._lines.put((who, text))

    def played(self, mark: str) -> None:
        with self._played:
            self._playing.discard(mark)
            self._played.notify_all()

    def wait_until_quiet(self, timeout: float = 30.0) -> None:
        """Block until everything queued has been played to the caller."""
        self._lines.join()
        with self._played:
            self._played.wait_for(lambda: not self._playing, timeout=timeout)

    def _speak_loop(self) -> None:
        while True:
            item = self._lines.get()
            try:
                if item is None:
                    return
                who, text = item
                try:
                    audio = speech(who, text)
                except Exception as exc:  # a missing line is better than a dead call
                    self.on_error(f"speech failed: {type(exc).__name__}")
                    continue
                for i in range(0, len(audio), CHUNK):
                    self._send({"event": "media", "streamSid": self.stream_sid,
                                "media": {"payload": base64.b64encode(audio[i:i + CHUNK]).decode()}})
                self._marks += 1
                mark = f"m{self._marks}"
                with self._played:
                    self._playing.add(mark)
                self._send({"event": "mark", "streamSid": self.stream_sid, "mark": {"name": mark}})
            finally:
                self._lines.task_done()

    def _send(self, msg: dict) -> None:
        if not self.closed:
            asyncio.run_coroutine_threadsafe(self._send_json(json.dumps(msg)), self._loop)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._lines.put(None)
        self.caller.end()
