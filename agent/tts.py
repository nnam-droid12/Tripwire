"""Speaking warnings aloud in a natural, human-sounding voice.

Speech matters more than the screen during a hard stop: if a scammer is
controlling the screen remotely, the senior can still *hear* Tripwire.

Voice: Google Cloud Text-to-Speech, Chirp 3 HD "Vindemiatrix", a gentle, natural female
US-English voice (set ``TRIPWIRE_VOICE`` to change it), spoken slightly
slower than normal for older listeners. Meta's API offers speech-to-text but
not text-to-speech, hence Google for this one piece.

Reliability: every synthesized phrase is cached on disk, and the standard
warnings are synthesized at start-up, so the hard-stop warning plays
instantly and even without internet. If a phrase is not cached and the
network fails, the built-in Windows voice (SAPI) says it instead: the warning
must never go silent.

Only generic warning text and model-written calm sentences (no numbers, no
personal data) are sent for synthesis.
"""

from __future__ import annotations

import base64
import hashlib
import os
import queue
import threading
import time
import wave
from pathlib import Path

from core.config import RUNTIME_DIR

VOICE = os.environ.get("TRIPWIRE_VOICE", "en-US-Chirp3-HD-Vindemiatrix")
SPEAKING_RATE = float(os.environ.get("TRIPWIRE_SPEAKING_RATE", "0.92"))
GCP_PROJECT = os.environ.get("TRIPWIRE_GCP_PROJECT", "nixora-project")
CACHE_DIR = RUNTIME_DIR / "tts_cache"  # not purged with the 24h buffer: contains no personal data
TTS_URL = "https://texttospeech.googleapis.com/v1/text:synthesize"

SVSF_PURGE_BEFORE_SPEAK = 2


class GoogleVoice:
    """Synthesize text to a cached 24 kHz WAV file with Google Cloud TTS."""

    def __init__(self, voice: str = VOICE, rate: float = SPEAKING_RATE, cache_dir: Path = CACHE_DIR) -> None:
        self.voice, self.rate, self.cache_dir = voice, rate, cache_dir
        self._creds = None

    def path_for(self, text: str) -> Path:
        digest = hashlib.sha256(f"{self.voice}|{self.rate}|{text}".encode()).hexdigest()[:24]
        return self.cache_dir / f"{digest}.wav"

    def synthesize(self, text: str) -> Path:
        path = self.path_for(text)
        if path.exists():
            return path
        import requests

        body = {
            "input": {"text": text},
            "voice": {"languageCode": self.voice[:5], "name": self.voice},
            "audioConfig": {"audioEncoding": "LINEAR16", "sampleRateHertz": 24000, "speakingRate": self.rate},
        }
        resp = requests.post(TTS_URL, json=body, headers=self._headers(), timeout=20)
        resp.raise_for_status()
        audio = base64.b64decode(resp.json()["audioContent"])  # a complete WAV (RIFF header included)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(audio)
        tmp.replace(path)
        return path

    def _headers(self) -> dict[str, str]:
        import google.auth
        import google.auth.transport.requests

        if self._creds is None:
            self._creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        if not self._creds.valid:
            self._creds.refresh(google.auth.transport.requests.Request())
        return {"Authorization": f"Bearer {self._creds.token}", "x-goog-user-project": GCP_PROJECT}


def wav_seconds(path: Path) -> float:
    with wave.open(str(path)) as w:
        return w.getnframes() / w.getframerate()


class Speaker(threading.Thread):
    """Queue text to be spoken. ``urgent`` interrupts whatever is being said."""

    def __init__(self, enabled: bool = True, voice: GoogleVoice | None = None, prewarm: list[str] | None = None) -> None:
        super().__init__(name="tts", daemon=True)
        self.enabled = enabled
        self.voice = voice or GoogleVoice()
        self.prewarm = prewarm or []
        self._jobs: queue.Queue[tuple[str, bool] | None] = queue.Queue()
        self._interrupt = threading.Event()
        self.spoken: list[str] = []  # for logs and tests

    def say(self, text: str, urgent: bool = False) -> None:
        self.spoken.append(text)
        if not self.enabled:
            return
        if urgent:
            self._interrupt.set()
            while True:  # drop anything not yet spoken
                try:
                    self._jobs.get_nowait()
                except queue.Empty:
                    break
        self._jobs.put((text, urgent))

    def stop(self) -> None:
        self._jobs.put(None)

    def run(self) -> None:
        if not self.enabled:
            return
        threading.Thread(target=self._warm_cache, name="tts-prewarm", daemon=True).start()
        while (job := self._jobs.get()) is not None:
            text, _urgent = job
            self._interrupt.clear()
            try:
                self._play(self.voice.synthesize(text))
            except Exception:  # offline, quota, auth: fall back to the Windows voice rather than stay silent
                self._sapi(text)

    def _warm_cache(self) -> None:
        try:
            self.voice._headers()  # fetch credentials now (~10 s once), not during the first warning
        except Exception:
            return
        for text in self.prewarm:
            try:
                self.voice.synthesize(text)
            except Exception:
                return  # offline at start-up; phrases will be synthesized (or fall back) when needed

    def _play(self, path: Path) -> None:
        import winsound

        winsound.PlaySound(str(path), winsound.SND_FILENAME | winsound.SND_ASYNC)
        end = time.monotonic() + wav_seconds(path)
        while time.monotonic() < end:
            if self._interrupt.wait(0.05):
                winsound.PlaySound(None, 0)  # stop the current sound for an urgent message
                return

    def _sapi(self, text: str) -> None:
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        try:
            voice = win32com.client.Dispatch("SAPI.SpVoice")
            voice.Rate, voice.Volume = -1, 100
            voice.Speak(text, SVSF_PURGE_BEFORE_SPEAK)
        finally:
            pythoncom.CoUninitialize()
