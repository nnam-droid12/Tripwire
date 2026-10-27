"""Call audio capture with voice-activity gating (Tier 0).

The senior's call is on speakerphone, so the laptop microphone hears both
sides. Audio flows: microphone -> :class:`EnergyVAD` -> :class:`AudioGate` ->
Muse Voice Transcribe.

The realtime ASR requires continuous real-time audio for as long as a session
is open, so we cannot simply drop silent frames mid-session. Instead the gate
decides *when a session exists*: it opens one when speech starts (replaying a
short pre-roll so the first word is not clipped) and closes it after a run of
silence. Long quiet periods are never streamed or billed.

Each session's audio is also written to ``runtime/audio`` as a WAV (rolling
24h buffer) so an incident can be reviewed.
"""

from __future__ import annotations

import collections
import queue
import threading
import time
import wave
from pathlib import Path
from typing import Callable, Iterator

import numpy as np

from agent.transcribe import SAMPLE_RATE, MuseTranscriber, TranscriptTurn
from core.config import AUDIO_DIR
from core.events import Event, EventBus

FRAME_MS = 80
FRAME_SAMPLES = SAMPLE_RATE * FRAME_MS // 1000  # 1920 samples = 3840 bytes


class EnergyVAD:
    """Speech detector based on RMS energy above an adaptive noise floor.

    Deliberately simple: it only has to answer "is anyone talking near the
    laptop?", not transcribe. The noise floor tracks the room during
    non-speech frames, so a fan or road noise does not count as speech.
    """

    def __init__(self, ratio: float = 3.0, min_rms: float = 250.0, adapt: float = 0.05) -> None:
        self.ratio = ratio
        self.min_rms = min_rms
        self.adapt = adapt
        self.noise_floor: float | None = None

    def is_speech(self, frame: np.ndarray) -> bool:
        rms = float(np.sqrt(np.mean(frame.astype(np.float64) ** 2))) if frame.size else 0.0
        if self.noise_floor is None:
            self.noise_floor = rms
            return False
        speech = rms > max(self.noise_floor * self.ratio, self.min_rms)
        if not speech:
            self.noise_floor += self.adapt * (rms - self.noise_floor)
        return speech


class AudioGate:
    """Opens a stream on sustained speech, closes it after sustained silence.

    Pure state machine (no I/O) so it can be unit-tested: callers pass frames
    and VAD decisions in, and get ``on_open`` / ``on_frame`` / ``on_close``
    callbacks out.
    """

    def __init__(
        self,
        on_open: Callable[[], None],
        on_frame: Callable[[bytes], None],
        on_close: Callable[[], None],
        *,
        start_frames: int = 3,
        preroll_frames: int = 10,
        hangover_s: float = 12.0,
    ) -> None:
        self.on_open, self.on_frame, self.on_close = on_open, on_frame, on_close
        self.start_frames = start_frames
        self.hangover_frames = int(hangover_s * 1000 / FRAME_MS)
        self._preroll: collections.deque[bytes] = collections.deque(maxlen=preroll_frames)
        self._speech_run = 0
        self._silence_run = 0
        self.active = False

    def process(self, frame: bytes, speech: bool) -> None:
        if not self.active:
            self._preroll.append(frame)
            self._speech_run = self._speech_run + 1 if speech else 0
            if self._speech_run >= self.start_frames:
                self.active = True
                self._silence_run = 0
                self.on_open()
                for buffered in self._preroll:
                    self.on_frame(buffered)
                self._preroll.clear()
            return
        self.on_frame(frame)
        self._silence_run = 0 if speech else self._silence_run + 1
        if self._silence_run >= self.hangover_frames:
            self.close()

    def close(self) -> None:
        if self.active:
            self.active = False
            self._speech_run = 0
            self.on_close()


# -- frame sources ---------------------------------------------------------------


def mic_frames(stop: threading.Event, device: int | str | None = None) -> Iterator[bytes]:
    """Yield 80 ms PCM16 frames from the default (or given) microphone."""
    import sounddevice as sd

    frames: queue.Queue[bytes] = queue.Queue()

    def callback(indata, _frames, _time, _status) -> None:
        frames.put(bytes(indata))

    with sd.RawInputStream(samplerate=SAMPLE_RATE, channels=1, dtype="int16", blocksize=FRAME_SAMPLES, device=device, callback=callback):
        while not stop.is_set():
            try:
                yield frames.get(timeout=0.5)
            except queue.Empty:
                continue


def wav_frames(path: Path, stop: threading.Event, realtime: bool = True) -> Iterator[bytes]:
    """Yield 80 ms frames from a 24 kHz mono PCM16 WAV, paced like a live mic.

    Used by tests and the eval harness to replay a recorded call.
    """
    with wave.open(str(path)) as wav:
        if (wav.getframerate(), wav.getnchannels(), wav.getsampwidth()) != (SAMPLE_RATE, 1, 2):
            raise ValueError(f"{path} must be {SAMPLE_RATE} Hz mono 16-bit")
        while not stop.is_set():
            chunk = wav.readframes(FRAME_SAMPLES)
            if not chunk:
                return
            yield chunk
            if realtime:
                time.sleep(FRAME_MS / 1000)


# -- the watcher -----------------------------------------------------------------


class AudioWatcher(threading.Thread):
    """Runs VAD + gate over a frame source and publishes transcript events."""

    def __init__(self, bus: EventBus, source: Callable[[threading.Event], Iterator[bytes]] | None = None, out_dir: Path = AUDIO_DIR) -> None:
        super().__init__(name="audio-watcher", daemon=True)
        self.bus = bus
        self.source = source or mic_frames
        self.out_dir = out_dir
        self.vad = EnergyVAD()
        self.gate = AudioGate(self._open, self._frame, self._close)
        self._halt = threading.Event()
        self._asr: MuseTranscriber | None = None
        self._wav: wave.Wave_write | None = None
        self._opened_at = 0.0

    def run(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        for chunk in self.source(self._halt):
            frame = np.frombuffer(chunk, dtype=np.int16)
            self.gate.process(chunk, self.vad.is_speech(frame))
        self.gate.close()  # source ended (e.g. replayed WAV finished)

    def stop(self) -> None:
        self._halt.set()

    def _open(self) -> None:
        self._opened_at = time.time()
        path = self.out_dir / f"call_{int(self._opened_at * 1000)}.wav"
        self._wav = wave.open(str(path), "wb")
        self._wav.setnchannels(1)
        self._wav.setsampwidth(2)
        self._wav.setframerate(SAMPLE_RATE)
        self._asr = MuseTranscriber(self._on_turn, on_error=self._on_error)
        self._asr.start()
        self.bus.publish(Event("audio", "speech_started", {"recording": str(path), "summary": f"speech detected, streaming to ASR ({path.name})"}))

    def _frame(self, chunk: bytes) -> None:
        self._asr.feed(chunk)
        self._wav.writeframes(chunk)

    def _close(self) -> None:
        self._asr.close()
        self._wav.close()
        seconds = round(time.time() - self._opened_at, 1)
        self.bus.publish(Event("audio", "speech_ended", {"seconds": seconds, "summary": f"silence, closed ASR session after {seconds}s"}))

    def _on_turn(self, turn: TranscriptTurn) -> None:
        who = f"Speaker {turn.speaker}" if turn.speaker else "Speaker ?"
        self.bus.publish(
            Event(
                "audio",
                "transcript",
                {"speaker": turn.speaker, "text": turn.text, "turn_id": turn.turn_id, "asr_session": turn.session_id, "summary": f'{who}: "{turn.text}"'},
            )
        )

    def _on_error(self, message: str) -> None:
        self.bus.publish(Event("audio", "asr_error", {"summary": message}))
