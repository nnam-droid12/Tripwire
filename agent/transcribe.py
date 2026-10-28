"""Streaming client for Muse Voice Transcribe (Meta realtime ASR).

Protocol (``wss://api.meta.ai/v1/asr/realtime``):

1. Send a JSON handshake carrying the API key, encoding, model and mode.
2. Send raw PCM16 mono audio as binary frames, paced in real time.
3. Send ``{"type": "endStream"}`` and read until the server closes (1000).

We use ``DIARIZATION`` mode, so each completed turn is preceded by a
``speaker`` event (labels ``A``, ``B``...). That lets the CallAnalyst tell the
caller's lines from the senior's. Labels are only stable within one session.

The client runs its own asyncio loop on a background thread so the audio
capture thread can call :meth:`feed` without caring about async.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from dataclasses import dataclass
from typing import Callable

import websockets

import core.config  # noqa: F401  (loads .env)

ASR_URL = "wss://api.meta.ai/v1/asr/realtime"
ASR_MODEL = "muse-voice-transcribe-1.0"
SAMPLE_RATE = 24_000
FRAME_S = 0.08
FRAME_BYTES = int(SAMPLE_RATE * FRAME_S) * 2  # 80 ms of PCM16 mono

# Spelling hints for words that matter to scam detection and that ASR tends
# to mangle ("any desk").
DEFAULT_KEYWORDS = [
    "AnyDesk", "TeamViewer", "UltraViewer", "ScreenConnect", "LogMeIn", "Quick Assist",
    "Microsoft", "Windows Defender", "gift card", "Bitcoin", "Coinbase", "wire transfer",
]


@dataclass(frozen=True)
class TranscriptTurn:
    """One completed utterance."""

    session_id: str
    turn_id: int
    speaker: str | None
    text: str
    audio_ms: int


class MuseTranscriber:
    """One realtime transcription session. Create, :meth:`start`, :meth:`feed`, :meth:`close`."""

    def __init__(
        self,
        on_turn: Callable[[TranscriptTurn], None],
        *,
        api_key: str | None = None,
        mode: str = "DIARIZATION",
        keywords: list[str] | None = None,
        on_error: Callable[[str], None] | None = None,
        paced: bool = False,
    ) -> None:
        self.on_turn = on_turn
        self.paced = paced  # audio arriving over a network: release it at a steady real-time pace
        self.on_error = on_error or (lambda msg: None)
        self.api_key = api_key or os.environ["META_API_KEY"]
        self.mode = mode
        self.keywords = DEFAULT_KEYWORDS if keywords is None else keywords
        self.session_id = ""
        self._loop = asyncio.new_event_loop()
        self._audio: asyncio.Queue[bytes | None] | None = None
        self._thread = threading.Thread(target=self._loop.run_forever, name="muse-asr", daemon=True)

    # -- public, thread-safe API -------------------------------------------------

    def start(self) -> None:
        self._thread.start()
        self._audio = asyncio.run_coroutine_threadsafe(self._make_queue(), self._loop).result()
        self._done = asyncio.run_coroutine_threadsafe(self._run(), self._loop)

    def feed(self, pcm: bytes) -> None:
        """Queue one chunk of PCM16 mono 24 kHz audio."""
        self._loop.call_soon_threadsafe(self._audio.put_nowait, pcm)

    def close(self, timeout: float = 15.0) -> None:
        """End the stream, wait for the last transcripts, stop the loop."""
        self._loop.call_soon_threadsafe(self._audio.put_nowait, None)
        try:
            self._done.result(timeout=timeout)
        except Exception as exc:  # surfaced via on_error; never crash capture
            self.on_error(f"transcriber shutdown: {exc!r}")
        self._loop.call_soon_threadsafe(self._loop.stop)

    # -- internals ---------------------------------------------------------------

    async def _make_queue(self) -> asyncio.Queue[bytes | None]:
        return asyncio.Queue()

    async def _run(self) -> None:
        handshake = {
            "authorization": {"accessToken": f"Bearer {self.api_key}"},
            "audioEncoding": "PCM_24KHZ",
            "model": ASR_MODEL,
            "mode": self.mode,
            "emitAudioProgress": False,
            "keywords": self.keywords,
        }
        try:
            async with websockets.connect(ASR_URL, max_size=None) as ws:
                await ws.send(json.dumps(handshake))
                ack = json.loads(await ws.recv())
                self.session_id = ack.get("sessionId", "")
                sender = asyncio.create_task(self._send_audio(ws))
                await self._receive(ws)
                await sender
        except Exception as exc:
            self.on_error(f"ASR session failed: {exc!r}")

    async def _send_audio(self, ws: websockets.ClientConnection) -> None:
        if self.paced:
            await self._send_paced(ws)
            return
        while True:
            chunk = await self._audio.get()
            if chunk is None:
                await ws.send(json.dumps({"type": "endStream"}))
                return
            await ws.send(chunk)

    async def _send_paced(self, ws: websockets.ClientConnection) -> None:
        """Send exactly one 80 ms frame every 80 ms, whatever the arrival timing.

        Audio that comes over a network (the web arena) arrives in bursts and
        gaps, but the realtime ASR closes the stream if ingress falls below
        real time. So incoming audio is buffered and released at a steady pace,
        with silence filling any gap until the next chunk arrives.
        """
        loop = asyncio.get_running_loop()
        pending, closing, next_at = bytearray(), False, loop.time()
        while True:
            while not self._audio.empty():
                chunk = self._audio.get_nowait()
                if chunk is None:
                    closing = True
                else:
                    pending += chunk
            if closing and not pending:
                await ws.send(json.dumps({"type": "endStream"}))
                return
            frame = bytes(pending[:FRAME_BYTES]).ljust(FRAME_BYTES, b"\x00")  # silence pads a gap
            del pending[:FRAME_BYTES]
            await ws.send(frame)
            next_at += FRAME_S
            await asyncio.sleep(max(0.0, next_at - loop.time()))

    async def _receive(self, ws: websockets.ClientConnection) -> None:
        speaker: str | None = None
        try:
            async for raw in ws:
                if isinstance(raw, bytes):
                    continue
                msg = json.loads(raw)
                kind = msg.get("type")
                if kind == "speaker":
                    speaker = msg.get("label")
                elif kind == "speechComplete":
                    text = (msg.get("transcript") or "").strip()
                    if text:
                        self.on_turn(TranscriptTurn(self.session_id, msg.get("turnId", -1), speaker, text, msg.get("audioProcessedMs", 0)))
                    speaker = None
                elif kind == "transcript" and msg.get("final") and self.mode == "PUSH_TO_TALK":
                    # push-to-talk (the web arena): one final transcript per utterance, no turn events
                    text = (msg.get("transcript") or "").strip()
                    if text:
                        self.on_turn(TranscriptTurn(self.session_id, 0, None, text, msg.get("audioProcessedMs", 0)))
                elif kind == "error":
                    self.on_error(f"ASR error: {msg.get('message')}")
        except websockets.ConnectionClosed as exc:
            if exc.code not in (1000, None):
                self.on_error(f"ASR closed {exc.code}: {exc.reason}")
