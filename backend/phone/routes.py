"""Twilio endpoints for Tripwire's phone numbers.

``POST /twilio/voice`` is the voice webhook. A number works in one of two ways
(``?line=`` on the webhook URL, else ``TRIPWIRE_PHONE_MODE``):

* ``margaret`` (the public demo): the call is connected to ``/twilio/stream``, a
  bidirectional Media Stream, and the caller plays the scammer against Margaret;
* ``protect``: the call is forwarded to the protected person's real phone
  (``PROTECTED_PHONE_NUMBER``) while both sides stream to ``/twilio/listen``
  (see :mod:`backend.phone.guard_line`). ``/twilio/whisper`` is what the protected
  person hears before the call connects.

Security, since the URL is public:

* the webhook checks Twilio's ``X-Twilio-Signature`` (HMAC-SHA1 with the account's
  auth token), so only Twilio can start a call session;
* the stream needs a one-time token that only the signed webhook hands out, so a
  WebSocket opened by anyone else is closed at once;
* demo calls share the web arena's cap on simultaneous games and a daily cap on
  minutes (``TRIPWIRE_PHONE_DAILY_MINUTES``); a protected person's line is never capped;
* the caller's own phone number is never stored or reported to Community Shield:
  in this game the "scammer" is a real person trying the demo.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import parse_qsl
from xml.sax.saxutils import escape, quoteattr

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response

from backend.arena.session import voice_clip
from backend.phone import usage
from backend.phone.call import PhoneLine
from backend.phone.guard_line import GuardCall, whisper_text
from backend.phone.margaret_line import PhoneGame

TOKEN_TTL = 120.0
_tokens: dict[str, tuple[float, dict]] = {}  # one-time stream token -> (expiry, call details from the signed webhook)
ANNOUNCEMENT = "This call is protected by Tripwire, and may be monitored to prevent fraud."
ENDED = "This call has ended."
BUSY = "Margaret can't take another call right now. Please try again later, or play on Tripwire's website."


def public_url() -> str:
    return os.environ.get("TRIPWIRE_PUBLIC_URL", "http://127.0.0.1:8765").rstrip("/")


def valid_signature(url: str, params: dict[str, str], signature: str, auth_token: str) -> bool:
    """Twilio's request signature: base64(HMAC-SHA1(token, url + sorted key/value pairs))."""
    payload = url + "".join(k + params[k] for k in sorted(params))
    expected = base64.b64encode(hmac.new(auth_token.encode(), payload.encode(), hashlib.sha1).digest()).decode()
    return hmac.compare_digest(expected, signature or "")


def twiml(body: str) -> Response:
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><Response>{body}</Response>', media_type="text/xml")


def spoken(text: str) -> str:
    """TwiML for a line in Tripwire's own voice (falls back to Twilio's voice)."""
    clip = voice_clip("tripwire", text)
    return f"<Play>{public_url()}/arena/voice/{clip}.mp3</Play>" if clip else f"<Say>{escape(text)}</Say>"


def _mint(details: dict) -> str:
    now = time.time()
    for t, (exp, _) in list(_tokens.items()):
        if exp < now:
            _tokens.pop(t, None)
    token = secrets.token_urlsafe(16)
    _tokens[token] = (now + TOKEN_TTL, details)
    return token


def _redeem(token: str) -> dict | None:
    exp, details = _tokens.pop(token, (0.0, {}))
    return details if exp >= time.time() else None


async def _signed_params(request: Request) -> dict[str, str]:
    """The webhook's form fields, after checking Twilio's signature (403 otherwise)."""
    params = dict(parse_qsl((await request.body()).decode()))
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    url = public_url() + request.url.path + (f"?{request.url.query}" if request.url.query else "")
    if auth_token and not valid_signature(url, params, request.headers.get("X-Twilio-Signature", ""), auth_token):
        raise HTTPException(403)
    return params


def _ws_url(path: str) -> str:
    return public_url().replace("https://", "wss://").replace("http://", "ws://") + path


def make_router(games: asyncio.Semaphore) -> APIRouter:
    router = APIRouter()

    @router.post("/twilio/voice")
    async def voice(request: Request, line: str = "") -> Response:
        params = await _signed_params(request)
        if (line or os.environ.get("TRIPWIRE_PHONE_MODE", "margaret")) == "protect":
            return await asyncio.to_thread(_protect, params)
        if games.locked() or not usage.allowed():
            return twiml(await asyncio.to_thread(spoken, BUSY) + "<Hangup/>")
        token = _mint({"started": time.time()})
        return twiml(f'<Connect><Stream url={quoteattr(_ws_url("/twilio/stream"))}><Parameter name="k" value={quoteattr(token)}/></Stream></Connect>')

    def _protect(params: dict[str, str]) -> Response:
        protected = os.environ.get("PROTECTED_PHONE_NUMBER", "")
        if not protected:
            return twiml("<Say>This line is not set up yet.</Say><Hangup/>")
        caller = params.get("From", "")
        token = _mint({"call_sid": params.get("CallSid", ""), "from": caller})
        # its own token: the stream starts (and redeems its token) before the protected person picks up
        whisper = public_url() + "/twilio/whisper?k=" + _mint({"whisper": whisper_text(caller)})
        return twiml(
            spoken(ANNOUNCEMENT)
            + f'<Start><Stream url={quoteattr(_ws_url("/twilio/listen"))} track="both_tracks"><Parameter name="k" value={quoteattr(token)}/></Stream></Start>'
            + f'<Dial callerId={quoteattr(params.get("To", ""))} timeout="25"><Number url={quoteattr(whisper)}>{escape(protected)}</Number></Dial>'
            + spoken(ENDED) + "<Hangup/>"
        )

    @router.post("/twilio/whisper")
    async def whisper(request: Request, k: str = "") -> Response:
        """Played to the protected person when they pick up, before the caller is connected."""
        await _signed_params(request)
        details = _redeem(k) or {}
        text = details.get("whisper") or "Tripwire is listening to protect you on this call."
        return twiml(await asyncio.to_thread(spoken, text))

    @router.websocket("/twilio/listen")
    async def listen(ws: WebSocket) -> None:
        """Both sides of a protected call (receive-only: Twilio does not play audio from this stream)."""
        await ws.accept()
        guard: GuardCall | None = None
        try:
            while True:
                msg = json.loads(await ws.receive_text())
                event = msg.get("event")
                if event == "start":
                    details = _redeem(msg["start"].get("customParameters", {}).get("k", ""))
                    if details is None:
                        await ws.close()
                        return
                    guard = GuardCall(details["call_sid"] or msg["start"].get("callSid", ""), details["from"],
                                      os.environ.get("PROTECTED_PHONE_NUMBER", ""), os.environ.get("PROTECTED_NAME", ""))
                    await asyncio.to_thread(guard.start)
                elif guard is not None and event == "media":
                    guard.audio(msg["media"].get("track", "inbound"), base64.b64decode(msg["media"]["payload"]))
                elif event == "stop":
                    break
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if guard:
                guard.end()

    @router.websocket("/twilio/stream")
    async def stream(ws: WebSocket) -> None:
        await ws.accept()
        loop = asyncio.get_running_loop()
        game: PhoneGame | None = None
        line: PhoneLine | None = None

        def hang_up() -> None:
            asyncio.run_coroutine_threadsafe(ws.close(), loop)

        try:
            async with games:
                while True:
                    msg = json.loads(await ws.receive_text())
                    event = msg.get("event")
                    if event == "start":
                        if _redeem(msg["start"].get("customParameters", {}).get("k", "")) is None:
                            await ws.close()
                            return
                        started = time.time()
                        sid = msg["start"]["streamSid"]

                        def make_line(on_turn, sid=sid):
                            nonlocal line
                            line = PhoneLine(ws.send_text, loop, sid, on_turn)
                            return line

                        game = PhoneGame(make_line, hang_up)
                        await asyncio.to_thread(game.start)
                    elif game is None:
                        continue
                    elif event == "media" and msg["media"].get("track", "inbound") == "inbound":
                        line.caller_audio(msg["media"]["payload"])
                    elif event == "mark":
                        line.played(msg["mark"]["name"])
                    elif event == "stop":
                        break
                    if game.session.expired():
                        game.session.hang_up()
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if game:
                game.caller_hung_up()
                usage.add(time.time() - started)

    return router
