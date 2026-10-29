"""Twilio endpoints for Tripwire's phone number.

``POST /twilio/voice`` is the number's voice webhook. It answers with TwiML that
connects the call to ``/twilio/stream``, a bidirectional Media Stream.

Security, since the URL is public:

* the webhook checks Twilio's ``X-Twilio-Signature`` (HMAC-SHA1 with the account's
  auth token), so only Twilio can start a call session;
* the stream needs a one-time token that only the signed webhook hands out, so a
  WebSocket opened by anyone else is closed at once;
* calls share the web arena's cap on simultaneous games;
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
from xml.sax.saxutils import quoteattr

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response

from backend.phone.call import PhoneLine
from backend.phone.margaret_line import PhoneGame

TOKEN_TTL = 60.0
_tokens: dict[str, float] = {}


def public_url() -> str:
    return os.environ.get("TRIPWIRE_PUBLIC_URL", "http://127.0.0.1:8765").rstrip("/")


def valid_signature(url: str, params: dict[str, str], signature: str, auth_token: str) -> bool:
    """Twilio's request signature: base64(HMAC-SHA1(token, url + sorted key/value pairs))."""
    payload = url + "".join(k + params[k] for k in sorted(params))
    expected = base64.b64encode(hmac.new(auth_token.encode(), payload.encode(), hashlib.sha1).digest()).decode()
    return hmac.compare_digest(expected, signature or "")


def twiml(body: str) -> Response:
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><Response>{body}</Response>', media_type="text/xml")


def make_router(games: asyncio.Semaphore) -> APIRouter:
    router = APIRouter()

    @router.post("/twilio/voice")
    async def voice(request: Request) -> Response:
        params = dict(parse_qsl((await request.body()).decode()))
        auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
        if auth_token and not valid_signature(public_url() + "/twilio/voice", params, request.headers.get("X-Twilio-Signature", ""), auth_token):
            raise HTTPException(403)
        if games.locked():
            return twiml('<Say voice="Google.en-US-Chirp3-HD-Vindemiatrix">Margaret is on another call right now. '
                         "Please try again in a minute, or play at Tripwire's website.</Say><Hangup/>")
        now = time.time()
        for t, exp in list(_tokens.items()):
            if exp < now:
                _tokens.pop(t, None)
        token = secrets.token_urlsafe(16)
        _tokens[token] = now + TOKEN_TTL
        stream = public_url().replace("https://", "wss://").replace("http://", "ws://") + "/twilio/stream"
        return twiml(f'<Connect><Stream url={quoteattr(stream)}><Parameter name="k" value={quoteattr(token)}/></Stream></Connect>')

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
                        token = msg["start"].get("customParameters", {}).get("k", "")
                        if _tokens.pop(token, 0) < time.time():
                            await ws.close()
                            return
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

    return router
