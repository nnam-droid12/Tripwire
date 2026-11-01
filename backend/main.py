"""Tripwire backend: agent API, family dashboard, and the public web arena.

Run locally with::

    uvicorn backend.main:app --port 8765

or deploy to Cloud Run (``deploy/deploy.sh``).

* ``/arena``: "Can you scam Margaret?", the public, no-login web app. The
  visitor plays a scammer; Margaret (AI) answers; the real Tripwire pipeline
  stops the scam live and a recovery agent secures her accounts.
* ``/``: landing page; ``/progress``: the public status and roadmap page.
* ``/family``: the family dashboard (live status, alerts); ``/i/<id>``: one incident.
* ``/api/agent/*``: where the on-device agent reports, with its agent token.

Access: the dashboard and incident pages are public when
``TRIPWIRE_PUBLIC_DASHBOARD=1`` (the hackathon deployment, where all data is
fictional); otherwise they need the dashboard key or the incident's private
token. Agent endpoints always need ``TRIPWIRE_AGENT_TOKEN``. Locally, missing
keys are generated into ``runtime/backend/keys.json`` (git-ignored).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from backend import approvals, family_check, shield
from backend.arena import laptop, scores
from backend.arena.session import VOICE_DIR, ArenaSession, prewarm_voices
from backend.incidents import STORE, create_incident, decode_frames
from backend.phone.routes import make_router as make_phone_router
from core.config import RUNTIME_DIR

BACKEND_DIR = RUNTIME_DIR / "backend"
KEYS_FILE = BACKEND_DIR / "keys.json"
DASHBOARD_DIR = Path(__file__).parent / "dashboard"
RESULTS_DIR = Path(__file__).parent.parent / "eval" / "results"
PROGRESS_KEY = "site/progress.json"
PUBLIC_DASHBOARD = os.environ.get("TRIPWIRE_PUBLIC_DASHBOARD") == "1"
MAX_ARENA_GAMES = int(os.environ.get("TRIPWIRE_MAX_ARENA_GAMES", "4"))
_ID = re.compile(r"^[a-f0-9]{16}$")
_IMAGE = re.compile(r"^(?:(?:frame|highlight)_\d+|explainer)\.png$")
_CLIP = re.compile(r"^[a-f0-9]{24}$")


def load_keys() -> dict[str, str]:
    """Agent token and dashboard key: from env, else (locally only) generated once and kept on disk."""
    env = {"agent_token": os.environ.get("TRIPWIRE_AGENT_TOKEN", ""), "dashboard_key": os.environ.get("TRIPWIRE_DASHBOARD_KEY", "")}
    if all(env.values()):
        return env
    if os.environ.get("TRIPWIRE_GCS_BUCKET"):
        raise RuntimeError("In the cloud, TRIPWIRE_AGENT_TOKEN and TRIPWIRE_DASHBOARD_KEY must be set")
    stored = json.loads(KEYS_FILE.read_text()) if KEYS_FILE.exists() else {}
    keys = {
        "agent_token": env["agent_token"] or stored.get("agent_token") or secrets.token_urlsafe(24),
        "dashboard_key": env["dashboard_key"] or stored.get("dashboard_key") or secrets.token_urlsafe(16),
    }
    if keys != stored:
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEYS_FILE.write_text(json.dumps(keys))
    return keys


KEYS = load_keys()
app = FastAPI(title="Tripwire", docs_url=None, redoc_url=None)
_status: dict[str, Any] = {"state": "offline", "updated": 0}
_arena_games = asyncio.Semaphore(MAX_ARENA_GAMES)
app.include_router(make_phone_router(_arena_games))  # Call Margaret: the same game over a real phone call


# -- models ------------------------------------------------------------------------------


class StatusIn(BaseModel):
    state: str
    stage: int = 0
    stage_name: str = "NONE"
    confidence: float = 0.0
    action: str = "log"
    summary: str = ""


class IncidentIn(BaseModel):
    verdict: dict[str, Any]
    snapshot: dict[str, Any]
    frames: list[str] = []  # base64 PNG, already redacted on the device
    protected_name: str = ""


# -- access ------------------------------------------------------------------------------


def _require_agent(token: str | None) -> None:
    if not token or not hmac.compare_digest(token, KEYS["agent_token"]):
        raise HTTPException(401, "bad agent token")


def _dashboard_allowed(key: str) -> bool:
    return PUBLIC_DASHBOARD or hmac.compare_digest(key, KEYS["dashboard_key"])


def _load_incident(incident_id: str, key: str) -> dict[str, Any]:
    if not _ID.match(incident_id):
        raise HTTPException(404)
    incident = STORE.load(incident_id)
    if not incident:
        raise HTTPException(404)
    if not (_dashboard_allowed(key) or (key and hmac.compare_digest(key, incident["token"]))):
        raise HTTPException(403)
    return incident


def _public(incident: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in incident.items() if k != "token"}


# -- agent -> backend --------------------------------------------------------------------


@app.post("/api/agent/status")
def post_status(status: StatusIn, x_tripwire_token: str | None = Header(None)) -> dict[str, str]:
    _require_agent(x_tripwire_token)
    _status.update(status.model_dump(), updated=time.time())
    return {"ok": "true"}


@app.post("/api/agent/incidents")
def post_incident(body: IncidentIn, x_tripwire_token: str | None = Header(None)) -> dict[str, str]:
    _require_agent(x_tripwire_token)
    incident_id, link = create_incident(body.verdict, body.snapshot, decode_frames(body.frames), body.protected_name)
    return {"id": incident_id, "link": link}


# -- family dashboard --------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def landing() -> HTMLResponse:
    return HTMLResponse((DASHBOARD_DIR / "landing.html").read_text(encoding="utf-8"))


@app.get("/progress", response_class=HTMLResponse)
def progress_page() -> HTMLResponse:
    return HTMLResponse((DASHBOARD_DIR / "progress.html").read_text(encoding="utf-8"))


@app.get("/api/results")
def results() -> dict[str, Any]:
    """Evaluation results, read from the committed result files (never typed in by hand)."""
    out: dict[str, Any] = {}
    for name in ("latest", "external", "external_baseline", "frames"):
        # the configuration that ships includes Tripwire Sentinel; its runs are reported when present
        path = next((p for p in (RESULTS_DIR / f"{name}_sentinel.json", RESULTS_DIR / f"{name}.json") if p.exists()), None)
        if path:
            data = json.loads(path.read_text(encoding="utf-8"))
            out[name] = {"meta": data.get("meta"), "summary": data.get("summary")}
    return out


@app.get("/api/phone")
def phone_info() -> dict[str, str]:
    """The public demo number, once one is set up (``TRIPWIRE_PHONE_NUMBER``)."""
    number = os.environ.get("TRIPWIRE_PHONE_NUMBER", "")
    digits = re.sub(r"\D", "", number)[-10:]
    display = f"+1 ({digits[:3]}) {digits[3:6]}-{digits[6:]}" if len(digits) == 10 else number
    return {"number": number, "display": display}


@app.get("/api/progress")
def get_progress() -> dict[str, Any]:
    raw = STORE.backend.get_bytes(PROGRESS_KEY)
    return json.loads(raw) if raw else {"now": "", "milestones": [], "updated": 0}


@app.post("/api/progress")
def post_progress(body: dict[str, Any], x_tripwire_token: str | None = Header(None)) -> dict[str, str]:
    """The status page's data; written by the team's machine with the agent token."""
    _require_agent(x_tripwire_token)
    STORE.backend.put_bytes(PROGRESS_KEY, json.dumps({**body, "updated": time.time()}).encode(), "application/json")
    return {"ok": "true"}


class DecisionIn(BaseModel):
    approve: bool


@app.get("/approve/{approval_id}", response_class=HTMLResponse)
def approve_page(approval_id: str) -> HTMLResponse:
    if not approvals.get(approval_id):
        raise HTTPException(404)
    return HTMLResponse((DASHBOARD_DIR / "approve.html").read_text(encoding="utf-8"))


@app.get("/api/approvals/{approval_id}")
def get_approval(approval_id: str) -> dict[str, Any]:
    approval = approvals.get(approval_id)
    if not approval:
        raise HTTPException(404)
    return approval


@app.post("/api/approvals/{approval_id}")
def post_approval(approval_id: str, body: DecisionIn) -> dict[str, Any]:
    """The family member's answer to a held payment. The link itself is the credential (unguessable id)."""
    approval = approvals.decide(approval_id, body.approve)
    if not approval:
        raise HTTPException(404)
    return approval


class CheckAnswerIn(BaseModel):
    status: str


@app.get("/check/{check_id}", response_class=HTMLResponse)
def check_page(check_id: str) -> HTMLResponse:
    if not family_check.get(check_id):
        raise HTTPException(404)
    return HTMLResponse((DASHBOARD_DIR / "check.html").read_text(encoding="utf-8"))


@app.get("/api/checks/{check_id}")
def get_check(check_id: str) -> dict[str, Any]:
    check = family_check.get(check_id)
    if not check:
        raise HTTPException(404)
    return check


@app.post("/api/checks/{check_id}")
def post_check(check_id: str, body: CheckAnswerIn) -> dict[str, Any]:
    """The relative's answer to "someone says they're you". The link itself is the credential (unguessable id)."""
    check = family_check.answer(check_id, body.status)
    if not check:
        raise HTTPException(404)
    return check


@app.get("/family", response_class=HTMLResponse)
def dashboard(k: str = Query("")) -> HTMLResponse:
    if not _dashboard_allowed(k):
        raise HTTPException(403, "Open the dashboard with its private link.")
    return HTMLResponse((DASHBOARD_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/i/{incident_id}", response_class=HTMLResponse)
def incident_page(incident_id: str, k: str = Query("")) -> HTMLResponse:
    _load_incident(incident_id, k)
    return HTMLResponse((DASHBOARD_DIR / "incident.html").read_text(encoding="utf-8"))


@app.get("/api/status")
def get_status(k: str = Query("")) -> dict[str, Any]:
    if not _dashboard_allowed(k):
        raise HTTPException(403)
    online = time.time() - _status.get("updated", 0) < 45
    return {**_status, "state": _status["state"] if online else "offline", "incidents": STORE.index()[:20]}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, k: str = Query("")) -> dict[str, Any]:
    return _public(_load_incident(incident_id, k))


@app.post("/api/incidents/{incident_id}/report/signoff")
def sign_off_report(incident_id: str, k: str = Query("")) -> dict[str, Any]:
    """The human in the loop: the recovery agent's fraud report stays a draft until a family member signs it off."""
    incident = _load_incident(incident_id, k)
    if not incident["verdict"].get("report"):
        raise HTTPException(404)

    def sign(i: dict[str, Any]) -> None:
        i["verdict"]["report"].setdefault("signed_off_at", time.time())

    STORE.update(incident_id, sign)
    return {"ok": True}


@app.get("/api/incidents/{incident_id}/image/{name}")
def get_image(incident_id: str, name: str, k: str = Query("")) -> Response:
    _load_incident(incident_id, k)
    if not _IMAGE.match(name):
        raise HTTPException(404)
    data = STORE.get_image(incident_id, name)
    if data is None:
        raise HTTPException(404)
    return Response(data, media_type="image/png", headers={"Cache-Control": "no-store"})


# -- the arena ---------------------------------------------------------------------------


@app.get("/arena", response_class=HTMLResponse)
def arena_page() -> HTMLResponse:
    return HTMLResponse((DASHBOARD_DIR / "arena.html").read_text(encoding="utf-8"))


@app.get("/arena/pages/{name}")
def arena_laptop_page(name: str) -> FileResponse:
    """Margaret's laptop pages (fictional HTML) and their shared stylesheet."""
    if name == "_style.css":
        return FileResponse(laptop.PAGES_DIR / "_style.css", media_type="text/css")
    page = name.removesuffix(".html")
    if page not in laptop.PAGES:
        raise HTTPException(404)
    return FileResponse(laptop.html_path(page), media_type="text/html")


@app.get("/arena/voice/{clip}.mp3")
def arena_voice(clip: str) -> FileResponse:
    path = VOICE_DIR / f"{clip}.mp3"
    if not _CLIP.match(clip) or not path.exists():
        raise HTTPException(404)
    return FileResponse(path, media_type="audio/mpeg", headers={"Cache-Control": "public, max-age=86400"})


class NameIn(BaseModel):
    session: str
    name: str


class ShieldCheckIn(BaseModel):
    text: str


@app.get("/api/shield")
def shield_stats() -> dict[str, Any]:
    """How many scammer identifiers the community has learned (scammer-side data only)."""
    return shield.stats()


@app.post("/api/shield/check")
def shield_check(body: ShieldCheckIn) -> dict[str, Any]:
    """Used by the desktop agent: known scammer identifiers in a line of text."""
    return {"hits": shield.lookup(body.text[:2000])}


@app.get("/api/arena/board")
def arena_board() -> dict[str, Any]:
    return scores.board()


@app.post("/api/arena/name")
def arena_name(body: NameIn) -> dict[str, bool]:
    """Attach a nickname to a finished game. The score itself was recorded by the server."""
    return {"ok": scores.set_name(body.session, body.name)}


@app.websocket("/ws/arena")
async def arena_socket(ws: WebSocket) -> None:
    """One game. Client sends {"type": "start"|"say"|"ptt_start"|"ptt_end"|"hang_up"} and binary PCM16 24 kHz audio."""
    await ws.accept()
    if _arena_games.locked():
        await ws.send_json({"type": "busy", "text": "Margaret is on another call. Try again in a minute."})
        await ws.close()
        return
    async with _arena_games:
        loop = asyncio.get_running_loop()
        outbox: asyncio.Queue[dict] = asyncio.Queue()
        session: ArenaSession | None = None

        def send(msg: dict) -> None:  # called from worker threads
            loop.call_soon_threadsafe(outbox.put_nowait, msg)

        async def pump() -> None:
            while True:
                await ws.send_json(await outbox.get())

        pump_task = asyncio.create_task(pump())
        try:
            while True:
                msg = await ws.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
                if msg.get("bytes") is not None:
                    if session:
                        session.ptt_audio(msg["bytes"])
                    continue
                data = json.loads(msg.get("text") or "{}")
                kind = data.get("type")
                if kind == "start" and session is None:
                    session = ArenaSession(send, data.get("situation", "popup"))
                    await asyncio.to_thread(session.start)
                elif session is None:
                    continue
                elif kind == "say":
                    asyncio.get_running_loop().run_in_executor(None, session.scammer_says, str(data.get("text", "")))
                elif kind == "ptt_start":
                    await asyncio.to_thread(session.ptt_start)
                elif kind == "ptt_end":
                    asyncio.get_running_loop().run_in_executor(None, session.ptt_end)
                elif kind == "hang_up":
                    session.hang_up()
                if session.expired():
                    session.hang_up()
        except WebSocketDisconnect:
            pass
        finally:
            pump_task.cancel()


@app.on_event("startup")
async def _warm_arena_voices() -> None:
    asyncio.get_running_loop().run_in_executor(None, prewarm_voices)  # urgent phrases ready before the first game


@app.get("/health")  # not /healthz: Cloud Run reserves paths ending in "z"
def health() -> dict[str, str]:
    return {"ok": "true"}
