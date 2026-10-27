"""Tripwire backend: live status, incidents, family SMS and the family dashboard.

Run with::

    uvicorn backend.main:app --port 8765

* The on-device agent pushes live status and, on a hard stop, an incident
  (redacted frames, redacted timeline, verdict) with the shared agent token.
* An incident immediately triggers a text to the family containing a private
  link. Then, in the background, frames are re-checked for sensitive numbers
  (defence in depth), the threat is outlined with SAM 3.1, and Muse Spark
  writes a plain-language narration of what happened.
* The family dashboard (``/?k=<dashboard key>``) shows live status and past
  incidents; an incident link (``/i/<id>?k=<incident token>``) shows one incident.

Secrets: ``TRIPWIRE_AGENT_TOKEN`` and ``TRIPWIRE_DASHBOARD_KEY`` come from the
environment; if unset, random ones are generated into ``runtime/backend/keys.json``
(local, git-ignored) and the agent on the same machine reads them from there.
"""

from __future__ import annotations

import base64
import hmac
import io
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from PIL import Image
from pydantic import BaseModel

from agent.redact import RedactionError, redact_image, redact_text
from analysts.common import SAFETY_RULES
from backend.highlight import highlight
from backend.sms import send_sms
from core.config import RUNTIME_DIR
from core.model_client import ModelClient

BACKEND_DIR = RUNTIME_DIR / "backend"
INCIDENTS_DIR = BACKEND_DIR / "incidents"
KEYS_FILE = BACKEND_DIR / "keys.json"
DASHBOARD_DIR = Path(__file__).parent / "dashboard"
_ID = re.compile(r"^[a-f0-9]{16}$")
_IMAGE = re.compile(r"^(frame|highlight)_\d+\.png$")


def load_keys() -> dict[str, str]:
    """Agent token and dashboard key: from env, else generated once and kept locally."""
    stored = json.loads(KEYS_FILE.read_text()) if KEYS_FILE.exists() else {}
    keys = {
        "agent_token": os.environ.get("TRIPWIRE_AGENT_TOKEN") or stored.get("agent_token") or secrets.token_urlsafe(24),
        "dashboard_key": os.environ.get("TRIPWIRE_DASHBOARD_KEY") or stored.get("dashboard_key") or secrets.token_urlsafe(16),
    }
    if keys != stored:
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEYS_FILE.write_text(json.dumps(keys))
    return keys


KEYS = load_keys()
PUBLIC_BASE_URL = os.environ.get("TRIPWIRE_PUBLIC_URL", "http://127.0.0.1:8765").rstrip("/")
app = FastAPI(title="Tripwire backend", docs_url=None, redoc_url=None)
_status: dict[str, Any] = {"state": "offline", "updated": 0}
_lock = threading.Lock()


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


# -- auth --------------------------------------------------------------------------------


def _require_agent(token: str | None) -> None:
    if not token or not hmac.compare_digest(token, KEYS["agent_token"]):
        raise HTTPException(401, "bad agent token")


def _incident_dir(incident_id: str) -> Path:
    if not _ID.match(incident_id):
        raise HTTPException(404)
    path = INCIDENTS_DIR / incident_id
    if not path.exists():
        raise HTTPException(404)
    return path


def _load_incident(incident_id: str, key: str | None) -> dict[str, Any]:
    incident = json.loads((_incident_dir(incident_id) / "incident.json").read_text(encoding="utf-8"))
    ok = key and (hmac.compare_digest(key, incident["token"]) or hmac.compare_digest(key, KEYS["dashboard_key"]))
    if not ok:
        raise HTTPException(403)
    return incident


def _save_incident(incident: dict[str, Any]) -> None:
    path = INCIDENTS_DIR / incident["id"] / "incident.json"
    with _lock:
        path.write_text(json.dumps(incident, indent=2), encoding="utf-8")


def _public(incident: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in incident.items() if k != "token"}


# -- agent -> backend --------------------------------------------------------------------


@app.post("/api/agent/status")
def post_status(status: StatusIn, x_tripwire_token: str | None = Header(None)) -> dict[str, str]:
    _require_agent(x_tripwire_token)
    _status.update(status.model_dump(), updated=time.time())
    return {"ok": "true"}


@app.post("/api/agent/incidents")
def post_incident(body: IncidentIn, background: BackgroundTasks, x_tripwire_token: str | None = Header(None)) -> dict[str, str]:
    _require_agent(x_tripwire_token)
    incident_id = secrets.token_hex(8)
    token = secrets.token_urlsafe(16)
    folder = INCIDENTS_DIR / incident_id
    folder.mkdir(parents=True)

    frames = []
    for i, b64 in enumerate(body.frames[:4]):
        try:
            # defence in depth: the agent already redacted; redact again before storing
            image, _ = redact_image(Image.open(io.BytesIO(base64.b64decode(b64))))
        except (RedactionError, OSError, ValueError):
            continue
        name = f"frame_{i}.png"
        image.save(folder / name, optimize=True)
        frames.append(name)

    snap = body.snapshot
    verdict = body.verdict
    incident = {
        "id": incident_id,
        "token": token,
        "created": time.time(),
        "protected_name": body.protected_name,
        "verdict": {**verdict, "family_message": redact_text(verdict.get("family_message", ""))},
        "stage": snap.get("stage", 0),
        "stage_name": snap.get("stage_name", ""),
        "confidence": snap.get("confidence", 0.0),
        "brands": snap.get("brands", {}),
        "signals": [{**s, "evidence": redact_text(s.get("evidence", ""))} for s in snap.get("signals", [])],
        "timeline": [{**t, "text": redact_text(t.get("text", ""))} for t in snap.get("timeline", [])],
        "frames": frames,
        "highlights": [],
        "narration": None,
        "sms": None,
    }
    _save_incident(incident)
    link = f"{PUBLIC_BASE_URL}/i/{incident_id}?k={token}"
    background.add_task(_alert_family, incident_id, link)
    background.add_task(_enrich, incident_id)
    return {"id": incident_id, "link": link}


def _alert_family(incident_id: str, link: str) -> None:
    incident = json.loads((INCIDENTS_DIR / incident_id / "incident.json").read_text(encoding="utf-8"))
    who = incident["protected_name"] or "your relative"
    message = incident["verdict"].get("family_message") or f"Tripwire stopped a likely scam on {who}'s computer."
    body = f"TRIPWIRE ALERT for {who}: {message} Details: {link}"
    result = send_sms(body)
    incident["sms"] = {"sent": result.sent, "detail": result.detail, "body": body.replace(incident["token"], "<token>")}
    _save_incident(incident)


def _enrich(incident_id: str) -> None:
    folder = INCIDENTS_DIR / incident_id
    incident = json.loads((folder / "incident.json").read_text(encoding="utf-8"))
    for name in incident["frames"]:
        png, boxes = highlight((folder / name).read_bytes())
        if boxes:
            out = name.replace("frame_", "highlight_")
            (folder / out).write_bytes(png)
            incident["highlights"].append({"image": out, "frame": name, "labels": sorted({b.label for b in boxes})})
    incident["narration"] = narrate(incident)
    _save_incident(incident)


NARRATE_PROMPT = f"""{SAFETY_RULES}

Write what happened during this incident for a worried family member, in plain words.
Reply with one JSON object: {{"title": "<short headline>", "steps": [{{"time": "HH:MM", "text": "<one plain sentence>"}}], "next": ["<what the family member should do now, 2-3 short items>"]}}
Use 4 to 7 steps, oldest first. Do not include account, card or phone numbers, and do not use internal
signal names written with underscores (say "a hidden message aimed at AI software", not "ai_directed_text")."""


def narrate(incident: dict[str, Any]) -> dict[str, Any] | None:
    lines = "\n".join(
        f"{time.strftime('%H:%M:%S', time.localtime(t['ts']))} [{t['source']}] {t['text']}" for t in incident["timeline"]
    )
    reasons = "\n".join(f"- {r.get('reason')}: {r.get('evidence')}" for r in incident["verdict"].get("reasons", []))
    messages = [
        {"role": "system", "content": NARRATE_PROMPT},
        {"role": "user", "content": f"<session_timeline>\n{lines}\n</session_timeline>\n<judge_reasons>\n{reasons}\n</judge_reasons>"},
    ]
    error = ""
    for _attempt in range(2):  # a reply can come back empty if reasoning uses the whole budget
        try:
            return ModelClient.for_provider("meta").chat_json(messages, max_tokens=8000, reasoning_effort="low")
        except Exception as exc:  # narration is optional; the incident page works without it
            error = type(exc).__name__
    return {"title": "Tripwire stopped a likely scam", "steps": [], "next": [], "error": error}


# -- family dashboard --------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def dashboard(k: str = Query("")) -> HTMLResponse:
    if not hmac.compare_digest(k, KEYS["dashboard_key"]):
        raise HTTPException(403, "Open the dashboard with its private link.")
    return HTMLResponse((DASHBOARD_DIR / "index.html").read_text(encoding="utf-8"))


@app.get("/i/{incident_id}", response_class=HTMLResponse)
def incident_page(incident_id: str, k: str = Query("")) -> HTMLResponse:
    _load_incident(incident_id, k)
    return HTMLResponse((DASHBOARD_DIR / "incident.html").read_text(encoding="utf-8"))


@app.get("/api/status")
def get_status(k: str = Query("")) -> dict[str, Any]:
    if not hmac.compare_digest(k, KEYS["dashboard_key"]):
        raise HTTPException(403)
    incidents = []
    for folder in sorted(INCIDENTS_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
        try:
            i = json.loads((folder / "incident.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        incidents.append({"id": i["id"], "created": i["created"], "stage_name": i["stage_name"], "title": (i.get("narration") or {}).get("title") or "Likely scam stopped"})
    online = time.time() - _status.get("updated", 0) < 30
    return {**_status, "state": _status["state"] if online else "offline", "incidents": incidents}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, k: str = Query("")) -> dict[str, Any]:
    return _public(_load_incident(incident_id, k))


@app.get("/api/incidents/{incident_id}/image/{name}")
def get_image(incident_id: str, name: str, k: str = Query("")) -> FileResponse:
    _load_incident(incident_id, k)
    if not _IMAGE.match(name):
        raise HTTPException(404)
    path = _incident_dir(incident_id) / name
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "no-store"})
