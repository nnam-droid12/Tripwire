"""Creating and enriching incidents: shared by the agent API and the web arena.

An incident is created synchronously (frames stored, text redacted, a private
link minted). Then, on background threads, the family is texted, the threat
is outlined with SAM 3.1 and Muse Spark writes the plain-language story.
"""

from __future__ import annotations

import base64
import io
import os
import secrets
import sys
import threading
import time
from typing import Any

from PIL import Image

from agent.redact import RedactionError, redact_image, redact_text
from analysts.common import SAFETY_RULES
from backend.highlight import highlight
from backend.sms import send_sms
from backend.storage import IncidentStore
from core.model_client import ModelClient

PUBLIC_BASE_URL = os.environ.get("TRIPWIRE_PUBLIC_URL", "http://127.0.0.1:8765").rstrip("/")
STORE = IncidentStore()


def recheck_redaction(image: Image.Image) -> Image.Image:
    """Defence in depth: redact again where OCR exists (Windows). Raises if OCR fails there."""
    try:
        return redact_image(image)[0]
    except RedactionError:
        if sys.platform != "win32":
            return image.convert("RGB")  # no Windows OCR on Linux; frames were redacted (fail-closed) before upload
        raise


def create_incident(
    verdict: dict[str, Any],
    snapshot: dict[str, Any],
    frames_png: list[bytes],
    protected_name: str = "",
    *,
    redact_frames: bool = True,
    source: str = "agent",
) -> tuple[str, str]:
    """Store a new incident, start the family alert and enrichment; return ``(id, private link)``."""
    incident_id = secrets.token_hex(8)
    token = secrets.token_urlsafe(16)
    frames = []
    for i, png in enumerate(frames_png[:4]):
        try:
            image = Image.open(io.BytesIO(png))
            image = recheck_redaction(image) if redact_frames else image.convert("RGB")
        except (RedactionError, OSError, ValueError):
            continue
        name = f"frame_{i}.png"
        buf = io.BytesIO()
        image.save(buf, format="PNG", optimize=True)
        STORE.put_image(incident_id, name, buf.getvalue())
        frames.append(name)

    incident = {
        "id": incident_id,
        "token": token,
        "created": time.time(),
        "source": source,
        "protected_name": protected_name,
        "verdict": {**verdict, "family_message": redact_text(verdict.get("family_message", ""))},
        "stage": snapshot.get("stage", 0),
        "stage_name": snapshot.get("stage_name", ""),
        "confidence": snapshot.get("confidence", 0.0),
        "brands": snapshot.get("brands", {}),
        "signals": [{**s, "evidence": redact_text(s.get("evidence", ""))} for s in snapshot.get("signals", [])],
        "timeline": [{**t, "text": redact_text(t.get("text", ""))} for t in snapshot.get("timeline", [])],
        "frames": frames,
        "highlights": [],
        "narration": None,
        "sms": None,
    }
    STORE.save(incident)
    link = f"{PUBLIC_BASE_URL}/i/{incident_id}?k={token}"
    threading.Thread(target=_alert_family, args=(incident_id, link), daemon=True).start()
    threading.Thread(target=_enrich, args=(incident_id,), daemon=True).start()
    return incident_id, link


def decode_frames(frames_b64: list[str]) -> list[bytes]:
    out = []
    for b64 in frames_b64:
        try:
            out.append(base64.b64decode(b64))
        except ValueError:
            continue
    return out


def _alert_family(incident_id: str, link: str) -> None:
    incident = STORE.load(incident_id)
    who = incident["protected_name"] or "your relative"
    message = incident["verdict"].get("family_message") or f"Tripwire stopped a likely scam on {who}'s computer."
    body = f"TRIPWIRE ALERT for {who}: {message} Details: {link}"
    result = send_sms(body)
    sms = {"sent": result.sent, "detail": result.detail, "body": body.replace(incident["token"], "<token>")}
    STORE.update(incident_id, lambda i: i.update(sms=sms))


def _enrich(incident_id: str) -> None:
    incident = STORE.load(incident_id)
    highlights = []
    for name in incident["frames"]:
        png, boxes = highlight(STORE.get_image(incident_id, name))
        if boxes:
            out = name.replace("frame_", "highlight_")
            STORE.put_image(incident_id, out, png)
            highlights.append({"image": out, "frame": name, "labels": sorted({b.label for b in boxes})})
    narration = narrate(incident)
    STORE.update(incident_id, lambda i: i.update(highlights=highlights, narration=narration))


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
