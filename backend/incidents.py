"""Creating and enriching incidents: shared by the agent API and the web arena.

An incident is created synchronously (frames stored, text redacted, a private
link minted). Then, on background threads, the family is texted, the threat
is outlined with SAM 3.1, Muse Image turns the scam screen into a verified
large-print explainer card, and Muse Spark writes the plain-language story.
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
from backend import explainer, shield
from backend.highlight import highlight
from backend.sms import send_sms
from backend.storage import IncidentStore
from core.model_client import ModelClient
from core.output_checks import invented_numbers
from core.shield import from_incident

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
    protected_ids: set[str] = frozenset(),
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
        "verdict": {**verdict, "family_message": redact_text(verdict.get("family_message", "")),
                    "report": {k: redact_text(str(v)) for k, v in verdict["report"].items()} if verdict.get("report") else None},
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
    # Community Shield: the scammer's identifiers from this stopped scam now protect every other home
    shield.report(from_incident(incident["timeline"], protected_ids=protected_ids, signals=incident["signals"]), incident_id)
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
    card = make_explainer(incident_id, incident, highlights)
    narration = check_narration(narrate(incident), incident)
    STORE.update(incident_id, lambda i: i.update(highlights=highlights, narration=narration, explainer=card))


def make_explainer(incident_id: str, incident: dict[str, Any], highlights: list[dict]) -> dict[str, Any] | None:
    """"This is what the scam looked like": Muse Image edits the scam screen into a verified explainer card."""
    if not incident["frames"]:
        return None
    signals = {s["name"] for s in incident.get("signals", [])}
    brands = set().union(*map(set, incident.get("brands", {}).values())) if incident.get("brands") else set()
    labels = {h["frame"]: set(h["labels"]) for h in highlights}
    seen = [t["text"] for t in incident["timeline"]] + [s.get("evidence", "") for s in incident.get("signals", [])]
    # screens SAM outlined first, newest last; each must still be confirmed to show the scam before it is edited
    frames = sorted(incident["frames"], key=lambda f: f not in labels)[:3]
    card = None
    for frame in frames:
        template = explainer.choose(labels.get(frame, set()), signals, brands)
        if not template:
            continue
        try:
            card = explainer.make_card(STORE.get_image(incident_id, frame), template, explainer.phone_numbers(seen))
        except Exception:
            card = None
        if card:
            break
    if not card:
        return None
    STORE.put_image(incident_id, "explainer.png", card.pop("png"))
    return {**card, "image": "explainer.png", "frame": frame, "model": "Muse Image"}


NARRATE_PROMPT = f"""{SAFETY_RULES}

Write what happened during this incident for a worried family member, in plain words.
Reply with one JSON object: {{"title": "<short headline>", "steps": [{{"time": "HH:MM", "text": "<one plain sentence>"}}], "next": ["<what the family member should do now, 2-3 short items>"]}}
Use 4 to 7 steps, oldest first. Do not include account, card or phone numbers, and do not use internal
signal names written with underscores (say "a hidden message aimed at AI software", not "ai_directed_text")."""


def check_narration(narration: dict[str, Any] | None, incident: dict[str, Any]) -> dict[str, Any] | None:
    """Drop any sentence of the story that states a number the record does not contain."""
    if not narration or not narration.get("steps"):
        return narration
    record = [t["text"] for t in incident["timeline"]]
    kept = [s for s in narration["steps"] if isinstance(s, dict) and not invented_numbers(str(s.get("text", "")), record)]
    narration["verification"] = {"sentences_checked": len(narration["steps"]), "removed": len(narration["steps"]) - len(kept)}
    narration["steps"] = kept
    return narration


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
