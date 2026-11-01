"""Model-call provenance: every Meta model call, named, timed and visible as it happens.

Each call becomes one record: the exact model ID, which part of Tripwire made
it and why, how long it took, and the start of the request and the response.
Every record is printed to the server log as a ``META_MODEL_CALL`` line (Cloud
Run keeps them), and passed to an optional observer: the live scam test shows
them in its "Meta model calls" console, and an incident stores the calls made
while it was enriched (SAM 3.1, Muse Image, the family story).
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any, Callable

Observer = Callable[[dict], None]
SNIPPET = 220


def text_of(messages: list[dict[str, Any]]) -> str:
    """The newest user message as plain text (images shown as [image])."""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        content = m.get("content")
        if isinstance(content, list):
            return " ".join("[image]" if part.get("type") == "image_url" else str(part.get("text", "")) for part in content)
        return str(content or "")
    return ""


def emit(observer: Observer | None, model: str, purpose: str, started: float, request: str, response: str,
         ok: bool = True, provider: str = "") -> dict:
    record = {
        "ts": time.time(), "model": model, "provider": provider, "purpose": purpose, "ok": ok,
        "seconds": round(time.time() - started, 2),
        "request": " ".join(request.split())[:SNIPPET], "response": " ".join(response.split())[:SNIPPET],
        "request_full": request[:4000], "response_full": response[:4000],
    }
    line = {k: v for k, v in record.items() if not k.endswith("_full")}
    print("META_MODEL_CALL " + json.dumps(line, ensure_ascii=False), file=sys.stdout, flush=True)
    if observer:
        try:
            observer(record)
        except Exception:
            pass  # showing a call must never break making it
    return record
