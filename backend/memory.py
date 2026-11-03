"""Scam Memory storage: the shared list of learned scam scripts.

One JSON document next to Community Shield's. Each playbook keeps how many
separate stopped scams taught it ("seen") and a few example lines per step from
different scammers, so one script, phrased many ways, stays one entry.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

from backend.storage import IncidentStore
from core.memory import merge_key

_KEY = "memory/playbooks.json"
_lock = threading.Lock()
_backend = IncidentStore().backend
_cache: dict[str, Any] = {"at": 0.0, "data": []}


def _load() -> list[dict[str, Any]]:
    raw = _backend.get_bytes(_KEY)
    return json.loads(raw) if raw else []


def playbooks() -> list[dict[str, Any]]:
    """Every stored playbook (re-read at most every 10 s: this runs on every call line)."""
    if time.time() - _cache["at"] > 10:
        _cache.update(at=time.time(), data=_load())
    return _cache["data"]


def add(playbook: dict[str, Any], incident_id: str) -> tuple[dict[str, Any], bool]:
    """Store a reviewed playbook, or merge it into the same script already known. ``(entry, is_new)``."""
    with _lock:
        data, now = _load(), time.time()
        same = merge_key(playbook, data)
        if same is not None:
            if incident_id not in same["incidents"]:
                same["incidents"] = (same["incidents"] + [incident_id])[-50:]
                same["seen"] += 1
            same["variants"] = (same.get("variants", []) + [[s["line"] for s in playbook["steps"]]])[-5:]
            same["last_seen"] = now
            entry, is_new = same, False
        else:
            pid = hashlib.sha1(json.dumps(playbook["steps"]).encode()).hexdigest()[:10]
            entry = {**playbook, "id": pid, "seen": 1, "incidents": [incident_id], "first_seen": now, "last_seen": now}
            data.append(entry)
            is_new = True
        _backend.put_bytes(_KEY, json.dumps(data).encode(), "application/json")
        _cache.update(at=0.0)
        return entry, is_new


def stats() -> dict[str, Any]:
    data = playbooks()
    recent = sorted(data, key=lambda e: e.get("last_seen", 0), reverse=True)[:8]
    return {"playbooks": len(data), "scams_learned_from": sum(e["seen"] for e in data),
            "recent": [{"title": e["title"], "kind": e["kind"], "seen": e["seen"], "steps": len(e["steps"])} for e in recent]}
