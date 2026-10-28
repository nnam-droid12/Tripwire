"""Community Shield storage: the shared list of scammer identifiers.

One small JSON document next to the incidents. Each entry is a normalised
identifier with how many separate stopped scams reported it and when it was
first and last seen. Lookups are exact matches.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from backend.storage import IncidentStore
from core.shield import Indicator, extract

_KEY = "shield/indicators.json"
_lock = threading.Lock()
_backend = IncidentStore().backend
_cache: dict[str, Any] = {"at": 0.0, "data": {}}


def _load() -> dict[str, dict[str, Any]]:
    raw = _backend.get_bytes(_KEY)
    return json.loads(raw) if raw else {}


def _cached() -> dict[str, dict[str, Any]]:
    if time.time() - _cache["at"] > 10:  # lookups run on every call line; re-read at most every 10 s
        _cache.update(at=time.time(), data=_load())
    return _cache["data"]


def report(indicators: set[Indicator], incident_id: str) -> int:
    """Add a stopped scam's indicators. Returns how many were new."""
    if not indicators:
        return 0
    with _lock:
        data, new, now = _load(), 0, time.time()
        for ind in indicators:
            key = f"{ind.kind}:{ind.value}"
            entry = data.get(key)
            if entry is None:
                new += 1
                entry = data[key] = {"kind": ind.kind, "value": ind.value, "display": ind.display, "reports": 0,
                                     "first_seen": now, "incidents": []}
            if incident_id not in entry["incidents"]:
                entry["incidents"] = (entry["incidents"] + [incident_id])[-50:]
                entry["reports"] += 1
            entry["last_seen"] = now
        _backend.put_bytes(_KEY, json.dumps(data).encode(), "application/json")
        _cache.update(at=0.0)
        return new


def lookup(text: str) -> list[dict[str, Any]]:
    """Known scammer identifiers in a line of text."""
    data = _cached()
    hits = []
    for ind in extract(text):
        entry = data.get(f"{ind.kind}:{ind.value}")
        if entry:
            hits.append({"kind": ind.kind, "display": entry["display"], "reports": entry["reports"]})
    return hits


def stats() -> dict[str, Any]:
    data = _cached()
    recent = sorted(data.values(), key=lambda e: e.get("last_seen", 0), reverse=True)[:8]
    return {
        "indicators": len(data),
        "reports": sum(e["reports"] for e in data.values()),
        "recent": [{"kind": e["kind"], "display": e["display"], "reports": e["reports"]} for e in recent],
    }
