"""A daily cap on phone minutes: the number is public, and every minute is billed."""

from __future__ import annotations

import json
import os
import threading
import time

from backend.incidents import STORE

KEY = "phone/usage.json"
_lock = threading.Lock()


def daily_cap_seconds() -> float:
    return float(os.environ.get("TRIPWIRE_PHONE_DAILY_MINUTES", "120")) * 60


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _load() -> dict:
    raw = STORE.backend.get_bytes(KEY)
    data = json.loads(raw) if raw else {}
    return data if data.get("day") == _today() else {"day": _today(), "seconds": 0.0, "calls": 0}


def allowed() -> bool:
    with _lock:
        return _load()["seconds"] < daily_cap_seconds()


def add(seconds: float) -> None:
    with _lock:
        data = _load()
        data["seconds"] += max(0.0, seconds)
        data["calls"] += 1
        STORE.backend.put_bytes(KEY, json.dumps(data).encode(), "application/json")


def today() -> dict:
    with _lock:
        return {**_load(), "cap_seconds": daily_cap_seconds()}
