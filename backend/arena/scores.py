"""Arena scoreboard: every finished game, and Tripwire's running record.

Scores are written by the server when a game ends, from the session itself;
the visitor can only attach a nickname to their own game. Stored next to the
incidents (local folder or the private GCS bucket) as one small JSON list.
"""

from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from backend.storage import IncidentStore

_KEY = "arena/games.json"
_NAME = re.compile(r"[^A-Za-z0-9 _.\-']")
_lock = threading.Lock()
_backend = IncidentStore().backend


def _load() -> list[dict[str, Any]]:
    raw = _backend.get_bytes(_KEY)
    return json.loads(raw) if raw else []


def _save(games: list[dict[str, Any]]) -> None:
    _backend.put_bytes(_KEY, json.dumps(games[-2000:]).encode(), "application/json")


def record_game(session_id: str, situation: str, caught: bool, stage: int, stage_name: str, lines: int, seconds: float) -> None:
    if lines < 1:
        return  # nobody spoke: not a game
    with _lock:
        games = _load()
        games.append({"id": session_id, "situation": situation, "caught": caught, "stage": stage, "stage_name": stage_name,
                      "lines": lines, "seconds": round(seconds), "ts": time.time(), "name": ""})
        _save(games)


def set_name(session_id: str, name: str) -> bool:
    name = _NAME.sub("", name).strip()[:24]
    if not name:
        return False
    with _lock:
        games = _load()
        for g in games:
            if g["id"] == session_id and not g["name"]:
                g["name"] = name
                _save(games)
                return True
    return False


def board(limit: int = 8) -> dict[str, Any]:
    games = _load()
    stopped = [g for g in games if g["caught"]]
    escaped = [g for g in games if not g["caught"] and g["stage"] >= 3]  # reached control or beyond without a hard stop
    best = sorted(stopped, key=lambda g: (-g["stage"], -g["lines"], g["ts"]))[:limit]
    return {
        "games": len(games),
        "stopped": len(stopped),
        "escaped": len(escaped),
        "best": [{k: g[k] for k in ("name", "stage_name", "lines", "seconds", "situation")} for g in best],
        "beat_tripwire": [{k: g[k] for k in ("name", "stage_name", "lines", "situation")} for g in escaped[-limit:]],
    }
