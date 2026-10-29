"""Call Tom: ask the real relative, instead of trying to hear a voice clone.

When a caller claims to be a grandchild (or other relative) in trouble, no one
can reliably tell a cloned voice from the real one. But the real person can be
asked. Tripwire sends the relative a link: "Someone on the phone with Grandma
says they're you. Are you OK?" A "That's not me, I'm safe" answer is a fact
from outside the call, and it ends the scam whatever the voice sounded like.

Stored next to the incidents, like payment approvals. The link id is the
credential (unguessable); answers can't be changed once given.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from typing import Any

from backend.storage import IncidentStore

_lock = threading.Lock()
_backend = IncidentStore().backend
EXPIRES_S = 30 * 60
ANSWERS = {"safe": "not me, I'm safe", "me": "yes, it's really me"}


def _key(check_id: str) -> str:
    return f"checks/{check_id}.json"


def create(protected_name: str, relative: str, claim: str, source: str = "agent") -> dict[str, Any]:
    check = {"id": secrets.token_hex(8), "created": time.time(), "status": "pending", "source": source,
             "protected_name": protected_name, "relative": relative, "claim": claim[:300], "answered_at": None}
    _backend.put_bytes(_key(check["id"]), json.dumps(check).encode(), "application/json")
    return check


def get(check_id: str) -> dict[str, Any] | None:
    if not check_id.isalnum():
        return None
    raw = _backend.get_bytes(_key(check_id))
    if not raw:
        return None
    check = json.loads(raw)
    if check["status"] == "pending" and time.time() - check["created"] > EXPIRES_S:
        check["status"] = "expired"
    return check


def answer(check_id: str, status: str) -> dict[str, Any] | None:
    if status not in ANSWERS:
        return None
    with _lock:
        check = get(check_id)
        if not check or check["status"] != "pending":
            return check
        check.update(status=status, answered_at=time.time())
        _backend.put_bytes(_key(check_id), json.dumps(check).encode(), "application/json")
        return check
