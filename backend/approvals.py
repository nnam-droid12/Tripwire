"""Family approvals for held payments.

When a family rule holds a payment, an approval request is created and the
family is sent a link. Nothing moves until a family member answers Approve
or Deny on that page. Stored next to the incidents.
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


def _key(approval_id: str) -> str:
    return f"approvals/{approval_id}.json"


def create(protected_name: str, what: str, explanation: str, approver: str, source: str = "agent") -> dict[str, Any]:
    approval = {
        "id": secrets.token_hex(8), "created": time.time(), "status": "pending", "source": source,
        "protected_name": protected_name, "what": what, "explanation": explanation, "approver": approver, "decided_at": None,
    }
    _backend.put_bytes(_key(approval["id"]), json.dumps(approval).encode(), "application/json")
    return approval


def get(approval_id: str) -> dict[str, Any] | None:
    if not approval_id.isalnum():
        return None
    raw = _backend.get_bytes(_key(approval_id))
    if not raw:
        return None
    approval = json.loads(raw)
    if approval["status"] == "pending" and time.time() - approval["created"] > EXPIRES_S:
        approval["status"] = "expired"  # an unanswered hold never turns into an approval
    return approval


def decide(approval_id: str, approve: bool) -> dict[str, Any] | None:
    with _lock:
        approval = get(approval_id)
        if not approval or approval["status"] != "pending":
            return approval
        approval.update(status="approved" if approve else "denied", decided_at=time.time())
        _backend.put_bytes(_key(approval_id), json.dumps(approval).encode(), "application/json")
        return approval
