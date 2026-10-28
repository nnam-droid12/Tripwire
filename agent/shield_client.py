"""Community Shield lookups from the desktop agent.

Sends only lines that contain something shaped like a phone number, remote-
access ID or crypto address (checked locally first), so ordinary speech never
leaves the computer for this. A slow or offline backend never blocks
analysis: the lookup times out quickly and returns nothing.
"""

from __future__ import annotations

import json
import os
import urllib.request

from core.shield import extract

DEFAULT_URL = "http://127.0.0.1:8765"


def lookup(text: str) -> list[dict]:
    indicators = extract(text)
    if not indicators:
        return []  # nothing identifier-shaped: no request at all
    query = " ".join(i.value for i in indicators)  # only the identifiers themselves are sent
    url = os.environ.get("TRIPWIRE_BACKEND_URL", DEFAULT_URL).rstrip("/") + "/api/shield/check"
    req = urllib.request.Request(url, data=json.dumps({"text": query}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read()).get("hits", [])
    except OSError:
        return []
