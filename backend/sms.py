"""Family text alerts via Twilio's REST API.

Uses only the standard library (one form-encoded POST), so no SDK is needed.
Without Twilio credentials in the environment, messages are written to
``runtime/backend/sms_outbox.log`` instead (dry run), so the rest of the
pipeline can be demonstrated and tested without sending real texts.

Messages carry text and a private link only. Picture messages (MMS) are not
available in many countries, so the redacted, highlighted screenshot is shown
on the linked incident page.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

from core.config import RUNTIME_DIR

OUTBOX = RUNTIME_DIR / "backend" / "sms_outbox.log"


@dataclass(frozen=True)
class SmsResult:
    sent: bool
    detail: str


def send_sms(body: str, to: str | None = None) -> SmsResult:
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    sender = os.environ.get("TWILIO_FROM_NUMBER", "")
    to = to or os.environ.get("FAMILY_PHONE_NUMBER", "")
    if not (sid and token and sender and to):
        OUTBOX.parent.mkdir(parents=True, exist_ok=True)
        with OUTBOX.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "to": _mask_phone(to), "body": body}) + "\n")
        return SmsResult(False, f"dry run (Twilio not configured); written to {OUTBOX.name}")

    request = urllib.request.Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
        data=urllib.parse.urlencode({"From": sender, "To": to, "Body": body}).encode(),
        headers={"Authorization": "Basic " + base64.b64encode(f"{sid}:{token}".encode()).decode()},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:
            data = json.loads(resp.read())
        return SmsResult(True, f"sent to {_mask_phone(to)} (status {data.get('status')})")
    except urllib.error.HTTPError as exc:
        return SmsResult(False, f"Twilio error {exc.code}: {exc.read()[:200]!r}")
    except OSError as exc:
        return SmsResult(False, f"network error: {exc!r}")


def _mask_phone(number: str) -> str:
    return "*" * max(0, len(number) - 4) + number[-4:] if number else "(none)"
