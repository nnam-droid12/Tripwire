"""The few Twilio REST calls Tripwire makes during a protected call."""

from __future__ import annotations

import os

import requests

API = "https://api.twilio.com/2010-04-01/Accounts/{sid}"


def _auth() -> tuple[str, str]:
    return os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"]


def _url(path: str) -> str:
    return API.format(sid=_auth()[0]) + path


def child_calls(parent_sid: str) -> list[str]:
    """The live legs a call has dialled (here: the protected person's phone)."""
    resp = requests.get(_url("/Calls.json"), params={"ParentCallSid": parent_sid, "Status": "in-progress"}, auth=_auth(), timeout=10)
    resp.raise_for_status()
    return [c["sid"] for c in resp.json().get("calls", [])]


def redirect(call_sid: str, twiml: str) -> None:
    """Replace what a live call leg is doing with new TwiML (it leaves the bridge at once)."""
    resp = requests.post(_url(f"/Calls/{call_sid}.json"), data={"Twiml": twiml}, auth=_auth(), timeout=10)
    resp.raise_for_status()
