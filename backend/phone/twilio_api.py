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


def conference_sid(name: str) -> str | None:
    """The live conference with this friendly name, if it has started."""
    resp = requests.get(_url("/Conferences.json"), params={"FriendlyName": name, "Status": "in-progress"}, auth=_auth(), timeout=10)
    resp.raise_for_status()
    rooms = resp.json().get("conferences", [])
    return rooms[0]["sid"] if rooms else None


def add_participant(conference: str, from_: str, to: str, **params: str) -> str:
    """Dial ``to`` into the conference (by friendly name); returns the new leg's call SID."""
    resp = requests.post(_url(f"/Conferences/{conference}/Participants.json"), data={"From": from_, "To": to, **params},
                         auth=_auth(), timeout=15)
    resp.raise_for_status()
    return resp.json()["call_sid"]


def participant_sids(conference_sid_: str) -> list[str]:
    resp = requests.get(_url(f"/Conferences/{conference_sid_}/Participants.json"), auth=_auth(), timeout=10)
    resp.raise_for_status()
    return [p["call_sid"] for p in resp.json().get("participants", [])]


def update_participant(conference_sid_: str, call_sid: str, **params: str) -> None:
    """Mute, hold or play an announcement to one participant (only they hear it)."""
    resp = requests.post(_url(f"/Conferences/{conference_sid_}/Participants/{call_sid}.json"), data=params, auth=_auth(), timeout=10)
    resp.raise_for_status()
