"""Identify who is connected in a remote-access session, for the family allowlist.

A son helping over AnyDesk and a scammer on AnyDesk look identical from the
process list. What differs is the remote party's ID, which the tools write to
local connection logs:

* AnyDesk:    ``%ProgramData%\\AnyDesk\\connection_trace.txt`` (installed) or
              ``%AppData%\\AnyDesk\\connection_trace.txt`` (portable); UTF-16,
              one line per session: direction, date, time, auth type, remote ID.
* TeamViewer: ``%ProgramFiles%\\TeamViewer\\Connections_incoming.txt``;
              tab-separated, remote ID first.

If the latest *incoming* connection came from an ID the family registered,
the session is trusted and does not count as scam evidence.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from pathlib import Path

_ANYDESK_LINE = re.compile(r"^\s*(Incoming|Outgoing)\s+(\d{4}-\d{2}-\d{2}),\s+(\d{2}:\d{2})\s+\S+\s+(\d{6,})", re.M)


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or raw[1:2] == b"\x00":
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def parse_anydesk_trace(text: str) -> list[tuple[str, datetime, str]]:
    """Return ``(direction, when, remote_id)`` for every session line."""
    out = []
    for direction, day, hhmm, remote_id in _ANYDESK_LINE.findall(text):
        out.append((direction, datetime.strptime(f"{day} {hhmm}", "%Y-%m-%d %H:%M"), remote_id))
    return out


def parse_teamviewer_incoming(text: str) -> list[tuple[str, datetime, str]]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].strip().isdigit():
            try:
                when = datetime.strptime(parts[2].strip(), "%d-%m-%Y %H:%M:%S")
            except ValueError:
                continue
            out.append(("Incoming", when, parts[0].strip()))
    return out


def _trace_paths(tool: str) -> list[Path]:
    env = os.environ
    if tool == "AnyDesk":
        return [Path(env.get("ProgramData", r"C:\ProgramData")) / "AnyDesk" / "connection_trace.txt",
                Path(env.get("APPDATA", "")) / "AnyDesk" / "connection_trace.txt"]
    if tool == "TeamViewer":
        return [Path(env.get("ProgramFiles", r"C:\Program Files")) / "TeamViewer" / "Connections_incoming.txt",
                Path(env.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "TeamViewer" / "Connections_incoming.txt"]
    return []


def latest_incoming_id(tool: str, within: timedelta = timedelta(minutes=10), now: datetime | None = None) -> str | None:
    """The remote ID of the most recent incoming session, if it started recently."""
    parser = parse_anydesk_trace if tool == "AnyDesk" else parse_teamviewer_incoming
    now = now or datetime.now()
    sessions = []
    for path in _trace_paths(tool):
        try:
            sessions += parser(_read_text(path))
        except OSError:
            continue
    incoming = [s for s in sessions if s[0] == "Incoming" and now - s[1] <= within]
    return max(incoming, key=lambda s: s[1])[2] if incoming else None
