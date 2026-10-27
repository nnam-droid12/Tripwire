"""Tier-0 system watchers: remote-access processes, remote sessions, clipboard.

These are cheap, local, and high-signal. A remote-access tool launching in the
middle of a "Microsoft support" call is the Control stage of the kill chain,
and needs no model to notice.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass

import psutil

from agent.allowlist import latest_incoming_id
from core.events import Event, EventBus
from core.settings import Settings, mask_id

# Executable name (lower-case) -> product name. Covers the tools most often
# abused in tech-support scams, plus Windows' built-in Quick Assist and
# Remote Assistance, which scammers increasingly prefer because nothing has to
# be downloaded.
REMOTE_ACCESS_TOOLS: dict[str, str] = {
    "anydesk.exe": "AnyDesk",
    "teamviewer.exe": "TeamViewer",
    "teamviewer_desktop.exe": "TeamViewer",
    "tv_w32.exe": "TeamViewer",
    "tv_x64.exe": "TeamViewer",
    "ultraviewer_desktop.exe": "UltraViewer",
    "ultraviewer_service.exe": "UltraViewer",
    "screenconnect.windowsclient.exe": "ScreenConnect",
    "screenconnect.clientservice.exe": "ScreenConnect",
    "logmein.exe": "LogMeIn",
    "lmi_rescue.exe": "LogMeIn Rescue",
    "logmeinrescue.exe": "LogMeIn Rescue",
    "quickassist.exe": "Windows Quick Assist",
    "msra.exe": "Windows Remote Assistance",
    "rustdesk.exe": "RustDesk",
    "supremo.exe": "Supremo",
    "aa_v3.exe": "Ammyy Admin",
    "srserver.exe": "Splashtop",
    "za_connect.exe": "Zoho Assist",
    "g2ax_customer.exe": "GoTo Assist",
    "remotepc.exe": "RemotePC",
}


def match_remote_tool(exe_name: str, extra: dict[str, str] | None = None) -> str | None:
    """Return the product name if ``exe_name`` is a known remote-access tool."""
    name = exe_name.lower()
    return (extra or {}).get(name) or REMOTE_ACCESS_TOOLS.get(name)


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_unspecified)


class ProcessWatcher(threading.Thread):
    """Reports remote-access tools starting/stopping and their network activity.

    Network heuristic: remote-access tools keep a connection to their relay
    servers even when idle, so "has a connection" proves nothing. Instead we
    record each tool's public endpoints during a short settle period after it
    is first seen, and report ``remote_session_suspected`` when it opens
    *additional* public connections later, which is what happens when a
    session is established. This is a hint, not proof; the ScreenAnalyst
    corroborates it by seeing the session window.

    Inbound Windows Remote Desktop (local port 3389) is reported directly.

    Family allowlist: when a session starts, the remote party's ID is read
    from the tool's connection log (``agent/allowlist.py``). A registered
    family ID produces ``trusted_remote_session`` instead, which is not
    scam evidence.
    """

    def __init__(
        self,
        bus: EventBus,
        interval_s: float = 1.0,
        settle_s: float = 15.0,
        extra_tools: dict[str, str] | None = None,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(name="process-watcher", daemon=True)
        self.bus = bus
        self.interval_s = interval_s
        self.settle_s = settle_s
        self.extra_tools = {k.lower(): v for k, v in (extra_tools or {}).items()}
        self.settings = settings or Settings.load()
        self._halt = threading.Event()
        self._seen: dict[int, dict] = {}  # pid -> {tool, first_seen, baseline, session}
        self._rdp_active = False

    def run(self) -> None:
        first_pass = True
        while not self._halt.is_set():
            self._scan_processes(first_pass)
            self._scan_sessions()
            self._scan_rdp()
            first_pass = False
            self._halt.wait(self.interval_s)

    def stop(self) -> None:
        self._halt.set()

    def _scan_processes(self, first_pass: bool) -> None:
        alive: set[int] = set()
        for proc in psutil.process_iter(["pid", "name"]):
            tool = match_remote_tool(proc.info["name"] or "", self.extra_tools)
            if not tool:
                continue
            pid = proc.info["pid"]
            alive.add(pid)
            if pid in self._seen:
                continue
            self._seen[pid] = {"tool": tool, "first_seen": time.time(), "baseline": None, "session": False}
            kind = "process_running" if first_pass else "process_launched"
            verb = "already running" if first_pass else "launched"
            self.bus.publish(Event("process", kind, {"tool": tool, "exe": proc.info["name"], "pid": pid, "summary": f"{tool} {verb} (pid {pid})"}))
        for pid in set(self._seen) - alive:
            info = self._seen.pop(pid)
            self.bus.publish(Event("process", "process_exited", {"tool": info["tool"], "pid": pid, "summary": f"{info['tool']} exited (pid {pid})"}))

    def _scan_sessions(self) -> None:
        for pid, info in self._seen.items():
            try:
                conns = psutil.Process(pid).net_connections(kind="inet")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            endpoints = {c.raddr.ip for c in conns if c.status == psutil.CONN_ESTABLISHED and c.raddr and _is_public(c.raddr.ip)}
            if time.time() - info["first_seen"] < self.settle_s:
                info["baseline"] = (info["baseline"] or set()) | endpoints
                continue
            new = endpoints - (info["baseline"] or set())
            if new and not info["session"]:
                info["session"] = True
                self.bus.publish(session_event(info["tool"], pid, len(new), self.settings))
            elif not new and info["session"]:
                info["session"] = False
                self.bus.publish(Event("network", "remote_session_ended", {"tool": info["tool"], "pid": pid, "summary": f"{info['tool']} session connections closed"}))

    def _scan_rdp(self) -> None:
        try:
            conns = psutil.net_connections(kind="tcp")
        except psutil.AccessDenied:
            return
        active = any(c.status == psutil.CONN_ESTABLISHED and c.laddr and c.laddr.port == 3389 for c in conns)
        if active != self._rdp_active:
            self._rdp_active = active
            kind = "remote_session_suspected" if active else "remote_session_ended"
            self.bus.publish(Event("network", kind, {"tool": "Windows Remote Desktop", "summary": f"inbound Remote Desktop {'connected' if active else 'disconnected'}"}))


def session_event(tool: str, pid: int, new_endpoints: int, settings: Settings) -> Event:
    """``remote_session_suspected``, or ``trusted_remote_session`` for an allowlisted remote ID."""
    remote_id = latest_incoming_id(tool) if tool in ("AnyDesk", "TeamViewer") else None
    who = f"remote ID {mask_id(remote_id)}"
    if settings.is_trusted(tool, remote_id):
        return Event("network", "trusted_remote_session", {"tool": tool, "pid": pid, "remote_id": mask_id(remote_id), "summary": f"{tool} session from trusted family {who}"})
    return Event(
        "network",
        "remote_session_suspected",
        {"tool": tool, "pid": pid, "new_endpoints": new_endpoints, "remote_id": mask_id(remote_id), "summary": f"{tool} opened {new_endpoints} new remote connection(s), {who}: possible live session"},
    )


# -- clipboard -------------------------------------------------------------------


@dataclass(frozen=True)
class ClipboardFinding:
    kind: str
    masked: str


_CLIPBOARD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("bitcoin_address", re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("ethereum_address", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("money_amount", re.compile(r"(?:[$£€₦]\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*(?:\.\d{2})?\s?(?:USD|GBP|EUR|NGN|dollars)\b)", re.I)),
    ("card_number", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
]


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _mask(value: str) -> str:
    """Keep only enough to recognise the value; never log it in full."""
    compact = re.sub(r"\s", "", value)
    return compact if len(compact) <= 8 else f"{compact[:4]}…{compact[-4:]}"


def scan_clipboard_text(text: str) -> list[ClipboardFinding]:
    """Find crypto addresses, money amounts and card numbers in clipboard text."""
    findings: list[ClipboardFinding] = []
    for kind, pattern in _CLIPBOARD_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if kind == "card_number":
                digits = re.sub(r"\D", "", value)
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    continue
                findings.append(ClipboardFinding(kind, "****" + digits[-4:]))
            elif kind == "money_amount":
                findings.append(ClipboardFinding(kind, value.strip()))
            else:
                findings.append(ClipboardFinding(kind, _mask(value)))
    return findings


class ClipboardWatcher(threading.Thread):
    """Polls the Windows clipboard sequence number and scans new text.

    Only the *kind* of finding and a masked value are published; the raw
    clipboard text never leaves this thread.
    """

    def __init__(self, bus: EventBus, interval_s: float = 0.5) -> None:
        super().__init__(name="clipboard-watcher", daemon=True)
        self.bus = bus
        self.interval_s = interval_s
        self._halt = threading.Event()

    def run(self) -> None:
        import win32clipboard

        last_seq = win32clipboard.GetClipboardSequenceNumber()
        while not self._halt.is_set():
            self._halt.wait(self.interval_s)
            seq = win32clipboard.GetClipboardSequenceNumber()
            if seq == last_seq:
                continue
            last_seq = seq
            text = self._read_text(win32clipboard)
            for finding in scan_clipboard_text(text) if text else []:
                self.bus.publish(Event("clipboard", finding.kind, {"masked": finding.masked, "summary": f"{finding.kind.replace('_', ' ')} copied: {finding.masked}"}))

    def stop(self) -> None:
        self._halt.set()

    @staticmethod
    def _read_text(win32clipboard) -> str:
        for _ in range(3):  # clipboard may be briefly locked by the copying app
            try:
                win32clipboard.OpenClipboard()
                try:
                    if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                        return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                    return ""
                finally:
                    win32clipboard.CloseClipboard()
            except Exception:
                time.sleep(0.05)
        return ""
