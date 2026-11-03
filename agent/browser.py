"""The browser's real address, and Device Trust checks of this computer (Windows).

Site Check must compare what a page *claims* with where the browser *really* is. The real address is
read from the browser's own toolbar through Windows UI Automation (the accessibility interface screen
readers use), never from screen pixels: a scam page can paint a fake address bar, but it cannot change
the value of the browser's real one.

:class:`DeviceTrustWatcher` checks the computer itself (see :mod:`core.device_trust`): the hosts file at
start-up and every 10 minutes, and the certificate of a bank's, shop's or agency's real site whenever one
is open, because that is exactly where a tampered computer would show a fake site with the real address.
"""

from __future__ import annotations

import threading
import time

from core import device_trust
from core.events import Event, EventBus
from core.site_check import OFFICIAL, host_of, registrable

BROWSERS = {"chrome.exe": "Chrome", "msedge.exe": "Edge", "firefox.exe": "Firefox", "brave.exe": "Brave", "opera.exe": "Opera"}
_EDIT = 50004  # UIA_EditControlTypeId
_VALUE_PROPERTY = 30045  # UIA_ValueValuePropertyId
_PROTECTED = {d for domains in OFFICIAL.values() for d in domains}
_uia = None


def _automation():
    global _uia
    if _uia is None:
        import comtypes.client

        comtypes.client.GetModule("UIAutomationCore.dll")
        from comtypes.gen.UIAutomationClient import CUIAutomation, IUIAutomation

        _uia = comtypes.client.CreateObject(CUIAutomation, interface=IUIAutomation)
    return _uia


def foreground_browser() -> tuple[int, str] | None:
    """``(window handle, browser name)`` if the window in front is a web browser."""
    try:
        import psutil
        import win32gui
        import win32process

        hwnd = win32gui.GetForegroundWindow()
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        name = BROWSERS.get(psutil.Process(pid).name().lower())
        return (hwnd, name) if name else None
    except Exception:
        return None


def address_of(hwnd: int) -> str | None:
    """The value of the browser's own address bar (Chrome, Edge, Brave, Opera, Firefox), or None (e.g. full screen)."""
    try:
        uia = _automation()
        root = uia.ElementFromHandle(hwnd)
        edits = root.FindAll(4, uia.CreatePropertyCondition(30003, _EDIT))  # TreeScope_Descendants, ControlType == Edit
        for i in range(edits.Length):
            el = edits.GetElement(i)
            name = (el.CurrentName or "").lower()
            if "address" not in name and "search" not in name:
                continue
            value = el.GetCurrentPropertyValue(_VALUE_PROPERTY)
            if isinstance(value, str) and "." in value and " " not in value.strip():
                return value.strip()
    except Exception:
        return None
    return None


def current_url() -> tuple[str, str] | None:
    """``(real address, browser name)`` of the browser in front, if there is one."""
    fg = foreground_browser()
    if not fg:
        return None
    url = address_of(fg[0])
    return (url, fg[1]) if url else None


class DeviceTrustWatcher(threading.Thread):
    """Publishes ``device`` events when the hosts file or a certificate shows the computer was tampered with."""

    def __init__(self, bus: EventBus, hosts_every_s: float = 600.0) -> None:
        super().__init__(name="device-trust", daemon=True)
        self.bus = bus
        self.hosts_every_s = hosts_every_s
        self._halt = threading.Event()
        self._reported: set[str] = set()
        self._cert_checked: dict[str, float] = {}

    def run(self) -> None:
        while not self._halt.is_set():
            for f in device_trust.hosts_overrides():
                self._publish(f)
            self._halt.wait(self.hosts_every_s)

    def stop(self) -> None:
        self._halt.set()

    def check_url(self, url: str) -> None:
        """Called when the browser shows a new address: a protected site's certificate is checked (in the background)."""
        host = host_of(url)
        if registrable(host) not in _PROTECTED or time.time() - self._cert_checked.get(host, 0) < 3600:
            return
        self._cert_checked[host] = time.time()
        threading.Thread(target=lambda: (f := device_trust.certificate_check(url)) and self._publish(f), daemon=True).start()

    def _publish(self, finding) -> None:
        if finding.evidence in self._reported:
            return
        self._reported.add(finding.evidence)
        self.bus.publish(Event("device", finding.signal, {"summary": f"Device Trust: {finding.evidence}"}))
