"""Who is in control? Detects mouse and keyboard input injected by remote-access tools.

Logging in tells you who sat down; it doesn't tell you who is moving the mouse.
When a scammer drives the computer through AnyDesk, TeamViewer or Quick
Assist, their clicks and keystrokes arrive as *injected* input: Windows marks
every such event with ``LLMHF_INJECTED`` (mouse) or ``LLKHF_INJECTED``
(keyboard) in its low-level input hooks. A physical mouse and keyboard never
set these flags.

So this is an observed fact, not a model's guess. To avoid confusing remote
control with accessibility software (which may also inject input), the event
is only reported while a remote-access tool is running.

Only counts are kept: no keystrokes, characters or cursor positions are
recorded or sent anywhere.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import threading
import time
from collections import deque
from typing import Callable

import psutil

from agent.watchers import match_remote_tool
from core.events import Event, EventBus

WH_KEYBOARD_LL, WH_MOUSE_LL = 13, 14
LLKHF_INJECTED, LLMHF_INJECTED = 0x10, 0x01
WM_QUIT = 0x0012


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("pt", wt.POINT), ("mouseData", wt.DWORD), ("flags", wt.DWORD), ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wt.DWORD), ("scanCode", wt.DWORD), ("flags", wt.DWORD), ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, wt.WPARAM, wt.LPARAM)


def running_remote_tool(extra_tools: dict[str, str] | None = None) -> str | None:
    for proc in psutil.process_iter(["name"]):
        tool = match_remote_tool(proc.info["name"] or "", extra_tools)
        if tool:
            return tool
    return None


class InjectionCounter:
    """Rolling count of injected vs physical input events. Pure logic, unit-testable."""

    def __init__(self, window_s: float = 5.0, threshold: int = 12, clock: Callable[[], float] = time.monotonic) -> None:
        self.window_s, self.threshold, self.clock = window_s, threshold, clock
        self.injected: deque[float] = deque()

    def add(self, injected: bool) -> bool:
        """Record one input event; True when injected input is sustained (not a stray event)."""
        now = self.clock()
        if injected:
            self.injected.append(now)
        while self.injected and now - self.injected[0] > self.window_s:
            self.injected.popleft()
        return len(self.injected) >= self.threshold


class ControlWatcher(threading.Thread):
    """Low-level input hooks; publishes ``control/remote_input`` when someone else is driving."""

    def __init__(self, bus: EventBus, extra_tools: dict[str, str] | None = None, quiet_s: float = 30.0) -> None:
        super().__init__(name="control-watcher", daemon=True)
        self.bus, self.extra_tools, self.quiet_s = bus, extra_tools, quiet_s
        self.counter = InjectionCounter()
        self.remote = False
        self._last_injected = 0.0
        self._thread_id = 0
        self._procs: list[HOOKPROC] = []  # keep references alive for the hooks' lifetime
        self.hooks_installed = False

    def _on_input(self, injected: bool) -> None:
        if injected:
            self._last_injected = time.monotonic()
        if self.counter.add(injected) and not self.remote:
            tool = running_remote_tool(self.extra_tools)
            if tool:
                self.remote = True
                self.bus.publish(Event("control", "remote_input", {"tool": tool,
                    "summary": f"Mouse and keyboard input is being injected by {tool}: someone else is in control"}))
        elif self.remote and time.monotonic() - self._last_injected > self.quiet_s:
            self.remote = False
            self.bus.publish(Event("control", "local_input", {"summary": "Injected input stopped: the person is back in control"}))

    def run(self) -> None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        user32.CallNextHookEx.argtypes = [wt.HHOOK, ctypes.c_int, wt.WPARAM, wt.LPARAM]
        user32.CallNextHookEx.restype = ctypes.c_ssize_t
        user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wt.HINSTANCE, wt.DWORD]
        user32.SetWindowsHookExW.restype = wt.HHOOK
        kernel32.GetModuleHandleW.restype = wt.HMODULE  # 64-bit handle: the default int return type truncates it
        user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
        self._thread_id = kernel32.GetCurrentThreadId()

        def mouse(n_code, w_param, l_param):
            if n_code == 0:
                info = ctypes.cast(l_param, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
                self._on_input(bool(info.flags & LLMHF_INJECTED))
            return user32.CallNextHookEx(None, n_code, w_param, l_param)

        def keyboard(n_code, w_param, l_param):
            if n_code == 0:
                info = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                self._on_input(bool(info.flags & LLKHF_INJECTED))
            return user32.CallNextHookEx(None, n_code, w_param, l_param)

        self._procs = [HOOKPROC(mouse), HOOKPROC(keyboard)]
        hooks = [user32.SetWindowsHookExW(WH_MOUSE_LL, self._procs[0], kernel32.GetModuleHandleW(None), 0),
                 user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._procs[1], kernel32.GetModuleHandleW(None), 0)]
        self.hooks_installed = all(hooks)
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:  # low-level hooks need a message loop
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        for h in hooks:
            user32.UnhookWindowsHookEx(h)

    def stop(self) -> None:
        if self._thread_id:
            ctypes.windll.user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
