"""Full-screen, always-on-top warning shown during a hard stop.

Design for the person reading it: very large text, few words, one clear
instruction ("Hang up the phone"), and the *real* way to verify ("call the
number on the back of your card"), never a number taken from the screen or
the caller.

Design against the scammer: the window has no title bar, ignores close
requests (Alt+F4), re-asserts itself on top every 300 ms, and can only be
dismissed with the family PIN or after the cooldown (see ``core/guard.py``).

Tkinter is used because it ships with Python. It runs on its own thread; other
threads talk to it through :meth:`show`, :meth:`hide` and
:meth:`restart_cooldown`, which are queued and applied on the Tk thread.
"""

from __future__ import annotations

import os
import queue
import threading
from typing import Callable

from core.guard import DismissGate

BG = "#7a0000"
FG = "#ffffff"
ACCENT = "#ffd84d"


class WarningOverlay(threading.Thread):
    def __init__(self, gate: DismissGate, on_dismiss: Callable[[str], None], auto_hide_s: float | None = None) -> None:
        super().__init__(name="overlay", daemon=True)
        self.gate = gate
        self.on_dismiss = on_dismiss
        self.auto_hide_s = auto_hide_s  # tests/demos only
        # Demos only: cover one window ("x,y,w,h" in screen pixels) instead of the whole screen.
        region = os.environ.get("TRIPWIRE_OVERLAY_REGION")
        self.region = tuple(int(v) for v in region.split(",")) if region else None
        self.visible = False
        self._commands: queue.Queue[tuple[str, dict]] = queue.Queue()
        self._ready = threading.Event()

    # -- thread-safe API -----------------------------------------------------------

    def show(self, headline: str, reasons: list[str], family_name: str) -> None:
        self._commands.put(("show", {"headline": headline, "reasons": reasons, "family_name": family_name}))

    def hide(self) -> None:
        self._commands.put(("hide", {}))

    def restart_cooldown(self) -> None:
        self._commands.put(("cooldown", {}))

    def ask_pin(self, prompt: str, on_result: Callable[[bool], None]) -> None:
        """Small PIN dialog (used by the tray to pause or quit). Calls back with True if correct."""
        self._commands.put(("ask_pin", {"prompt": prompt, "on_result": on_result}))

    def wait_ready(self, timeout: float = 5.0) -> bool:
        return self._ready.wait(timeout)

    # -- Tk thread -----------------------------------------------------------------

    def run(self) -> None:
        import ctypes
        import tkinter as tk

        # Without this, on a display scaled to e.g. 150% Tk sees a smaller "logical"
        # screen and the warning covers only part of it.
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor DPI aware
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
        self.tk = tk
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.overrideredirect(True)
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)  # ignore Alt+F4 / close
        self._build()
        self._ready.set()
        self.root.after(100, self._poll)
        self.root.mainloop()

    def _build(self) -> None:
        tk, root = self.tk, self.root
        # sizes are designed for 1080 px of height; a demo region scales them down
        k = self.region[3] / 1080 * 0.8 if self.region else root.winfo_screenheight() / 1080
        big = ("Segoe UI", round(54 * k), "bold")
        mid = ("Segoe UI", round(26 * k))
        small = ("Segoe UI", max(9, round(18 * k)))
        frame = tk.Frame(root, bg=BG)
        frame.place(relx=0.5, rely=0.47, anchor="center")
        self.headline = tk.Label(frame, text="", font=big, fg=FG, bg=BG, wraplength=round(1500 * k), justify="center")
        self.headline.pack(pady=(0, round(18 * k)))
        tk.Label(frame, text="Hang up the phone now.", font=("Segoe UI", round(40 * k), "bold"), fg=ACCENT, bg=BG).pack(pady=(0, round(18 * k)))
        self.reasons = tk.Label(frame, text="", font=mid, fg=FG, bg=BG, wraplength=round(1400 * k), justify="left")
        self.reasons.pack(pady=(0, round(18 * k)))
        tk.Label(
            frame,
            text="Microsoft, Apple and your bank never call you about viruses or refunds.\n"
            "To check your account, call your bank\nusing the number on the BACK OF YOUR CARD.",
            font=mid, fg=FG, bg=BG, justify="center", wraplength=round(1400 * k),
        ).pack(pady=(0, round(14 * k)))
        self.family = tk.Label(frame, text="", font=small, fg=FG, bg=BG)
        self.family.pack(pady=(0, 24))

        controls = tk.Frame(frame, bg=BG)
        controls.pack()
        tk.Label(controls, text="Family PIN:", font=small, fg=FG, bg=BG).grid(row=0, column=0, padx=6)
        self.pin = tk.Entry(controls, show="•", font=small, width=8)
        self.pin.grid(row=0, column=1, padx=6)
        self.pin.bind("<Return>", lambda _e: self._try_pin())
        tk.Button(controls, text="Unlock", font=small, command=self._try_pin).grid(row=0, column=2, padx=6)
        self.self_dismiss = tk.Button(controls, text="", font=small, state="disabled", command=self._self_dismiss)
        self.self_dismiss.grid(row=0, column=3, padx=(30, 6))
        self.status = tk.Label(frame, text="", font=small, fg=ACCENT, bg=BG)
        self.status.pack(pady=(10, 0))

    def _poll(self) -> None:
        try:
            while True:
                cmd, args = self._commands.get_nowait()
                getattr(self, f"_do_{cmd}")(**args)
        except queue.Empty:
            pass
        if self.visible:
            self.root.attributes("-topmost", True)
            self.root.lift()
            left = self.gate.seconds_left()
            if left > 0:
                self.self_dismiss.config(state="disabled", text=f"I am safe ({int(left) + 1}s)")
            else:
                self.self_dismiss.config(state="normal", text="I have hung up. I am safe.")
        self.root.after(300, self._poll)

    def _do_show(self, headline: str, reasons: list[str], family_name: str) -> None:
        self.headline.config(text=headline)
        self.reasons.config(text="\n".join(f"•  {r}" for r in reasons[:3]))
        self.family.config(text=f"We have let {family_name} know.")
        self.status.config(text="")
        self.gate.restart_cooldown()
        if self.region:
            x, y, w, h = self.region
        else:
            x, y, w, h = 0, 0, self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.deiconify()
        self.root.attributes("-topmost", True)
        self.root.focus_force()
        self.visible = True
        if self.auto_hide_s:
            self.root.after(int(self.auto_hide_s * 1000), lambda: self._dismiss("auto (test)"))

    def _do_hide(self) -> None:
        self.root.withdraw()
        self.visible = False

    def _do_cooldown(self) -> None:
        self.gate.restart_cooldown()
        self.status.config(text="Someone asked you to close this. Please keep it open and hang up.")

    def _do_ask_pin(self, prompt: str, on_result: Callable[[bool], None]) -> None:
        tk = self.tk
        dialog = tk.Toplevel(self.root)
        dialog.title("Tripwire")
        dialog.attributes("-topmost", True)
        dialog.resizable(False, False)
        tk.Label(dialog, text=prompt, font=("Segoe UI", 12), padx=16, pady=10).pack()
        entry = tk.Entry(dialog, show="•", font=("Segoe UI", 14), width=10)
        entry.pack(padx=16)
        entry.focus_force()

        def finish(ok: bool) -> None:
            dialog.destroy()
            on_result(ok)

        entry.bind("<Return>", lambda _e: finish(self.gate.try_pin(entry.get())))
        dialog.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        tk.Button(dialog, text="OK", command=lambda: finish(self.gate.try_pin(entry.get()))).pack(pady=10)

    def _try_pin(self) -> None:
        if self.gate.try_pin(self.pin.get()):
            self._dismiss("family PIN")
        else:
            self.status.config(text="That PIN is not right.")
        self.pin.delete(0, "end")

    def _self_dismiss(self) -> None:
        if self.gate.can_self_dismiss():
            self._dismiss("cooldown")

    def _dismiss(self, how: str) -> None:
        if not self.visible:
            return
        self._do_hide()
        self.on_dismiss(how)
