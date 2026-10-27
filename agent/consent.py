"""One-time consent screen shown on first run.

Tripwire watches the screen and listens to calls, so the person it protects
must agree to that, in plain words, before it starts. The answer and its time
are stored in the household settings; declining exits without capturing
anything.
"""

from __future__ import annotations

import time

from core.settings import Settings

TEXT = (
    "Tripwire helps protect you from phone and computer scams.\n\n"
    "While it is on, it will:\n"
    "  •  look at your screen and listen to calls on speakerphone,\n"
    "  •  hide account and card numbers on this computer before anything is sent,\n"
    "  •  speak up, and if needed cover the screen, when it sees a scam,\n"
    "  •  send {family} a text if it stops a scam.\n\n"
    "Recordings and screenshots are deleted after 24 hours.\n"
    "You will always see the Tripwire shield next to the clock."
)


def ensure_consent(settings: Settings) -> bool:
    """Show the consent dialog if needed. Returns True if Tripwire may run."""
    if settings.consent_given_at:
        return True
    import tkinter as tk

    answer = {"ok": False}
    root = tk.Tk()
    root.title("Tripwire")
    root.attributes("-topmost", True)
    root.resizable(False, False)
    tk.Label(root, text="Turn on Tripwire?", font=("Segoe UI", 20, "bold"), padx=24, pady=12).pack(anchor="w")
    tk.Label(root, text=TEXT.format(family=settings.family_name), font=("Segoe UI", 13), justify="left", padx=24).pack(anchor="w")
    buttons = tk.Frame(root, pady=18)
    buttons.pack()

    def choose(ok: bool) -> None:
        answer["ok"] = ok
        root.destroy()

    tk.Button(buttons, text="Yes, turn it on", font=("Segoe UI", 13, "bold"), command=lambda: choose(True)).pack(side="left", padx=8)
    tk.Button(buttons, text="Not now", font=("Segoe UI", 13), command=lambda: choose(False)).pack(side="left", padx=8)
    root.protocol("WM_DELETE_WINDOW", lambda: choose(False))
    root.mainloop()
    if answer["ok"]:
        settings.consent_given_at = time.time()
        settings.save()
    return answer["ok"]
