"""System-tray icon: Tripwire is visible, never hidden.

The icon shows whether Tripwire is watching (green), paused (grey) or raising
an alert (red), so it is plainly a tool the person opted into, not spyware.

"Turn off your antivirus" is a standard scammer instruction, so pausing or
quitting needs the family PIN when one is set, and is refused outright while
a hard stop is on screen.
"""

from __future__ import annotations

from typing import Callable

import pystray
from PIL import Image, ImageDraw

from agent.overlay import WarningOverlay
from core.settings import Settings

COLORS = {"watching": (34, 139, 34), "paused": (128, 128, 128), "alert": (200, 0, 0)}


def _icon(color: tuple[int, int, int]) -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon([(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)], fill=color)  # shield
    d.line([(20, 32), (29, 41), (45, 23)], fill=(255, 255, 255), width=6)  # tick
    return img


class TrayIcon:
    def __init__(
        self,
        settings: Settings,
        overlay: WarningOverlay,
        *,
        is_alert_active: Callable[[], bool],
        on_pause: Callable[[bool], None],
        on_quit: Callable[[], None],
    ) -> None:
        self.settings, self.overlay = settings, overlay
        self.is_alert_active, self.on_pause, self.on_quit = is_alert_active, on_pause, on_quit
        self.paused = False
        self.icon = pystray.Icon(
            "tripwire",
            _icon(COLORS["watching"]),
            "Tripwire: watching",
            menu=pystray.Menu(
                pystray.MenuItem(lambda _: self._status_text(), None, enabled=False),
                pystray.MenuItem(lambda _: "Resume watching" if self.paused else "Pause watching", self._toggle_pause),
                pystray.MenuItem("Quit Tripwire", self._quit),
            ),
        )

    def run_detached(self) -> None:
        self.icon.run_detached()

    def set_state(self, state: str) -> None:
        """``watching`` | ``paused`` | ``alert``"""
        self.icon.icon = _icon(COLORS[state])
        self.icon.title = f"Tripwire: {state}"
        self.icon.update_menu()

    def stop(self) -> None:
        self.icon.stop()

    def _status_text(self) -> str:
        if self.is_alert_active():
            return "ALERT: scam warning on screen"
        return "Paused" if self.paused else "Watching for scams"

    def _with_pin(self, action: str, then: Callable[[], None]) -> None:
        if self.is_alert_active():
            return  # never during a hard stop
        if not self.settings.has_pin:
            then()
            return
        self.overlay.ask_pin(f"Enter the family PIN to {action} Tripwire.", lambda ok: then() if ok else None)

    def _toggle_pause(self) -> None:
        if self.paused:
            self.paused = False
            self.on_pause(False)
            self.set_state("watching")
            return

        def pause() -> None:
            self.paused = True
            self.on_pause(True)
            self.set_state("paused")

        self._with_pin("pause", pause)

    def _quit(self) -> None:
        self._with_pin("quit", self.on_quit)
