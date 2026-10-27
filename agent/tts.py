"""Speaking warnings aloud with the built-in Windows voice (SAPI).

Speech matters more than the screen during a hard stop: if a scammer is
controlling the screen remotely, the senior can still *hear* Tripwire. We use
SAPI through pywin32, so nothing extra has to be installed, and run it on a
dedicated thread because COM objects belong to the thread that created them.
"""

from __future__ import annotations

import queue
import threading

SVSF_ASYNC = 1
SVSF_PURGE_BEFORE_SPEAK = 2


class Speaker(threading.Thread):
    """Queue text to be spoken. ``urgent`` interrupts whatever is being said."""

    def __init__(self, rate: int = -1, volume: int = 100, enabled: bool = True) -> None:
        super().__init__(name="tts", daemon=True)
        self.rate, self.volume, self.enabled = rate, volume, enabled
        self._jobs: queue.Queue[tuple[str, bool] | None] = queue.Queue()
        self.spoken: list[str] = []  # for logs and tests

    def say(self, text: str, urgent: bool = False) -> None:
        self.spoken.append(text)
        if self.enabled:
            self._jobs.put((text, urgent))

    def stop(self) -> None:
        self._jobs.put(None)

    def run(self) -> None:
        if not self.enabled:
            return
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        try:
            voice = win32com.client.Dispatch("SAPI.SpVoice")
            voice.Rate, voice.Volume = self.rate, self.volume
            while (job := self._jobs.get()) is not None:
                text, urgent = job
                voice.Speak(text, SVSF_PURGE_BEFORE_SPEAK if urgent else 0)
        finally:
            pythoncom.CoUninitialize()
