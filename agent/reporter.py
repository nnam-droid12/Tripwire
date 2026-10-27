"""Pushes live status and incidents from the device to the backend.

Everything sent is redacted first: frames go through :func:`redact_for_upload`
(a frame that cannot be redacted is left out), and the backend redacts
timeline text again on arrival. Requests run on a background thread so a slow
network never delays capture or interventions.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import threading
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from agent.redact import RedactionError, redact_for_upload
from core.casefile import CaseFile
from core.config import RUNTIME_DIR
from core.events import Event, EventBus
from core.settings import Settings

if TYPE_CHECKING:
    from core.orchestrator import Orchestrator

DEFAULT_URL = "http://127.0.0.1:8765"


def agent_token() -> str:
    token = os.environ.get("TRIPWIRE_AGENT_TOKEN")
    if token:
        return token
    keys = RUNTIME_DIR / "backend" / "keys.json"  # written by a backend on this machine
    return json.loads(keys.read_text())["agent_token"] if keys.exists() else ""


class BackendReporter(threading.Thread):
    def __init__(
        self,
        bus: EventBus,
        case: CaseFile,
        orchestrator: "Orchestrator",
        settings: Settings | None = None,
        url: str | None = None,
        log: Callable[[str], None] = print,
        max_frames: int = 3,
    ) -> None:
        super().__init__(name="backend-reporter", daemon=True)
        self.bus, self.case, self.orchestrator = bus, case, orchestrator
        self.settings = settings or Settings.load()
        self.url = (url or os.environ.get("TRIPWIRE_BACKEND_URL", DEFAULT_URL)).rstrip("/")
        self.log = log
        self.max_frames = max_frames
        self.heartbeat_s = 15.0
        self.token = agent_token()
        self.frames: list[tuple[float, str]] = []  # (ts, path) of kept frames
        self.alert = False
        self.incident_links: list[str] = []
        self._jobs: queue.Queue[tuple[str, dict] | None] = queue.Queue()

    def start(self) -> None:
        super().start()
        self.bus.subscribe(self.handle)
        self._queue_status("watching starting")

    def stop(self, timeout: float = 30) -> None:
        self._jobs.put(None)
        self.join(timeout)

    # -- event handling ------------------------------------------------------------

    def handle(self, event: Event) -> None:
        key = (event.source, event.kind)
        if key == ("screen", "frame_kept"):
            self.frames = (self.frames + [(event.ts, event.data["path"])])[-40:]
        elif key == ("decision", "hard_stop"):
            self.alert = True
            self._queue_status(event.data.get("summary", ""))
        elif key == ("intervention", "dismissed"):
            self.alert = False
            self._queue_status(event.data.get("summary", ""))
        elif key == ("intervention", "family_alert_requested"):
            self._jobs.put(("incident", {}))
        elif event.source in ("judge", "decision"):
            self._queue_status(event.data.get("summary", ""))

    def _queue_status(self, summary: str) -> None:
        stage, confidence, _ = self.case.assess()
        state = "alert" if self.alert else "paused" if self.orchestrator.paused else "watching"
        self._jobs.put(("status", {
            "state": state, "stage": int(stage), "stage_name": stage.name, "confidence": confidence,
            "action": self.orchestrator.action.label, "summary": summary[:200],
        }))

    # -- worker --------------------------------------------------------------------

    def run(self) -> None:
        while True:
            try:
                job = self._jobs.get(timeout=self.heartbeat_s)
            except queue.Empty:  # heartbeat: lets the dashboard tell "watching" from "offline"
                self._queue_status("")
                continue
            if job is None:
                return
            kind, payload = job
            try:
                if kind == "status":
                    self._post("/api/agent/status", payload)
                else:
                    self._send_incident()
            except OSError as exc:
                self.log(f"  ! backend unreachable ({self.url}): {exc}")

    def _send_incident(self) -> None:
        verdict = self.orchestrator.decisions[-1][1].to_dict() if self.orchestrator.decisions else {}
        body = {
            "verdict": verdict,
            "snapshot": self.case.snapshot(),
            "frames": self._redacted_frames(),
            "protected_name": self.settings.protected_name,
        }
        reply = self._post("/api/agent/incidents", body)
        link = reply.get("link", "")
        self.incident_links.append(link)
        self.bus.publish(Event("intervention", "family_alerted", {"summary": f"Incident sent to backend; family link {link.split('?')[0]}", "incident": reply.get("id")}))

    def _redacted_frames(self) -> list[str]:
        """The most telling frames: any that produced screen evidence or a med/high risk rating, else the latest."""
        snap = self.case.snapshot()
        telling = {t["ts"] for t in snap["timeline"] if t["source"] == "screen" and t["risk"] in ("med", "high")}
        telling |= {s["ts"] for s in snap["signals"] if s["source"] == "screen"}
        chosen = [p for ts, p in self.frames if ts in telling] or [p for _, p in self.frames[-1:]]
        out = []
        for path in chosen[-self.max_frames:]:
            try:
                out.append(base64.b64encode(redact_for_upload(Path(path).read_bytes())).decode())
            except (RedactionError, OSError):
                continue  # never send a frame we could not redact
        return out

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            self.url + path, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "X-Tripwire-Token": self.token},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")
