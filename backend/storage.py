"""Where the backend keeps incidents: a local folder, or a private GCS bucket.

On the laptop, incidents live under ``runtime/backend/incidents``. On Cloud
Run, whose disk is temporary, they go to the bucket named in
``TRIPWIRE_GCS_BUCKET`` (private, uniform access, objects auto-deleted after
30 days by a lifecycle rule). Keys look like ``incidents/<id>/incident.json``;
an ``incidents/index.json`` lists incidents newest first for the dashboard.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Callable

from core.config import RUNTIME_DIR


class LocalStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def get_bytes(self, key: str) -> bytes | None:
        path = self.root / key
        return path.read_bytes() if path.is_file() else None

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)  # atomic: a concurrent reader never sees a half-written file


class GcsStore:
    def __init__(self, bucket: str) -> None:
        from google.cloud import storage

        self.bucket = storage.Client().bucket(bucket)

    def get_bytes(self, key: str) -> bytes | None:
        blob = self.bucket.blob(key)
        return blob.download_as_bytes() if blob.exists() else None

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.bucket.blob(key).upload_from_string(data, content_type=content_type)


class IncidentStore:
    """Incident JSON, images and the newest-first index, on either backend."""

    def __init__(self) -> None:
        bucket = os.environ.get("TRIPWIRE_GCS_BUCKET")
        self.backend = GcsStore(bucket) if bucket else LocalStore(RUNTIME_DIR / "backend")
        self._lock = threading.RLock()

    def load(self, incident_id: str) -> dict[str, Any] | None:
        raw = self.backend.get_bytes(f"incidents/{incident_id}/incident.json")
        return json.loads(raw) if raw else None

    def save(self, incident: dict[str, Any]) -> None:
        with self._lock:
            self.backend.put_bytes(f"incidents/{incident['id']}/incident.json", json.dumps(incident, indent=2).encode(), "application/json")
            index = [i for i in self.index() if i["id"] != incident["id"]]
            entry = {
                "id": incident["id"], "created": incident["created"], "stage_name": incident["stage_name"],
                "title": (incident.get("narration") or {}).get("title") or "Likely scam stopped",
            }
            index = sorted(index + [entry], key=lambda i: i["created"], reverse=True)[:200]
            self.backend.put_bytes("incidents/index.json", json.dumps(index).encode(), "application/json")

    def update(self, incident_id: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        """Load, change and save one incident as a single step (background threads update it concurrently)."""
        with self._lock:
            incident = self.load(incident_id)
            if incident is not None:
                mutate(incident)
                self.save(incident)

    def index(self) -> list[dict[str, Any]]:
        raw = self.backend.get_bytes("incidents/index.json")
        return json.loads(raw) if raw else []

    def put_image(self, incident_id: str, name: str, png: bytes) -> None:
        self.backend.put_bytes(f"incidents/{incident_id}/{name}", png, "image/png")

    def get_image(self, incident_id: str, name: str) -> bytes | None:
        return self.backend.get_bytes(f"incidents/{incident_id}/{name}")
