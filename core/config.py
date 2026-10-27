"""Paths and tunables shared across the agent; also loads ``.env``.

Everything captured at runtime (frames, audio, session logs) lives under
``runtime/``, which is git-ignored and purged after ``RETENTION_HOURS``.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")
RUNTIME_DIR = Path(os.environ.get("TRIPWIRE_RUNTIME_DIR", REPO_ROOT / "runtime"))
FRAMES_DIR = RUNTIME_DIR / "frames"
AUDIO_DIR = RUNTIME_DIR / "audio"
LOGS_DIR = RUNTIME_DIR / "logs"

RETENTION_HOURS = float(os.environ.get("TRIPWIRE_RETENTION_HOURS", "24"))
