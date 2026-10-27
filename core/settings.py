"""Per-household settings: family contact name, PIN, trusted remote-support IDs.

Stored in ``config/tripwire.json`` (git-ignored; see
``config/tripwire.example.json``). The family PIN is never stored in clear:
only a salted PBKDF2 hash. Set it with ``python -m scripts.set_pin``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.config import REPO_ROOT

SETTINGS_PATH = Path(os.environ.get("TRIPWIRE_SETTINGS", REPO_ROOT / "config" / "tripwire.json"))
_PBKDF2_ROUNDS = 200_000


@dataclass
class Settings:
    family_name: str = "your family"
    protected_name: str = ""
    # tool name (as in agent.watchers.REMOTE_ACCESS_TOOLS) -> remote IDs allowed to connect
    trusted_remote_ids: dict[str, list[str]] = field(default_factory=dict)
    pin_salt: str = ""
    pin_hash: str = ""
    cooldown_s: float = 60.0
    kill_remote_on_hard_stop: bool = True
    consent_given_at: float = 0.0

    @classmethod
    def load(cls, path: Path = SETTINGS_PATH) -> "Settings":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def save(self, path: Path = SETTINGS_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    # -- PIN -----------------------------------------------------------------------

    def set_pin(self, pin: str) -> None:
        if not (pin.isdigit() and 4 <= len(pin) <= 8):
            raise ValueError("PIN must be 4-8 digits")
        salt = os.urandom(16)
        self.pin_salt = salt.hex()
        self.pin_hash = _hash_pin(pin, salt)

    def check_pin(self, pin: str) -> bool:
        if not self.pin_hash:
            return False
        return hmac.compare_digest(_hash_pin(pin, bytes.fromhex(self.pin_salt)), self.pin_hash)

    @property
    def has_pin(self) -> bool:
        return bool(self.pin_hash)

    def is_trusted(self, tool: str, remote_id: str | None) -> bool:
        if not remote_id:
            return False
        return remote_id.replace(" ", "") in {i.replace(" ", "") for i in self.trusted_remote_ids.get(tool, [])}


def _hash_pin(pin: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, _PBKDF2_ROUNDS).hex()


def mask_id(remote_id: str | None) -> str:
    """Show only the last 3 digits of a remote-access ID in logs."""
    if not remote_id:
        return "unknown"
    return "*" * max(0, len(remote_id) - 3) + remote_id[-3:]
