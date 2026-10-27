"""Provider-agnostic model client.

Tripwire talks to three OpenAI-compatible providers:

* ``baseten``   - Muse Spark Open, the cheap always-on Tier-1 narrator.
* ``meta``      - Muse Spark via the Meta Model API, the Tier-2 CaseJudge.
* ``fireworks`` - optional fallback.

All of them speak the OpenAI chat-completions protocol, so one thin wrapper
around the ``openai`` SDK covers every tier. Callers pick a provider by name
and never touch base URLs or keys directly; those come from the environment
(see ``.env.example``).
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


@dataclass(frozen=True)
class ProviderConfig:
    """Connection details for one OpenAI-compatible provider."""

    name: str
    api_key: str
    base_url: str
    model: str
    reasoning_effort: str | None = None

    @classmethod
    def from_env(cls, name: str) -> "ProviderConfig":
        """Build a config from ``<NAME>_API_KEY`` / ``_BASE_URL`` / ``_MODEL``."""
        prefix = name.upper()
        api_key = os.environ.get(f"{prefix}_API_KEY", "")
        base_url = os.environ.get(f"{prefix}_BASE_URL", "")
        model = os.environ.get(f"{prefix}_MODEL", "")
        missing = [k for k, v in (("API_KEY", api_key), ("BASE_URL", base_url), ("MODEL", model)) if not v]
        if missing:
            raise RuntimeError(f"Provider '{name}' is missing env vars: {', '.join(prefix + '_' + m for m in missing)}")
        effort = os.environ.get(f"{prefix}_REASONING_EFFORT") or None
        return cls(name=name, api_key=api_key, base_url=base_url, model=model, reasoning_effort=effort)


class ModelClient:
    """Chat / vision / JSON calls against a single provider."""

    def __init__(self, config: ProviderConfig, timeout: float = 60.0) -> None:
        self.config = config
        self._client = OpenAI(api_key=config.api_key, base_url=config.base_url, timeout=timeout)

    @classmethod
    def for_provider(cls, name: str) -> "ModelClient":
        """Create a client for ``baseten``, ``meta`` or ``fireworks`` from env vars."""
        return cls(ProviderConfig.from_env(name))

    def chat(self, messages: list[dict[str, Any]], *, temperature: float = 0.2, max_tokens: int = 2048, **kwargs: Any) -> str:
        """Send a chat completion and return the assistant text.

        Muse Spark models reason before answering, and reasoning tokens count
        against ``max_tokens``; a small budget yields an empty reply. Hence the
        generous default and the per-provider ``reasoning_effort``.
        """
        if self.config.reasoning_effort and "reasoning_effort" not in kwargs:
            kwargs["reasoning_effort"] = self.config.reasoning_effort
        resp = self._client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        return resp.choices[0].message.content or ""

    def chat_json(self, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        """Like :meth:`chat`, but parse the reply as a JSON object.

        Models sometimes wrap JSON in prose or code fences, so we extract the
        outermost ``{...}`` block rather than trusting the raw string.
        """
        text = self.chat(messages, **kwargs)
        return parse_json_object(text)

    def describe_image(self, png_bytes: bytes, prompt: str, *, system: str | None = None, **kwargs: Any) -> str:
        """Ask a vision-capable model about a single (already redacted) PNG frame."""
        data_url = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
        messages: list[dict[str, Any]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append(
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            }
        )
        return self.chat(messages, **kwargs)


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def parse_json_object(text: str) -> dict[str, Any]:
    """Extract and parse the first top-level JSON object in ``text``."""
    match = _JSON_BLOCK.search(text)
    if not match:
        raise ValueError(f"No JSON object in model reply: {text[:200]!r}")
    return json.loads(match.group(0))
