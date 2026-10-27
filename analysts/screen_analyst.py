"""ScreenAnalyst (Tier 1): turns kept screen frames into kill-chain signals.

For each frame kept by the change detector it asks Muse Spark Open (Baseten)
for a one-line description, a risk level, the organisations the screen
claims to represent, and any matching signals. Frames are passed through
on-device redaction before upload (``agent/redact.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agent.redact import redact_for_upload
from analysts.common import SAFETY_RULES, clean_brands, clean_risk, clean_signals, signal_menu
from core.model_client import ModelClient, parse_json_object

PROMPT = f"""{SAFETY_RULES}

Look at this screenshot of the protected person's Windows screen.

{signal_menu()}

Only use signals that the SCREEN itself shows (pages, pop-ups, windows, on-screen text).
Reply with one JSON object and nothing else:
{{"description": "<one sentence: what is on screen>",
  "risk": "none|low|med|high",
  "brands": ["<organisations the screen claims to be or represent, e.g. Microsoft>"],
  "signals": [{{"signal": "<allowed name>", "evidence": "<short quote or detail from the screen>"}}]}}"""


@dataclass(frozen=True)
class ScreenFinding:
    description: str
    risk: str
    brands: list[str]
    signals: list[tuple[str, str]]


class ScreenAnalyst:
    def __init__(self, client: ModelClient | None = None) -> None:
        self.client = client or ModelClient.for_provider("baseten")

    def analyze(self, frame_path: Path) -> ScreenFinding:
        png = redact_for_upload(frame_path.read_bytes())
        reply = self.client.describe_image(png, PROMPT)
        data = parse_json_object(reply)
        return ScreenFinding(
            description=str(data.get("description", ""))[:300],
            risk=clean_risk(data.get("risk")),
            brands=clean_brands(data.get("brands")),
            signals=clean_signals(data.get("signals")),
        )
