"""Escalation policy: when to ask the CaseJudge, and what its verdict may do.

The Tier-1 score is cheap and always on but easily fooled by a single scary
moment, so it only decides *whether to ask* the Tier-2 judge. The judge's
verdict decides the action, inside hard limits enforced here in code:

* ``hard_stop`` needs ``is_scam`` and judge confidence >= ``hard_stop_min``.
  A judge that recommends a hard stop with less certainty is downgraded to a
  nudge. A model cannot talk its way past these numbers.
* Actions only escalate within a session (log -> nudge -> hard_stop). Standing
  down from a hard stop is a human decision (family PIN or cooldown, Stage E).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Action(IntEnum):
    LOG = 0
    NUDGE = 1
    HARD_STOP = 2

    @classmethod
    def parse(cls, raw: Any) -> "Action":
        return {"log": cls.LOG, "nudge": cls.NUDGE, "hard_stop": cls.HARD_STOP}.get(str(raw).strip().lower(), cls.LOG)

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Verdict:
    """The CaseJudge's structured opinion on the whole session."""

    is_scam: bool
    confidence: float
    stage: int
    reasons: list[dict[str, str]]
    recommended_action: Action
    family_message: str
    senior_message: str = ""
    tier1_confidence: float = 0.0
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_scam": self.is_scam,
            "confidence": self.confidence,
            "stage": self.stage,
            "reasons": self.reasons,
            "recommended_action": self.recommended_action.label,
            "family_message": self.family_message,
            "senior_message": self.senior_message,
            "tier1_confidence": self.tier1_confidence,
            "ts": self.ts,
        }


@dataclass
class EscalationPolicy:
    judge_min_confidence: float = 0.4
    judge_min_stages: int = 2
    hard_stop_min: float = 0.8
    nudge_min: float = 0.5

    def should_judge(self, tier1_confidence: float, stages_present: int) -> bool:
        """Tier-1 says "medium or worse", or at least two kill-chain stages co-occur."""
        return tier1_confidence >= self.judge_min_confidence or stages_present >= self.judge_min_stages

    def decide(self, verdict: Verdict) -> Action:
        """Clamp the judge's recommendation to what its own certainty supports."""
        action = verdict.recommended_action
        if action == Action.HARD_STOP and not (verdict.is_scam and verdict.confidence >= self.hard_stop_min):
            action = Action.NUDGE
        if action == Action.NUDGE and not verdict.is_scam and verdict.confidence < self.nudge_min:
            action = Action.LOG
        return action
