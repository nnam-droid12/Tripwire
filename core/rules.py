"""Family rules: deterministic decisions before sensitive actions.

The AI watches the whole story; these rules guard the moments that matter, the
way a bank holds a wire it isn't sure about. Before a sensitive action (a wire
or transfer screen, a gift-card checkout, a crypto deposit, a full-screen
remote session) the rules answer one of:

* ``allow``  - nothing in the rules applies;
* ``verify`` - ask the person a quick question out loud first;
* ``hold``   - pause the payment until a family member approves it;
* ``deny``   - stop outright.

Rules are plain code over facts observed by Tier 0 and the CaseFile, so they
cannot hallucinate. They can only make Tripwire stricter: the final decision
is the stricter of the family rules and the CaseJudge. Families choose them in
their settings; the defaults below are what most families want.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Decision(IntEnum):
    ALLOW = 0
    VERIFY = 1
    HOLD = 2
    DENY = 3

    @property
    def label(self) -> str:
        return self.name.lower()


# What a page or event is, for the rules. Screen pages are classified by Tier 1 signals
# or (in the arena) by the page id.
SENSITIVE = {
    "wire_transfer": "a wire transfer",
    "gift_cards": "a gift-card purchase",
    "bitcoin": "a cryptocurrency deposit",
}


@dataclass
class Facts:
    """What is true right now, from observation only (no model opinions)."""

    on_call: bool = False
    caller_known: bool = False  # caller is a trusted family member / allowlisted helper
    remote_control: bool = False  # someone other than the person is driving the mouse or keyboard
    sensitive_action: str | None = None  # key of SENSITIVE, if one is on screen
    amount: float | None = None
    judge_suspects_scam: bool = False  # the CaseJudge's verified verdict is "scam" (it never relaxes a rule)


@dataclass(frozen=True)
class RuleResult:
    decision: Decision
    rule: str
    explanation: str


@dataclass
class FamilyRules:
    """The family's choices. Defaults are deliberately protective."""

    hold_payments_during_calls_over: float = 500.0
    no_gift_cards_during_calls: bool = True
    no_crypto_during_calls: bool = True
    deny_payments_under_remote_control: bool = True
    verify_unknown_callers_before_payments: bool = True
    approvers: list[str] = field(default_factory=lambda: ["David"])

    def evaluate(self, f: Facts) -> RuleResult:
        """The strictest rule that applies, with a plain-language explanation."""
        results = [RuleResult(Decision.ALLOW, "none", "No family rule applies.")]
        what = SENSITIVE.get(f.sensitive_action or "", "")
        if what and f.remote_control and self.deny_payments_under_remote_control:
            results.append(RuleResult(Decision.DENY, "no_payments_under_remote_control",
                                      f"Someone else is controlling the computer while {what} is on screen."))
        if f.sensitive_action == "gift_cards" and f.on_call and not f.caller_known and self.no_gift_cards_during_calls:
            results.append(RuleResult(Decision.HOLD, "no_gift_cards_during_calls",
                                      "Gift cards are being bought during a call with someone who isn't family."))
        if f.sensitive_action == "bitcoin" and f.on_call and not f.caller_known and self.no_crypto_during_calls:
            results.append(RuleResult(Decision.HOLD, "no_crypto_during_calls",
                                      "Cryptocurrency is being bought during a call with someone who isn't family."))
        if f.sensitive_action == "wire_transfer" and f.on_call and not f.caller_known:
            big = f.amount is None or f.amount >= self.hold_payments_during_calls_over
            if big:
                results.append(RuleResult(Decision.HOLD, "hold_large_payments_during_calls",
                                          f"A transfer of {'an unknown amount' if f.amount is None else f'${f.amount:,.0f}'} is being made during a call with someone who isn't family."))
        if what and f.on_call and not f.caller_known and self.verify_unknown_callers_before_payments:
            results.append(RuleResult(Decision.VERIFY, "verify_before_payments",
                                      f"{what.capitalize()} during a call with someone who isn't family: check with the person first."))
        if what and f.judge_suspects_scam:
            results.append(RuleResult(Decision.DENY, "scam_in_progress", f"{what.capitalize()} while a scam is in progress."))
        return max(results, key=lambda r: r.decision)


def combine(rule: Decision, judge: Decision) -> Decision:
    """Rules and the CaseJudge each have a vote; the stricter one wins. Neither can relax the other."""
    return max(rule, judge)
