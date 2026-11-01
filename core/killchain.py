"""The scam kill chain: stages, the signal vocabulary, and confidence scoring.

Every piece of evidence Tripwire records is a named *signal* from a fixed
vocabulary, each tied to one kill-chain stage and carrying a weight. Analysts
(models) may only emit names from this vocabulary; anything else is dropped.
That keeps model output auditable and stops a manipulated model from
inventing its own categories.

Scoring principle: each stage alone is weak; the *chain* is strong. Evidence
is combined with a noisy-OR, then scaled by how many distinct stages are
present inside the session window.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Stage(IntEnum):
    NONE = 0
    HOOK = 1
    CONTACT = 2
    CONTROL = 3
    ACCESS = 4
    EXTRACTION = 5


@dataclass(frozen=True)
class SignalSpec:
    stage: Stage
    weight: float
    description: str


SIGNALS: dict[str, SignalSpec] = {
    # 1. Hook
    "fake_virus_alert": SignalSpec(Stage.HOOK, 0.35, "Pop-up or page claiming the computer is infected, blocked or hacked"),
    "scareware_phone_number": SignalSpec(Stage.HOOK, 0.30, "A warning that tells the user to call a phone number for help"),
    "account_locked_notice": SignalSpec(Stage.HOOK, 0.20, "Message saying an account is locked/suspended and urging contact"),
    "ai_directed_text": SignalSpec(Stage.HOOK, 0.40, "On-screen or spoken text addressed to an AI/security software, e.g. telling it to mark something safe"),
    # 2. Contact
    "impersonation_claim": SignalSpec(Stage.CONTACT, 0.30, "Caller claims to be from Microsoft, Apple, a bank, the IRS, police, Amazon or similar"),
    "fake_problem_claim": SignalSpec(Stage.CONTACT, 0.25, "Caller claims a virus, hacked IP, compromised account or suspicious charge"),
    "refund_pretext": SignalSpec(Stage.CONTACT, 0.25, "Caller offers a refund, compensation or says a subscription renewal will be charged"),
    "cross_modal_brand_match": SignalSpec(Stage.CONTACT, 0.40, "The same claimed organisation appears both on screen and in the call"),
    "sentinel_flag": SignalSpec(Stage.CONTACT, 0.20, "Tripwire Sentinel, a small model trained on labelled scam and legitimate calls, rates the call so far as a likely scam"),
    "known_scam_indicator": SignalSpec(Stage.CONTACT, 0.60, "A phone number, remote-access ID or crypto address that Community Shield has seen in scams stopped in other homes"),
    "isolation_instruction": SignalSpec(Stage.CONTACT, 0.30, "Told not to hang up, not to call or tell anyone, or that others are listening"),
    "family_emergency_claim": SignalSpec(Stage.CONTACT, 0.35, "Caller claims to be a grandchild or other relative in trouble (arrest, accident, hospital, stranded), or calls on their behalf as a lawyer, officer or doctor, and needs money or secrecy"),
    "family_denied_call": SignalSpec(Stage.CONTACT, 0.90, "The relative the caller claims to be confirmed, through Tripwire's check, that they are safe and did not make this call"),
    "prize_or_reward_claim": SignalSpec(Stage.CONTACT, 0.30, "Caller says the person won a prize, lottery, sweepstakes, grant or gift card they did not enter for"),
    # 3. Control
    "remote_tool_install_request": SignalSpec(Stage.CONTROL, 0.40, "Caller asks the user to download/open a remote-access tool"),
    "remote_access_code_shared": SignalSpec(Stage.CONTROL, 0.40, "User reads out or is asked for a remote-access ID/code"),
    "remote_tool_launched": SignalSpec(Stage.CONTROL, 0.30, "A remote-access program started on this computer"),
    "remote_session_active": SignalSpec(Stage.CONTROL, 0.45, "A remote-access session appears to be live"),
    "remote_control_input": SignalSpec(Stage.CONTROL, 0.55, "Someone other than the person is moving the mouse or typing (input injected by a remote-access tool)"),
    "disable_protection": SignalSpec(Stage.CONTROL, 0.50, "Instruction to close a warning, ignore security software, or turn off/uninstall protection"),
    # 4. Access
    "bank_site_open": SignalSpec(Stage.ACCESS, 0.15, "An online banking or payment site is on screen"),
    "login_instruction": SignalSpec(Stage.ACCESS, 0.35, "Caller tells the user to log in to their bank, email or other account"),
    "bank_open_during_remote": SignalSpec(Stage.ACCESS, 0.55, "A banking site is open while a remote session is active"),
    "card_number_copied": SignalSpec(Stage.ACCESS, 0.25, "A payment card number was copied to the clipboard"),
    "merge_request": SignalSpec(Stage.ACCESS, 0.85, "The caller asks to merge, add or conference another call into this one (how a bank's automated code call is overheard)"),
    "forwarding_instruction": SignalSpec(Stage.CONTROL, 0.85, "The caller asks the person to dial a call-forwarding code (*72, **21*...) or to forward their calls"),
    "bank_code_overheard": SignalSpec(Stage.ACCESS, 0.90, "An automated bank voice began reading a one-time code where the caller could hear it (Line Lock)"),
    "code_request": SignalSpec(Stage.ACCESS, 0.85, "The caller asks for a one-time, verification or security code that was texted or emailed to the person (Code Shield)"),
    "code_received_during_call": SignalSpec(Stage.ACCESS, 0.40, "A text message carrying a one-time code arrived while the person was on a call with an unknown caller"),
    "personal_info_request": SignalSpec(Stage.ACCESS, 0.45, "An unsolicited caller asks for a Social Security number, bank account or routing number, password, PIN or one-time code, or for card details to 'verify', 'refund' or 'release' something"),
    # 5. Extraction
    "overpayment_refund_story": SignalSpec(Stage.EXTRACTION, 0.55, "Claim that too much was refunded and the user must send money back"),
    "gift_card_request": SignalSpec(Stage.EXTRACTION, 0.60, "Request to buy gift cards or read out gift card codes, or a gift card purchase on screen"),
    "crypto_request": SignalSpec(Stage.EXTRACTION, 0.55, "Request to buy or send cryptocurrency or use a Bitcoin ATM"),
    "wire_transfer_request": SignalSpec(Stage.EXTRACTION, 0.45, "Request to wire money, send a transfer, or a transfer screen is filled in"),
    "cash_withdrawal_request": SignalSpec(Stage.EXTRACTION, 0.45, "Request to withdraw cash, mail cash, or hand cash to a courier"),
    "advance_fee_request": SignalSpec(Stage.EXTRACTION, 0.55, "Asked to pay a fee, tax, shipping or 'processing' charge to receive a prize, refund, loan or grant"),
    "secrecy_instruction": SignalSpec(Stage.EXTRACTION, 0.50, "Told to hide a payment or transfer from the bank or family, or coached on what to tell the bank teller"),
    "crypto_address_copied": SignalSpec(Stage.EXTRACTION, 0.45, "A cryptocurrency address was copied to the clipboard"),
    "money_amount_copied": SignalSpec(Stage.EXTRACTION, 0.10, "A money amount was copied to the clipboard"),
    # Coercion that can appear at any point (scored with the stage it most supports)
    "urgency_pressure": SignalSpec(Stage.CONTACT, 0.20, "Pressure to act immediately, threats of loss, arrest or account closure"),
}

# How much of the combined evidence counts, by number of distinct stages seen.
CHAIN_MULTIPLIER = {0: 0.0, 1: 0.35, 2: 0.6, 3: 0.85, 4: 0.95, 5: 1.0}


# Raised only by Tripwire's own code (watchers, Community Shield, Sentinel, Code Shield's text check, a relative's
# answer), never by a model reading the screen or the call: a fooled analyst must not be able to claim them.
SYSTEM_ONLY = {
    "cross_modal_brand_match", "bank_open_during_remote", "known_scam_indicator", "sentinel_flag",
    "family_denied_call", "code_received_during_call", "remote_control_input", "bank_code_overheard",
}


def vocabulary_prompt() -> str:
    """The vocabulary as a compact list for analyst prompts (system-only signals left out)."""
    lines = []
    for name, spec in SIGNALS.items():
        if name in SYSTEM_ONLY:
            continue
        lines.append(f"- {name} (stage {int(spec.stage)} {spec.stage.name.lower()}): {spec.description}")
    return "\n".join(lines)


def score(signal_names: set[str]) -> tuple[float, set[Stage]]:
    """Return ``(confidence, stages_present)`` for a set of distinct signal names."""
    known = [SIGNALS[n] for n in signal_names if n in SIGNALS]
    if not known:
        return 0.0, set()
    miss = 1.0
    for spec in known:
        miss *= 1.0 - spec.weight
    stages = {spec.stage for spec in known}
    return round((1.0 - miss) * CHAIN_MULTIPLIER[len(stages)], 3), stages
