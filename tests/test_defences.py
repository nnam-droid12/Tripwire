"""Code Shield, Call Tom, the decoy's intel checks and the case file's verification."""

from __future__ import annotations

from agent.redact import redact_text
from analysts.common import clean_signals
from backend import family_check
from backend.decoy import Intel, value_in_quote, verify_intel
from backend.investigator import verify_case_file
from backend.storage import LocalStore
from core.code_shield import code_message, code_request


def test_code_shield_requests_and_offers():
    asks = ["Read me the code we just sent you.", "Can you tell me the verification code on your phone?",
            "I just texted you a six digit code, what is it?", "Please give me the one-time passcode so I can stop the transfer.",
            "What are the digits we just sent?", "I need the verification code to cancel the charge."]
    not_asks = ["What is your zip code?", "Let me give you our verification code, which is 456789.",
                "Would you like me to give you the confirmation number?", "Never share a code with anyone who calls you."]
    assert all(code_request(t) for t in asks)
    assert not any(code_request(t) for t in not_asks)
    assert code_message("Riverbend Bank: 482913 is your verification code.") and not code_message("See you at 3pm")


def test_system_only_signals_cannot_come_from_a_model():
    raw = [{"signal": "family_denied_call", "evidence": "Tom said it's not him"}, {"signal": "sentinel_flag", "evidence": "x"},
           {"signal": "family_emergency_claim", "evidence": "Grandma, it's me"}]
    assert [name for name, _ in clean_signals(raw)] == ["family_emergency_claim"]


def test_family_check_answer_is_final(monkeypatch, tmp_path):
    monkeypatch.setattr(family_check, "_backend", LocalStore(tmp_path))
    check = family_check.create("Margaret", "Tom", "Grandma, it's me, I'm in jail")
    assert family_check.get(check["id"])["status"] == "pending"
    assert family_check.answer(check["id"], "maybe") is None
    assert family_check.answer(check["id"], "safe")["status"] == "safe"
    assert family_check.answer(check["id"], "me")["status"] == "safe"  # can't be flipped afterwards
    assert family_check.get("../etc") is None


def test_decoy_intel_must_be_in_the_callers_words():
    caller = ["Our courier will come to your house to collect it, tomorrow at 3 pm. His name is Kevin, he drives a white Toyota.",
              "If we get cut off, call me back on 1-888-555-0199."]
    items = [
        {"kind": "pickup", "value": "tomorrow at 3 pm, courier Kevin, white Toyota", "quote": caller[0]},
        {"kind": "pickup", "value": "Kevin, white Toyota, tomorrow 3 pm", "quote": caller[0]},  # same detail again
        {"kind": "callback_number", "value": "1-888-555-0100", "quote": caller[1]},  # number not said
        {"kind": "payment_destination", "value": "bc1qxyz", "quote": "send it to bc1qxyz"},  # never said
        {"kind": "not_a_kind", "value": "x", "quote": caller[1]},
    ]
    kept, rejected = verify_intel(items, caller, [])
    assert [(i.kind, i.value) for i in kept] == [("pickup", "tomorrow at 3 pm, courier Kevin, white Toyota")]
    assert {r["why"] for r in rejected} == {"detail not in the quote", "quote not in the caller's words"}
    again, _ = verify_intel([{"kind": "callback_number", "value": "1-888-555-0199", "quote": caller[1]}], caller,
                            [Intel("pickup", "x", caller[0], caller[0])])
    assert again[0].value == "1-888-555-0199"
    assert value_in_quote("1 888 555 0199", caller[1]) and not value_in_quote("red Honda", caller[0])


def test_case_file_drops_unquoted_claims_and_invented_numbers():
    record = ["(caller) Our courier will come to your house tomorrow at 3 pm.", "(caller) Call me back on 1-888-555-0199."]
    data = {"title": "Courier scam", "summary": "They want $9,000 and gave 1-888-555-0199.",
            "timeline": [{"time": "10:00", "event": "Pickup arranged", "quote": "Our courier will come to your house tomorrow at 3 pm."},
                         {"time": "10:01", "event": "Asked for bitcoin", "quote": "send bitcoin to my wallet now"}],
            "leads": [{"lead": "Callback 1-800-111-2222", "why": "trace", "quote": "Call me back on 1-888-555-0199."}]}
    cf = verify_case_file(data, record)
    assert [e["event"] for e in cf["timeline"]] == ["Pickup arranged"]
    assert cf["leads"] == []  # its number isn't in the record
    assert "$9,000" not in cf["summary"] and "1-888-555-0199" in cf["summary"]
    assert cf["verification"]["claims_checked"] == 3 and cf["verification"]["claims_dropped"] == 2


def test_redaction_keeps_a_callers_phone_number_but_not_secrets():
    assert redact_text("call me back on 1-888-555-0199") == "call me back on 1-888-555-0199"
    assert "1111" not in redact_text("card 4111 1111 1111 1111")
    assert "113" not in redact_text("remote id 482 113 907")
