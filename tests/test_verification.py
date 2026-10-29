"""Verification: deterministic checks, the independent reviewer, retry with feedback, tool allowlist."""

from __future__ import annotations

import json
from types import SimpleNamespace

from analysts.case_judge import CaseJudge
from backend.arena.recovery import REJECTED, RecoveryAgent
from core.output_checks import check_message, check_report, invented_numbers
from core.policy import Action, EscalationPolicy

LINE = "Hi, this is Microsoft support, I need you to install RemoteDesk so I can fix your computer"
SNAPSHOT = {
    "stage": 3, "stage_name": "CONTROL", "confidence": 0.7, "stages_present": [2, 3], "remote_active": False,
    "brands": {"call": ["microsoft"]}, "signals": [],
    "timeline": [{"ts": 0.0, "source": "call", "text": f"(caller) {LINE}"}],
}


def verdict_json(evidence: str) -> dict:
    return {"is_scam": True, "confidence": 0.95, "stage": 3, "recommended_action": "hard_stop", "family_message": "m",
            "reasons": [{"reason": "fake Microsoft asks for remote access", "evidence": evidence}]}


class FakeClient:
    def __init__(self, replies: list[dict]) -> None:
        self.replies, self.calls = list(replies), []

    def chat_json(self, messages, **_):
        self.calls.append(messages)
        return self.replies.pop(0)


class FakeReviewer:
    def __init__(self, supported: bool) -> None:
        self.supported = supported

    def review(self, case_text, reasons):
        return [{"supported": self.supported, "note": "n"} for _ in reasons]


def test_invented_quote_gets_feedback_and_a_second_attempt():
    client = FakeClient([verdict_json("the caller demanded bitcoin right now"), verdict_json("I need you to install RemoteDesk")])
    v = CaseJudge(client, reviewer=FakeReviewer(True)).judge(SNAPSHOT)
    assert v.verification["attempts"] == 2
    assert "NOT FOUND" in client.calls[1][-1]["content"]  # the failure was explained to the judge
    assert EscalationPolicy().decide(v) == Action.HARD_STOP
    assert v.verification["confirmed"] == 1 and v.verification["dropped"][0]["why"] == "quote not in the record"


def test_reviewer_veto_blocks_the_stop():
    client = FakeClient([verdict_json("I need you to install RemoteDesk")] * 2)
    v = CaseJudge(client, reviewer=FakeReviewer(False)).judge(SNAPSHOT)
    assert v.reasons == [] and v.verification["attempts"] == 2
    assert EscalationPolicy().decide(v) == Action.NUDGE  # real quote, wrong meaning: no stop


def test_reviewer_outage_falls_back_to_deterministic_layer():
    class Down:
        def review(self, *_):
            raise TimeoutError

    v = CaseJudge(FakeClient([verdict_json("I need you to install RemoteDesk")]), reviewer=Down()).judge(SNAPSHOT)
    assert v.reasons and v.verification["reviewer"].startswith("unavailable")


def test_no_review_without_a_stop():
    reply = {**verdict_json("I need you to install RemoteDesk"), "recommended_action": "nudge", "confidence": 0.5}
    v = CaseJudge(FakeClient([reply]), reviewer=FakeReviewer(False)).judge(SNAPSHOT)
    assert v.verification["reviewed"] == 0 and v.verification["attempts"] == 1


def test_invented_numbers():
    record = ["call 1-888-555-0142 now", "buy $500 in gift cards"]
    assert invented_numbers("call 1-888-555-0142, send $500 at 10:42, 2 cards", record) == []
    assert invented_numbers("call 1-800-123-4567, send $900", record) == ["1-800-123-4567", "$900"]


def test_report_needs_coverage_and_grounding():
    snap = {**SNAPSHOT, "signals": [{"name": "remote_tool_install_request"}]}
    record = [LINE]
    good = {"summary": "A caller from Microsoft got her to install remote access software.", "scammer_claimed_to_be": "Microsoft", "money_lost": "none"}
    assert check_report(good, snap, record)["ok"]
    bad = check_report({"summary": "A caller called.", "scammer_claimed_to_be": "Apple", "money_lost": "$300"}, snap, record)
    assert not bad["ok"] and bad["coverage"] < 0.8 and len(bad["issues"]) == 4
    assert not check_message("Call me at 555-0199", record)["ok"]


def test_recovery_discards_unknown_tools_and_retries_rejected_ones():
    def call(name, args):
        return SimpleNamespace(id=name, function=SimpleNamespace(name=name, arguments=json.dumps(args)))

    turns = [[call("wire_money", {}), call("draft_fraud_report", {"summary": "x"})], [call("draft_fraud_report", {"summary": "y"})], []]

    class Completions:
        def create(self, **_):
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=turns.pop(0)))])

    client = SimpleNamespace(_client=SimpleNamespace(chat=SimpleNamespace(completions=Completions())), config=SimpleNamespace(model="m"))
    executed = []

    def execute(tool, args):
        executed.append(args["summary"])
        return f"{REJECTED}: fix it" if len(executed) == 1 else "ok"

    steps, _ = RecoveryAgent(client).run("case", execute)
    assert executed == ["x", "y"]  # rejected once, then allowed to resubmit
    assert steps[0].tool == "wire_money" and steps[0].result.startswith("Discarded")


def test_numbers_read_off_the_screen_count_as_observed():
    from core.output_checks import observed

    snap = {**SNAPSHOT, "signals": [{"name": "scareware_phone_number", "evidence": "Call PC SafeGuard now: +1 (555) 013-4477"}]}
    assert invented_numbers("They used +1 (555) 013-4477", observed(snap)) == []
    assert invented_numbers("They used +1 (555) 013-4478", observed(snap)) == ["+1 (555) 013-4478"]
