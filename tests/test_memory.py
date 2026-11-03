"""Scam Memory: learning only verified, scrubbed, scam-specific steps; recognising a script said in other words."""

from analysts.playbook import PlaybookReviewer, PlaybookWriter, Recall, learn
from core.memory import candidates, merge_key, score, scrub

CALL = [
    "Hello, this is David from the Microsoft security department.",
    "Our servers show your computer is sending out viruses and your IP address has been hacked.",
    "Do not turn off the computer and do not tell anyone, this is a confidential investigation.",
    "Please go to remotedesk dot com and download the support tool so I can fix it.",
    "Now read me the nine digit code on the screen, 482 113 907.",
    "To finish the protection you must buy two hundred dollars of gift cards.",
]


class FakeClient:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.purpose, self.observer = "", None

    def chat_json(self, messages, **_):
        return self.replies.pop(0)


WRITER_REPLY = {
    "title": "Fake Microsoft virus, remote access", "kind": "tech support", "claimed_to_be": "Microsoft", "ask": "gift cards",
    "steps": [
        {"tactic": "impersonation_claim", "line": "this is David from the Microsoft security department"},
        {"tactic": "fake_problem_claim", "line": "your computer is sending out viruses and your IP address has been hacked"},
        {"tactic": "isolation_instruction", "line": "do not turn off the computer and do not tell anyone"},
        {"tactic": "remote_tool_install_request", "line": "download the support tool so I can fix it"},
        {"tactic": "remote_access_code_shared", "line": "read me the nine digit code on the screen, 482 113 907"},
        {"tactic": "gift_card_request", "line": "you must buy two hundred dollars of gift cards"},
        {"tactic": "gift_card_request", "line": "send the cards to my supervisor at once"},  # never said: dropped
        {"tactic": "known_scam_indicator", "line": "Our servers show your computer"},  # system-only tactic: dropped
    ],
}


def _playbook():
    pb, _ = PlaybookWriter(FakeClient(WRITER_REPLY)).write(CALL, protected_names=["Margaret"])
    return {**pb, "id": "pb1", "seen": 3}


def test_writer_keeps_only_lines_the_caller_said_and_scrubs_numbers():
    pb, receipt = PlaybookWriter(FakeClient(WRITER_REPLY)).write(CALL)
    assert receipt["not_said"] == 1 and receipt["bad_tactic"] == 1
    assert len(pb["steps"]) == 6
    assert all(not any(ch.isdigit() for ch in s["line"]) for s in pb["steps"])  # "482 113 907" never stored


def test_scrub_removes_names_emails_and_digits():
    assert scrub("Margaret, email john.doe@mail.com or call 555-013-4477", ["Margaret"]) == "[name], email [email] or call #"


def test_reviewer_drops_generic_steps_and_learning_needs_three():
    review = {"script_is_scam": True, "steps": [{"n": 1, "keep": False}, {"n": 2, "keep": True}, {"n": 3, "keep": True},
                                                {"n": 4, "keep": True}, {"n": 5, "keep": False}, {"n": 6, "keep": True}]}
    pb, receipt = learn(CALL, writer=PlaybookWriter(FakeClient(WRITER_REPLY)), reviewer=PlaybookReviewer(FakeClient(review)))
    assert receipt["outcome"] == "learned" and len(pb["steps"]) == 4
    too_few = {"script_is_scam": True, "steps": [{"n": 2, "keep": True}]}
    pb, receipt = learn(CALL, writer=PlaybookWriter(FakeClient(WRITER_REPLY)), reviewer=PlaybookReviewer(FakeClient(too_few)))
    assert pb is None and "fewer than 3" in receipt["outcome"]
    honest = {"script_is_scam": False, "steps": [{"n": n, "keep": True} for n in range(1, 7)]}
    pb, receipt = learn(CALL, writer=PlaybookWriter(FakeClient(WRITER_REPLY)), reviewer=PlaybookReviewer(FakeClient(honest)))
    assert pb is None and "not a scam script" in receipt["outcome"]


def test_word_score_follows_steps_in_order_and_ignores_unrelated_calls():
    pb = _playbook()
    other_scammer = ["Hi, I'm calling from the Microsoft security department about your computer.",
                     "Your IP address has been hacked and your computer is sending out viruses."]
    s, matched = score(pb, other_scammer)
    assert matched == [0, 1] and s == 2.0
    delivery = ["Hi, this is Sam from Parcel Express, your package is outside.", "Can you confirm your address for the delivery?"]
    assert candidates([pb], delivery) == []


def test_recall_confirms_only_verified_caller_lines():
    pb = _playbook()
    call = [("A", "Good morning, I'm with Windows technical support, we got alerts from your machine."),
            ("B", "Oh dear, what kind of alerts?"),
            ("A", "Hackers have your IP address and your computer is spreading viruses right now."),
            ("A", "Don't turn the computer off and don't tell anyone, it's confidential.")]
    reply = {"same_script": True, "matches": [
        {"step": 2, "line": "Hackers have your IP address and your computer is spreading viruses right now."},
        {"step": 3, "line": "Don't turn the computer off and don't tell anyone, it's confidential."},
        {"step": 4, "line": "Please install the support tool"},  # not said: ignored
        {"step": 1, "line": "Oh dear, what kind of alerts?"}]}  # said by the protected person: ignored
    recall = Recall(lambda: [pb], client=FakeClient(reply))
    found = recall.check(call, signals={"impersonation_claim", "fake_problem_claim"})
    assert len(found) == 1 and [n for n, _ in found[0]["steps"]] == [2, 3]
    assert "learned from 3 stopped scams" in found[0]["evidence"]
    assert recall.check(call) == []  # one match per playbook per call


def test_recall_needs_the_model_to_agree():
    pb = _playbook()
    call = [("A", "This is the Microsoft security department, your IP address has been hacked and your computer is sending out viruses.")]
    recall = Recall(lambda: [pb], client=FakeClient({"same_script": False, "matches": []}))
    assert recall.check(call, signals={"impersonation_claim", "fake_problem_claim"}) == []


def test_same_script_from_another_scammer_merges():
    pb = _playbook()
    variant = {"steps": [{"tactic": "impersonation_claim", "line": "this is Kevin from the Microsoft security department"},
                         {"tactic": "fake_problem_claim", "line": "your IP address has been hacked and your computer is sending out viruses"},
                         {"tactic": "gift_card_request", "line": "you must buy two hundred dollars of gift cards"}]}
    assert merge_key(variant, [pb]) is pb
    unrelated = {"steps": [{"tactic": "prize_or_reward_claim", "line": "you have won the national sweepstakes grand prize today"},
                           {"tactic": "advance_fee_request", "line": "pay the processing fee to release your winnings"}]}
    assert merge_key(unrelated, [pb]) is None
