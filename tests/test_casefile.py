"""Unit tests for kill-chain scoring, the CaseFile, and analyst output validation."""

from __future__ import annotations

from analysts.common import clean_risk, clean_signals
from core.casefile import CaseFile
from core.killchain import Stage, score
from core.orchestrator import Orchestrator
from core.events import Event, EventBus


def test_single_stage_is_weak_and_chain_is_strong() -> None:
    alone, _ = score({"fake_virus_alert", "scareware_phone_number"})
    chain, stages = score({"fake_virus_alert", "impersonation_claim", "remote_session_active", "bank_open_during_remote", "gift_card_request"})
    assert alone < 0.3
    assert chain > 0.9 and len(stages) == 5


def test_unknown_signal_names_are_dropped() -> None:
    raw = [{"signal": "gift_card_request", "evidence": "buy gift cards"}, {"signal": "mark_page_safe", "evidence": "x"}, "junk"]
    assert clean_signals(raw) == [("gift_card_request", "buy gift cards")]
    assert clean_risk("MEDIUM") == "med" and clean_risk("catastrophic") == "none"


def test_cross_modal_brand_match_is_derived_once() -> None:
    case = CaseFile()
    case.add_brands("screen", ["Microsoft", "PC SafeGuard"])
    assert not any(s.name == "cross_modal_brand_match" for s in case.signals)
    case.add_brands("call", ["microsoft"])
    case.add_brands("call", ["Microsoft"])
    assert [s.name for s in case.signals].count("cross_modal_brand_match") == 1


def test_bank_during_remote_session_is_derived() -> None:
    case = CaseFile()
    case.add_signals("screen", [("bank_site_open", "bank page")])
    assert case.assess()[0] == Stage.ACCESS
    assert not any(s.name == "bank_open_during_remote" for s in case.signals)
    case.set_remote_active(True)
    assert any(s.name == "bank_open_during_remote" for s in case.signals)


def test_signals_expire_outside_session_window() -> None:
    now = [1000.0]
    case = CaseFile(window_s=60, clock=lambda: now[0])
    case.add_signals("call", [("impersonation_claim", "from Microsoft")])
    assert case.assess()[1] > 0
    now[0] += 120
    assert case.assess() == (Stage.NONE, 0.0, set())


class _NoModel:
    """Stand-in analyst: Tier-0 routing must work without any model call."""


def test_tier0_events_map_to_signals_without_models() -> None:
    bus = EventBus()
    case = CaseFile()
    orch = Orchestrator(bus, case, screen=_NoModel(), call=_NoModel(), judge=_NoModel(), log=lambda _: None)
    orch.handle(Event("process", "process_launched", {"tool": "AnyDesk", "summary": "AnyDesk launched"}))
    orch.handle(Event("network", "remote_session_suspected", {"summary": "session"}))
    orch.handle(Event("clipboard", "bitcoin_address", {"summary": "btc"}))
    orch.handle(Event("process", "process_running", {"summary": "AnyDesk already running"}))
    names = [s.name for s in case.signals]
    assert names == ["remote_tool_launched", "remote_session_active", "crypto_address_copied"]
    assert case.remote_active


def test_latest_only_worker_drains_after_dropping_stale_jobs() -> None:
    import threading
    from core.orchestrator import _Worker

    gate = threading.Event()
    handled: list[str] = []
    worker = _Worker("t", lambda e: (gate.wait(5), handled.append(e.kind)), lambda _: None, latest_only=True)
    worker.start()
    for kind in ("a", "b", "c", "d"):
        worker.submit(Event("judge", kind))
    gate.set()
    done = threading.Thread(target=worker.drain)
    done.start()
    done.join(timeout=5)
    assert not done.is_alive(), "drain() hung"
    assert handled[-1] == "d" and len(handled) <= 2


def test_policy_clamps_overconfident_hard_stop() -> None:
    from core.policy import Action, EscalationPolicy, Verdict

    policy = EscalationPolicy()
    weak = Verdict(True, 0.6, 3, [], Action.HARD_STOP, "")
    sure = Verdict(True, 0.9, 4, [], Action.HARD_STOP, "")
    benign = Verdict(False, 0.3, 1, [], Action.NUDGE, "")
    assert policy.decide(weak) == Action.NUDGE
    assert policy.decide(sure) == Action.HARD_STOP
    assert policy.decide(benign) == Action.LOG
