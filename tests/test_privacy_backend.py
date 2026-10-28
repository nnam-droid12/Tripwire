"""Stage F tests: what gets redacted, and the backend's auth, incident flow and dry-run SMS."""

from __future__ import annotations

import base64
import importlib
import io
import json
import time

import pytest
from PIL import Image

from agent.redact import Word, redact_text, sensitive_runs


def _line(*texts: str) -> list[Word]:
    return [Word(t, i * 50, 0, 40, 10) for i, t in enumerate(texts)]


def test_account_card_and_ssn_runs_are_sensitive() -> None:
    assert [" ".join(w.text for w in r) for r in sensitive_runs(_line("Checking", "—", "Account", "4417", "2280", "9931", "$4,310.55"))] == ["4417 2280 9931"]
    assert sensitive_runs(_line("SSN", "123-45-6789"))
    assert sensitive_runs(_line("Card", "4111", "1111", "1111", "1111"))


def test_evidence_is_not_redacted() -> None:
    for line in [("Call", "+1", "(555)", "013-4477"), ("Total:", "$15,000.00"), ("Date", "2026-10-27"), ("Ref", "#4417")]:
        assert sensitive_runs(_line(*line)) == [], line


def test_redact_text_masks_long_numbers_only() -> None:
    out = redact_text("card 4111 1111 1111 1111, code 482 113 907, call +1 (555) 013-4477, refund $15,000.00")
    assert "4111" not in out and "*111" in out
    assert "482 113" not in out and out.count("907") == 1
    assert "(555) 013-4477" in out and "$15,000.00" in out


@pytest.fixture()
def backend(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPWIRE_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("TRIPWIRE_AGENT_TOKEN", "agent-secret")
    monkeypatch.setenv("TRIPWIRE_DASHBOARD_KEY", "family-key")
    # Empty (not deleted): reloading core.config re-reads .env, which only fills *unset* variables.
    # Otherwise the test would send a real text through Twilio.
    for var in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER", "FAMILY_PHONE_NUMBER"):
        monkeypatch.setenv(var, "")
    import core.config

    # Point RUNTIME_DIR at tmp *before* backend.main is first imported, so the test
    # can never write its placeholder keys into the real runtime/backend/keys.json.
    importlib.reload(core.config)
    monkeypatch.setenv("TRIPWIRE_PUBLIC_DASHBOARD", "0")
    import backend.sms, backend.storage, backend.incidents, backend.main
    importlib.reload(backend.sms)
    importlib.reload(backend.storage)
    incidents = importlib.reload(backend.incidents)
    monkeypatch.setattr(incidents, "highlight", lambda png, prompts=None: (png, []))
    monkeypatch.setattr(incidents, "narrate", lambda incident: {"title": "Test", "steps": [], "next": []})
    monkeypatch.setattr(incidents, "redact_image", lambda img: (img.convert("RGB"), 0))  # OCR covered separately
    main = importlib.reload(backend.main)
    from fastapi.testclient import TestClient
    return main, TestClient(main.app)


def test_agent_endpoints_require_token(backend) -> None:
    _, client = backend
    assert client.post("/api/agent/status", json={"state": "watching"}).status_code == 401
    assert client.post("/api/agent/status", json={"state": "watching"}, headers={"X-Tripwire-Token": "agent-secret"}).status_code == 200
    assert client.get("/api/status?k=wrong").status_code == 403
    assert client.get("/api/status?k=family-key").json()["state"] == "watching"


def test_incident_flow_sends_dry_run_sms_with_private_link(backend) -> None:
    main, client = backend
    buf = io.BytesIO()
    Image.new("RGB", (64, 36), "red").save(buf, format="PNG")
    body = {
        "verdict": {"is_scam": True, "family_message": "Call her now. Card 4111 1111 1111 1111 was mentioned.", "reasons": []},
        "snapshot": {"stage": 5, "stage_name": "EXTRACTION", "timeline": [{"ts": 1.0, "source": "call", "text": "my code is 482113907", "risk": "high"}], "signals": []},
        "frames": [base64.b64encode(buf.getvalue()).decode()],
        "protected_name": "Margaret",
    }
    reply = client.post("/api/agent/incidents", json=body, headers={"X-Tripwire-Token": "agent-secret"}).json()
    incident_id, token = reply["id"], reply["link"].split("k=")[1]
    assert client.get(f"/api/incidents/{incident_id}?k=nope").status_code == 403
    for _ in range(50):  # the family text is sent on a background thread
        data = client.get(f"/api/incidents/{incident_id}?k={token}").json()
        if data["sms"]:
            break
        time.sleep(0.1)
    assert "token" not in data
    assert "4111 1111" not in data["verdict"]["family_message"] and "482113907" not in data["timeline"][0]["text"]
    assert data["sms"]["sent"] is False and "dry run" in data["sms"]["detail"]
    assert "TRIPWIRE ALERT for Margaret" in data["sms"]["body"] and token not in data["sms"]["body"]
    assert client.get(f"/api/incidents/{incident_id}/image/frame_0.png?k={token}").status_code == 200
    assert client.get(f"/api/incidents/{incident_id}/image/..%2Fincident.json?k={token}").status_code == 404
    outbox = (main.BACKEND_DIR / "sms_outbox.log").read_text(encoding="utf-8")
    assert token in json.loads(outbox.splitlines()[-1])["body"]


def test_arena_scoreboard(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("TRIPWIRE_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("TRIPWIRE_GCS_BUCKET", raising=False)
    import core.config, backend.storage
    importlib.reload(core.config)
    importlib.reload(backend.storage)
    import backend.arena.scores as scores
    scores = importlib.reload(scores)

    scores.record_game("g1", "popup", True, 3, "Control", 2, 14)
    scores.record_game("g2", "call", True, 5, "Extraction", 4, 40)
    scores.record_game("g3", "call", False, 4, "Access", 6, 80)  # got far without a stop
    scores.record_game("g4", "call", False, 1, "Hook", 1, 5)     # a short benign call: not "beating" anything
    scores.record_game("g0", "popup", True, 2, "Contact", 0, 3)  # nobody spoke: not recorded
    assert scores.set_name("g2", "  <b>Kevin</b>; drop table ") and not scores.set_name("g2", "Other")  # first name sticks
    b = scores.board()
    assert (b["games"], b["stopped"], b["escaped"]) == (4, 2, 1)
    assert b["best"][0]["stage_name"] == "Extraction" and b["best"][0]["name"] == "bKevinb drop table"
    assert [g["stage_name"] for g in b["beat_tripwire"]] == ["Access"]
