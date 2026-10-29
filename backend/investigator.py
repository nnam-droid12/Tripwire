"""The case file: Muse Wonder turns a stopped scam into a report police can act on.

After the decoy phase, Muse Wonder reads the whole record (what was said, what
happened on screen and on the computer, and the decoy's verified intel) and
writes a case file in the shape of an FBI IC3 / FTC complaint: what happened,
which known scheme it matches, the timeline, and the leads (a courier due at
the house at 3 pm is a lead police can use today).

Verified like everything else Tripwire writes:

* every timeline event and every lead must quote the record word for word;
  anything whose quote isn't found is dropped;
* no number may appear in the narrative that isn't in the record
  (``core.output_checks``): an invented phone number or amount is removed.
"""

from __future__ import annotations

import time
from typing import Any

from analysts.common import SAFETY_RULES
from core.grounding import supported
from core.model_client import ModelClient
from core.output_checks import invented_numbers

PROMPT = f"""{SAFETY_RULES}

You are Tripwire's investigator. A scam against an older person was stopped, and a decoy kept the scammer talking.
Write the case file a family member will file with the FBI (ic3.gov) and the FTC (reportfraud.ftc.gov), and give to
local police. Be factual and specific; never speculate beyond the record.

Name the scheme if it matches a known one (for example: tech-support / "Phantom Hacker" (fake tech support, then fake
bank, then fake government agent), bank impersonation with a one-time-code request, grandparent / family emergency,
government impersonation with a courier pickup of cash or gold, refund or prize scam).

Every timeline event and every lead must include "quote": words copied exactly from one line of <record>.

Reply with one JSON object:
{{"title": "<short headline>",
  "scheme": "<the known scheme it matches, or 'unclassified'>",
  "summary": "<3-5 plain sentences: who called, what they claimed, what they asked for, how it was stopped, money lost (none if none)>",
  "timeline": [{{"time": "HH:MM:SS", "event": "<one sentence>", "quote": "<exact words from the record>"}}],
  "leads": [{{"lead": "<an actionable detail: courier pickup time/place, wallet, account, callback number, claimed badge>",
              "why": "<why it helps investigators>", "quote": "<exact words from the record>"}}],
  "next_steps": ["<2-4 concrete steps for the family: report, bank, police if a pickup is scheduled>"]}}"""


def write_case_file(record: list[str], intel: list[dict], client: ModelClient | None = None) -> dict[str, Any]:
    client = client or ModelClient.wonder(reasoning_effort="low")
    intel_text = "\n".join(f"- {i['kind']}: {i['value']} (caller said: \"{i['quote']}\")" for i in intel) or "(none)"
    messages = [
        {"role": "system", "content": PROMPT},
        {"role": "user", "content": "<record>\n" + "\n".join(record) + "\n</record>\n<verified_intel>\n" + intel_text + "\n</verified_intel>"},
    ]
    started = time.time()
    data = client.chat_json(messages, max_tokens=6000)
    return verify_case_file(data, record, seconds=time.time() - started)


def verify_case_file(data: dict[str, Any], record: list[str], seconds: float = 0.0) -> dict[str, Any]:
    """Drop events and leads whose quote isn't in the record; remove numbers the record doesn't contain."""
    checked = dropped = 0

    def keep(items: Any) -> list[dict]:
        nonlocal checked, dropped
        out = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            checked += 1
            source = supported(str(item.get("quote", "")), record)
            if source is None or invented_numbers(" ".join(str(v) for k, v in item.items() if k != "quote"), record):
                dropped += 1
                continue
            out.append({**{k: str(v)[:400] for k, v in item.items()}, "source": source[:300]})
        return out

    def clean(text: Any) -> str:
        text = str(text or "")[:1500]
        for n in invented_numbers(text, record):
            text = text.replace(n, "[removed: not in record]")
        return text

    return {
        "title": clean(data.get("title")) or "Scam stopped by Tripwire",
        "scheme": clean(data.get("scheme")),
        "summary": clean(data.get("summary")),
        "timeline": keep(data.get("timeline")),
        "leads": keep(data.get("leads")),
        "next_steps": [clean(s) for s in data.get("next_steps", []) if isinstance(s, str)][:5],
        "verification": {"claims_checked": checked, "claims_dropped": dropped, "seconds": round(seconds, 1), "model": "Muse Wonder"},
    }
