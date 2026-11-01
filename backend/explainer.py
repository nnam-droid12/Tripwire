"""The explainer card: "this is what the scam looked like", made with Muse Image.

After a stop, the family gets a picture they can understand at a glance and
show to their parent: the real (already redacted) scam screen, edited by Muse
Image into a large-print card. The scammer's number is circled, a banner says
what it is, and one plain sentence says what real companies never do.

Muse Image paints, but it doesn't get to decide what the card says:

* the banner and caption come from a fixed set of reviewed sentences, chosen by
  what SAM 3.1 found on the screen and which scam signals fired;
* before any edit, Muse Spark (vision) reads the original screen and must
  confirm it really shows that kind of scam (a card about a fake warning is never
  made from a photo gallery);
* the finished card is read back and checked: the banner and caption must say
  exactly what was asked, every phone number on it must be one that was really
  on the scam screen (an edit can never change the scammer's number), and no
  other text may have been added;
* a card that fails is retried once with the problem named; if it fails again
  it is discarded, and the family sees the plain outlined screenshot instead.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
from dataclasses import dataclass
from typing import Any

import requests
from PIL import Image

from core.grounding import normalize, supported
from core.model_client import ModelClient

EDIT_URL = "https://api.meta.ai/v1/images/edits"
MAX_ATTEMPTS = 2


@dataclass(frozen=True)
class Template:
    kind: str
    banner: str
    caption: str
    mark: str  # what to circle


SHOWS = {  # what the original screen must show for each card
    "fake_warning": "a warning or alert that tells the user to call a phone number",
    "gift_cards": "a gift card purchase, order or gift card codes",
    "crypto": "a cryptocurrency or Bitcoin payment, wallet address or Bitcoin ATM",
    "wire": "a money transfer or wire form",
    "remote": "a remote-access or screen-sharing app window (an ID, a code or a connection request)",
}


def _company(brands: set[str]) -> str:
    for b in ("microsoft", "apple", "amazon", "norton", "mcafee", "geek squad"):
        if b in brands:
            return b.title() if b != "geek squad" else "Geek Squad"
    return "Real companies"


def choose(labels: set[str], signals: set[str], brands: set[str]) -> Template | None:
    """The card's wording, picked from reviewed sentences by what was on the screen."""
    who = _company(brands)
    never = "never puts" if who != "Real companies" else "never put"
    if "Scammer's phone number" in labels or "Fake warning" in labels or signals & {"fake_virus_alert", "scareware_phone_number"}:
        return Template("fake_warning", "THIS WARNING IS FAKE.", f"{who} {never} a phone number in a warning. Don't call it.",
                        "the phone number")
    if "Gift card order" in labels or "gift_card_request" in signals:
        return Template("gift_cards", "THIS IS A SCAM PAYMENT.", "No real company or government agency is ever paid in gift cards.",
                        "the order total")
    if "crypto_request" in signals or "crypto_address_copied" in signals:
        return Template("crypto", "THIS IS A SCAM PAYMENT.", "No real bank or agency asks you to pay with Bitcoin.", "the payment amount")
    if "wire_transfer_request" in signals:
        return Template("wire", "STOP: THIS TRANSFER IS A SCAM.", "Your bank will never ask you to move money to keep it safe.",
                        "the transfer amount")
    if "Remote-control window" in labels or signals & {"remote_session_active", "remote_tool_launched", "remote_control_input"}:
        return Template("remote", "A STRANGER WAS CONTROLLING THIS COMPUTER.",
                        "Never install an app or read out a code because a caller asked you to.", "the connection window")
    return None


def _prompt(t: Template, feedback: str = "") -> str:
    return (
        "Edit this screenshot of a scam into a clear, large-print explainer card for an older person's family. "
        "Keep the screenshot recognisable and do not change any of its text or numbers. "
        f"Draw a thick red circle around {t.mark}. "
        f"Add a bold banner at the top that reads exactly: {t.banner} "
        f"Add a caption at the bottom that reads exactly: {t.caption}"
        + (f" Important: the previous attempt was rejected because {feedback}. Fix that." if feedback else "")
    )


def _edit(png: bytes, prompt: str) -> bytes:
    image = Image.open(io.BytesIO(png)).convert("RGB")
    image.thumbnail((1280, 1280))
    buf = io.BytesIO()
    image.save(buf, format="WEBP", quality=85)
    resp = requests.post(EDIT_URL, timeout=180, headers={"Authorization": f"Bearer {os.environ['META_API_KEY']}"}, json={
        "model": "muse-image-1.0", "prompt": prompt, "n": 1,
        "images": [{"image_url": "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()}],
    })
    resp.raise_for_status()
    item = resp.json()["data"][0]
    raw = base64.b64decode(item["b64_json"]) if item.get("b64_json") else requests.get(item["url"], timeout=60).content
    out = io.BytesIO()
    card = Image.open(io.BytesIO(raw)).convert("RGB")
    card.thumbnail((1600, 1600))
    card.save(out, format="PNG", optimize=True)
    return out.getvalue()


READ_ORIGINAL = """Read this screenshot. Reply with one JSON object:
{{"shows": true|false (does it show {what}?),
 "lines": ["<every line of text visible, exactly as written>"],
 "phone_numbers": ["<every phone number visible, exactly as written>"]}}"""

READ_BACK = """Read this image. Reply with one JSON object:
{"banner": "<the large text at the top, exactly>", "caption": "<the text at the bottom, exactly>",
 "lines": ["<every other line of text visible anywhere in the image, exactly as written>"],
 "phone_numbers": ["<every phone number visible anywhere in the image, exactly as written>"]}"""


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _read(png: bytes, prompt: str, reader: ModelClient) -> dict | None:
    raw = reader.describe_image(png, prompt, max_tokens=4096)
    try:
        return json.loads(re.search(r"\{.*\}", raw, re.S).group(0))
    except (AttributeError, ValueError):
        return None


def check(card: bytes, t: Template, allowed_numbers: set[str], original_lines: list[str], reader: ModelClient) -> list[str]:
    """Problems with the card (empty if it is correct)."""
    data = _read(card, READ_BACK, reader)
    if data is None:
        return ["the card could not be read back"]
    problems = []
    allowed_text = original_lines + [t.banner, t.caption]
    for line in data.get("lines", []) if isinstance(data.get("lines"), list) else []:
        line = str(line)
        if len(normalize(line).split()) >= 3 and supported(line, allowed_text) is None:
            problems.append(f'it added text that was not asked for ("{line[:80]}"); add only the banner and the caption')
    if normalize(str(data.get("banner", ""))) != normalize(t.banner):
        problems.append(f'the banner must read exactly "{t.banner}"')
    if normalize(str(data.get("caption", ""))) != normalize(t.caption):
        problems.append(f'the caption must read exactly "{t.caption}"')
    for n in data.get("phone_numbers", []) if isinstance(data.get("phone_numbers"), list) else []:
        d = _digits(str(n))
        if len(d) >= 7 and not any(d[-10:] == a[-10:] for a in allowed_numbers):
            problems.append(f"the phone number {n} is not the one on the original screen")
    return problems


def make_card(png: bytes, t: Template, allowed_numbers: set[str], reader: ModelClient | None = None) -> dict[str, Any] | None:
    """Edit, read back, verify; retry once with the problems named. None if no card passes."""
    reader = reader or ModelClient.for_provider("meta")
    original = _read(png, READ_ORIGINAL.format(what=SHOWS[t.kind]), reader)
    if not original or original.get("shows") is not True:
        return None  # the screen doesn't show this kind of scam: no card, rather than a misleading one
    lines = [str(x) for x in original.get("lines", []) if isinstance(x, str)]
    allowed_numbers = allowed_numbers | {_digits(str(n)) for n in original.get("phone_numbers", [])}
    feedback, log = "", []
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            card = _edit(png, _prompt(t, feedback))
            problems = check(card, t, allowed_numbers, lines, reader)
        except Exception as exc:  # the card is a bonus; the outlined screenshot still stands
            log.append({"attempt": attempt, "problems": [type(exc).__name__]})
            continue
        log.append({"attempt": attempt, "problems": problems})
        if not problems:
            return {"png": card, "kind": t.kind, "banner": t.banner, "caption": t.caption, "attempts": attempt, "checks": log}
        feedback = "; ".join(problems)
    return None


def phone_numbers(texts: list[str]) -> set[str]:
    """Every phone number seen on screen or in system evidence: the only numbers a card may show."""
    found = set()
    for text in texts:
        for m in re.finditer(r"\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}", text):
            found.add(_digits(m.group(0)))
    return found
