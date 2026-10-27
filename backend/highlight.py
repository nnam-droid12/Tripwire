"""Outline the on-screen threat with SAM 3.1, for the family alert.

Runs only on frames that were already redacted on the device. SAM 3.1 is
prompted with short noun phrases ("warning pop-up window", "gift card
order") and returns boxes around matching UI regions, which are drawn onto
the redacted screenshot so a family member sees at a glance *what* was on
screen. Segmentation on UI, not photos.

Wire format (Meta Responses API, ``model: sam-3.1``): one text line per frame,
records like ``0<|box;x1=..;y1=..;x2=..;y2=..;w=..;h=..;c=0.82|><|mask;...|>``.
Only the boxes are used.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
import urllib.request
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageFont

import core.config  # noqa: F401  (loads .env)

SAM_URL = "https://api.meta.ai/v1/responses"
# prompt -> label shown to the family; earlier prompts win when boxes overlap
PROMPTS = {
    "warning pop-up window": "Fake warning",
    "phone number": "Scammer's phone number",
    "gift card order": "Gift card order",
    "remote access window": "Remote-control window",
}
_BOX = re.compile(r"<\|box;x1=(\d+);y1=(\d+);x2=(\d+);y2=(\d+);w=(\d+);h=(\d+)(?:;c=([\d.]+))?\|>")


@dataclass(frozen=True)
class Box:
    label: str
    x1: int
    y1: int
    x2: int
    y2: int
    confidence: float


def parse_boxes(text: str, label: str) -> list[Box]:
    return [Box(label, int(a), int(b), int(c), int(d), float(conf or 1.0)) for a, b, c, d, _w, _h, conf in _BOX.findall(text)]


def segment(png: bytes, prompt: str, timeout: float = 60) -> list[Box]:
    body = {
        "model": "sam-3.1",
        "input": [{"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": prompt},
            {"type": "input_image", "image_url": "data:image/png;base64," + base64.b64encode(png).decode()},
        ]}],
        "metadata": {"include_confidence": "true", "mask_encoding": "one_bit"},
    }
    req = urllib.request.Request(
        SAM_URL, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {os.environ['META_API_KEY']}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    text = "".join(c.get("text", "") for o in data.get("output", []) for c in o.get("content", []) if c.get("type") == "output_text")
    return parse_boxes(text, prompt)


def _iou(a: Box, b: Box) -> float:
    ix = max(0, min(a.x2, b.x2) - max(a.x1, b.x1))
    iy = max(0, min(a.y2, b.y2) - max(a.y1, b.y1))
    inter = ix * iy
    union = (a.x2 - a.x1) * (a.y2 - a.y1) + (b.x2 - b.x1) * (b.y2 - b.y1) - inter
    return inter / union if union else 0.0


def highlight(redacted_png: bytes, prompts: dict[str, str] | None = None, min_confidence: float = 0.5) -> tuple[bytes, list[Box]]:
    """Draw SAM boxes for each prompt onto an already-redacted frame."""
    boxes: list[Box] = []
    image_size = Image.open(io.BytesIO(redacted_png)).size
    for prompt, label in (prompts or PROMPTS).items():
        try:
            found = [b for b in segment(redacted_png, prompt) if b.confidence >= min_confidence]
        except OSError:
            continue  # highlighting is a nicety; the alert goes out regardless
        for b in found:
            frame_area = image_size[0] * image_size[1]
            if (b.x2 - b.x1) * (b.y2 - b.y1) > 0.85 * frame_area:
                continue  # "the whole screen" outlines nothing and mislabels the page
            if all(_iou(b, kept) < 0.6 for kept in boxes):  # same region already outlined
                boxes.append(Box(label, b.x1, b.y1, b.x2, b.y2, b.confidence))
    image = Image.open(io.BytesIO(redacted_png)).convert("RGB")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    for name in ("segoeuib.ttf", "DejaVuSans-Bold.ttf"):  # Windows locally, Debian in the container
        try:
            font = ImageFont.truetype(name, 18)
            break
        except OSError:
            continue
    for b in boxes:
        pad = 4  # outline sits just outside the region so it never covers its text
        x1, y1, x2, y2 = b.x1 - pad, b.y1 - pad, b.x2 + pad, b.y2 + pad
        draw.rectangle((x1, y1, x2, y2), outline=(255, 30, 30), width=3)
        tw = draw.textlength(b.label, font=font)
        ty = y1 - 26 if y1 >= 26 else y2 + 2
        draw.rectangle((x1, ty, x1 + tw + 12, ty + 24), fill=(255, 30, 30))
        draw.text((x1 + 6, ty + 1), b.label, fill=(255, 255, 255), font=font)
    out = io.BytesIO()
    image.save(out, format="PNG", optimize=True)
    return out.getvalue(), boxes
