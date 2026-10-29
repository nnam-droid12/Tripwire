"""On-device redaction of frames and text before anything leaves the machine.

Frames: Windows' built-in OCR engine (``Windows.Media.Ocr``; no model
download, nothing uploaded) reads every word and its position. A run of
adjacent number tokens with 8 or more digits in total, such as an account
number ("4417 2280 9931"), a card number or an SSN, is covered with a solid box.
Solid fill, not blur, because blurred digits can sometimes be recovered.

Deliberately left visible, because they are scam evidence rather than the
victim's secrets: money amounts ("$15,000.00"), phone numbers written as
phone numbers ("+1 (555) 013-4477") and dates.

Fail closed: if OCR is unavailable or fails, :func:`redact_for_upload` raises
:class:`RedactionError` and the frame is not uploaded at all.

SAM 3.1 is *not* used for redaction, because it runs in the cloud and the
frame would leave the device unredacted. It is used afterwards, on redacted
frames, to outline the threat for the family alert (``backend/highlight.py``).
"""

from __future__ import annotations

import asyncio
import io
import re
from dataclasses import dataclass

from PIL import Image, ImageDraw

MIN_DIGITS = 8
OCR_SCALE = 2  # upscale before OCR: small UI text is read far more reliably

_NUMERIC_TOKEN = re.compile(r"^[\d\-–•*xX#.:/()+]*\d[\d\-–•*xX#.:/()+]*$")
# US phone shapes (1-3-3-4 and 3-3-4, as written or as speech recognition spells them): a caller's number is evidence, not a secret
_PHONE = re.compile(r"^\+?\d?[\s.-]*\(\d{3}\)[\s.-]*\d{3}[\s.-]+\d{4}$|^\+\d[\d\s().-]{8,}$|^1?[\s.-]?\d{3}[\s.-]\d{3}[\s.-]\d{4}$")
_DATE = re.compile(r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$|^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$")
_MONEY = re.compile(r"^[$£€₦]|\d[,.]\d{2}$")


class RedactionError(RuntimeError):
    """Raised when a frame cannot be safely redacted; the caller must not upload it."""


@dataclass(frozen=True)
class Word:
    text: str
    x: float
    y: float
    w: float
    h: float


# -- OCR ----------------------------------------------------------------------------


def ocr_lines(image: Image.Image) -> list[list[Word]]:
    """Words grouped by line, with boxes in ``image`` pixel coordinates."""
    try:
        return asyncio.run(_ocr(image))
    except RedactionError:
        raise
    except Exception as exc:  # any WinRT failure means we cannot vouch for the frame
        raise RedactionError(f"OCR failed: {exc!r}") from exc


async def _ocr(image: Image.Image) -> list[list[Word]]:
    from winrt.windows.graphics.imaging import BitmapDecoder
    from winrt.windows.media.ocr import OcrEngine
    from winrt.windows.storage.streams import DataWriter, InMemoryRandomAccessStream

    engine = OcrEngine.try_create_from_user_profile_languages()
    if engine is None:
        raise RedactionError("Windows OCR engine is not available")
    big = image.convert("RGB").resize((image.width * OCR_SCALE, image.height * OCR_SCALE))
    buf = io.BytesIO()
    big.save(buf, format="PNG")

    stream = InMemoryRandomAccessStream()
    writer = DataWriter(stream)
    writer.write_bytes(buf.getvalue())
    await writer.store_async()
    writer.detach_stream()
    stream.seek(0)
    bitmap = await (await BitmapDecoder.create_async(stream)).get_software_bitmap_async()
    result = await engine.recognize_async(bitmap)
    s = OCR_SCALE
    return [
        [Word(w.text, w.bounding_rect.x / s, w.bounding_rect.y / s, w.bounding_rect.width / s, w.bounding_rect.height / s) for w in line.words]
        for line in result.lines
    ]


# -- what counts as sensitive ---------------------------------------------------------


def _digits(text: str) -> int:
    return sum(ch.isdigit() for ch in text)


def _evidence_not_secret(text: str) -> bool:
    t = text.strip()
    return bool(_PHONE.match(t) or _DATE.match(t) or _MONEY.search(t))


def sensitive_runs(line: list[Word]) -> list[list[Word]]:
    """Runs of adjacent numeric tokens that together look like an account/card/SSN number."""
    runs, current = [], []
    for word in line + [Word("", 0, 0, 0, 0)]:  # sentinel flushes the last run
        if word.text and _NUMERIC_TOKEN.match(word.text):
            current.append(word)
            continue
        if current:
            text = " ".join(w.text for w in current)
            if _digits(text) >= MIN_DIGITS and not _evidence_not_secret(text):
                runs.append(current)
            current = []
    return runs


# -- public API -----------------------------------------------------------------------


def redact_image(image: Image.Image, pad: int = 3) -> tuple[Image.Image, int]:
    """Return ``(redacted copy, number of regions covered)``."""
    out = image.convert("RGB").copy()
    draw = ImageDraw.Draw(out)
    count = 0
    for line in ocr_lines(image):
        for run in sensitive_runs(line):
            x1 = min(w.x for w in run) - pad
            y1 = min(w.y for w in run) - pad
            x2 = max(w.x + w.w for w in run) + pad
            y2 = max(w.y + w.h for w in run) + pad
            draw.rectangle((x1, y1, x2, y2), fill=(30, 30, 30))
            count += 1
    return out, count


def redact_for_upload(png_bytes: bytes) -> bytes:
    """PNG in, redacted PNG out. Raises :class:`RedactionError` rather than return an unsafe frame."""
    image = Image.open(io.BytesIO(png_bytes))
    redacted, _ = redact_image(image)
    buf = io.BytesIO()
    redacted.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


_TEXT_NUMBER = re.compile(r"(?<![\w$£€₦])(?:\d[\s\-–]?){%d,}\d(?![\w.,]\d)" % (MIN_DIGITS - 1))


def redact_text(text: str) -> str:
    """Mask long digit runs (card/account numbers, access codes) in transcripts and messages.

    Phone numbers written with phone punctuation and money amounts are kept.
    """

    def mask(m: re.Match[str]) -> str:
        value = m.group(0)
        if _evidence_not_secret(value):
            return value
        digits = re.sub(r"\D", "", value)
        return "*" * (len(digits) - 3) + digits[-3:]  # plain ASCII: SMS-safe

    return _TEXT_NUMBER.sub(mask, text)
