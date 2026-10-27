"""On-device redaction of frames before they leave the machine.

Every frame passes through :func:`redact_for_upload` before any model call.
Stage F replaces the body with SAM 3.1 / local detection that blurs account,
card and SSN numbers; until then frames pass through unchanged, and only the
fictional scenario frames are sent during development.
"""

from __future__ import annotations


def redact_for_upload(png_bytes: bytes) -> bytes:
    """Return a copy of the frame that is safe to upload."""
    return png_bytes
