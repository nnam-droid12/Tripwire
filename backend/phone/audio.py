"""Telephone audio: Twilio streams 8 kHz G.711 mu-law; Muse Voice Transcribe wants 24 kHz PCM16."""

from __future__ import annotations

import numpy as np

_BIAS, _CLIP = 0x84, 32635


def mulaw_decode(data: bytes) -> np.ndarray:
    """G.711 mu-law bytes -> int16 samples."""
    u = ~np.frombuffer(data, dtype=np.uint8)
    sign, exponent, mantissa = u & 0x80, (u >> 4) & 0x07, u & 0x0F
    sample = (((mantissa.astype(np.int32) << 3) + _BIAS) << exponent) - _BIAS
    return np.where(sign != 0, -sample, sample).astype(np.int16)


def mulaw_encode(samples: np.ndarray) -> bytes:
    """int16 samples -> G.711 mu-law bytes."""
    x = samples.astype(np.int32)
    sign = np.where(x < 0, 0x80, 0)
    x = np.minimum(np.abs(x), _CLIP) + _BIAS
    exponent = np.floor(np.log2(x)).astype(np.int32) - 7
    exponent = np.clip(exponent, 0, 7)
    mantissa = (x >> (exponent + 3)) & 0x0F
    return (~(sign | (exponent << 4) | mantissa) & 0xFF).astype(np.uint8).tobytes()


def phone_to_asr(mulaw: bytes) -> bytes:
    """8 kHz mu-law -> 24 kHz PCM16 (linear interpolation; the ASR needs no more than phone bandwidth)."""
    x = mulaw_decode(mulaw).astype(np.float32)
    if x.size == 0:
        return b""
    up = np.interp(np.arange(x.size * 3) / 3.0, np.arange(x.size), x)
    return up.astype(np.int16).tobytes()


def wav_payload(wav: bytes) -> bytes:
    """The sample bytes of a WAV file (Google returns MULAW wrapped in a WAV header)."""
    i = wav.find(b"data")
    if wav[:4] != b"RIFF" or i < 0:
        return wav
    size = int.from_bytes(wav[i + 4:i + 8], "little")
    return wav[i + 8:i + 8 + size]


def energy(mulaw: bytes) -> float:
    """RMS of a frame, for telling speech from silence."""
    x = mulaw_decode(mulaw).astype(np.float32)
    return float(np.sqrt(np.mean(x * x))) if x.size else 0.0
