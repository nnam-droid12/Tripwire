"""Synthesize a scenario's call script into a two-voice WAV with Windows TTS.

Usage::

    python -m scripts.make_call_audio eval/scenarios/scam_pc_safeguard.json

The caller is voiced by "Microsoft David", the protected person by
"Microsoft Zira" (both ship with Windows), so diarization has two distinct
voices to separate. Writes ``eval/scenarios/audio/<name>.wav`` (24 kHz mono
PCM16, the ASR's input format) and ``<name>.offsets.json`` with each line's
start time in seconds, so scenario events can be synchronised to call lines.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import wave
from pathlib import Path

from core.config import REPO_ROOT

AUDIO_DIR = REPO_ROOT / "eval" / "scenarios" / "audio"
VOICES = {"caller": "Microsoft David Desktop", "senior": "Microsoft Zira Desktop"}
GAP_S = 0.7
RATE = 24_000

_PS = r"""
Add-Type -AssemblyName System.Speech
$lines = Get-Content -Raw -Encoding UTF8 $args[0] | ConvertFrom-Json
$fmt = New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(24000, [System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen, [System.Speech.AudioFormat.AudioChannel]::Mono)
foreach ($l in $lines) {
  $s = New-Object System.Speech.Synthesis.SpeechSynthesizer
  $s.SelectVoice($l.voice)
  $s.SetOutputToWaveFile($l.out, $fmt)
  $s.Speak($l.text)
  $s.Dispose()
}
"""


def synthesize(scenario_path: Path) -> Path:
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
    AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        jobs = [
            {"voice": VOICES[line["speaker"]], "text": line["text"], "out": str(tmpdir / f"{i:03}.wav")}
            for i, line in enumerate(scenario["call"])
        ]
        (tmpdir / "jobs.json").write_text(json.dumps(jobs), encoding="utf-8")
        (tmpdir / "tts.ps1").write_text(_PS, encoding="utf-8")
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(tmpdir / "tts.ps1"), str(tmpdir / "jobs.json")],
            check=True,
            timeout=600,
        )
        out = AUDIO_DIR / f"{scenario['name']}.wav"
        offsets: list[float] = []
        gap_frames = int(GAP_S * RATE)
        written = 0
        with wave.open(str(out), "wb") as dst:
            dst.setnchannels(1)
            dst.setsampwidth(2)
            dst.setframerate(RATE)
            for job in jobs:
                offsets.append(round(written / RATE, 2))
                with wave.open(job["out"]) as src:
                    n = src.getnframes()
                    dst.writeframes(src.readframes(n))
                dst.writeframes(b"\x00\x00" * gap_frames)
                written += n + gap_frames
    (AUDIO_DIR / f"{scenario['name']}.offsets.json").write_text(json.dumps(offsets), encoding="utf-8")
    return out


def main(argv: list[str]) -> None:
    for arg in argv:
        out = synthesize(Path(arg))
        print(f"wrote {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main(sys.argv[1:])
