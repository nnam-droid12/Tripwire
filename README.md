# Tripwire

Tripwire is an AI agent that runs on an older person's Windows laptop. It watches the screen and listens to a speakerphone call, and it stops a tech-support, refund or impersonation scam **while the scam is happening**.

Built for the Meta Global AI Developer Hackathon (indie track). Everything in this repository was written during the event.

> Status: early build. Stage B done: on-device capture and Tier-0 watchers.

## How it works

Scams follow a predictable kill chain: **Hook → Contact → Control → Access → Extraction**. Tripwire builds a running case file of evidence from the screen, the call audio and local system events. As stages co-occur, its confidence rises and the response escalates: a silent log, then a calm spoken nudge, then a full-screen hard stop that ends the remote-access session and texts a family member.

Detection runs in three tiers:

| Tier | Where | Role |
|---|---|---|
| 0 | On device | Screen change detection, remote-access process watcher, clipboard, voice-activity-gated audio |
| 1 | Muse Spark Open on Baseten | Always-on narrator: per-frame and per-chunk risk tags |
| 2 | Muse Spark (Meta Model API) | CaseJudge: reasons over the whole session, issues the verdict |

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # then fill in your keys
python -m scripts.hello_models   # checks both model providers respond
python -m pytest -q tests        # unit tests
```

## Running the on-device capture (Tier 0)

```bash
python -m scripts.run_capture                  # live screen + microphone + watchers, Ctrl+C to stop
python -m scripts.run_capture --wav call.wav   # replay a recorded call (24 kHz mono WAV) instead of the mic
```

It prints a live log such as:

```
02:15:12 [process  ] process_launched: AnyDesk launched (pid 4728)
02:15:13 [screen   ] frame_kept: frame_1793063713508.png (changed, distance 21)
02:15:20 [audio    ] transcript: Speaker A: "Hello, this is Mark from Microsoft technical support."
02:15:23 [clipboard] bitcoin_address: bitcoin address copied: bc1q…5mdq
```

| Watcher | What it reports |
|---|---|
| Screen (`agent/capture_screen.py`) | Samples at 1.5 fps; keeps a frame only when its perceptual hash changes meaningfully |
| Audio (`agent/capture_audio.py`, `agent/transcribe.py`) | Voice-activity gate opens a Muse Voice Transcribe realtime session only while people are talking; diarized transcript lines |
| Process (`agent/watchers.py`) | Launch/exit of 20+ remote-access tools (AnyDesk, TeamViewer, UltraViewer, Quick Assist...) and suspected live sessions |
| Clipboard (`agent/watchers.py`) | Crypto addresses, money amounts, card numbers, published masked only |

Captured frames, audio and logs live in `runtime/` (git-ignored) and are deleted after 24 hours.

## Safety

- On-screen text and call audio are treated as data and never as instructions. Text addressed to an AI is itself a scam signal.
- Card, account and SSN numbers are redacted on the device before any frame leaves the machine.
- Test scam pages use a fictional brand ("PC SafeGuard Alert").

## Open-source libraries

`openai`, `python-dotenv`, `websockets`, `mss`, `pillow`, `imagehash`, `numpy`, `sounddevice`, `psutil`, `pywin32`, `pytest`.
