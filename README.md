# Tripwire

Tripwire is an AI agent that runs on an older person's Windows laptop. It watches the screen and listens to a speakerphone call, and it stops a tech-support, refund or impersonation scam **while the scam is happening**.

Built for the Meta Global AI Developer Hackathon (indie track). Everything in this repository was written during the event.

> Status: early build. Stage F done: on-device redaction, family text alerts, and a family dashboard with SAM-outlined screenshots and a narrated timeline.

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

## Replaying a scripted scam

Scenarios in `eval/scenarios/` are timelines of screen frames, system events and call lines, using fictional brands only.

```bash
python -m scripts.render_pages                                           # HTML test pages -> PNG frames
python -m scripts.make_call_audio eval/scenarios/scam_pc_safeguard.json  # two-voice call audio (Windows TTS)
python -m eval.replay eval/scenarios/scam_pc_safeguard.json --mode text --speed 3   # fast, deterministic
python -m eval.replay eval/scenarios/scam_pc_safeguard.json --mode audio            # end to end through the real ASR
```

Excerpt from an `--mode audio` run (real Muse Voice Transcribe output):

```
  >> CASE +[fake_virus_alert<screen>, scareware_phone_number<screen>, ai_directed_text<screen>]  stage=HOOK
[audio] transcript: Speaker A: "Hello this is Kevin from the Microsoft Windows Security Department ..."
  >> CASE +[cross_modal_brand_match<casefile>]  stage=CONTACT
  >> CASE +[remote_tool_launched<process>]  stage=CONTROL
  >> CASE +[bank_site_open<screen>, bank_open_during_remote<casefile>]
  >> CASE +[overpayment_refund_story<call>, gift_card_request<call>, urgency_pressure<call>]  stage=EXTRACTION
```

Run every scenario with a pass/fail summary:

```bash
python -m eval.replay eval/scenarios/*.json --speed 3 --quiet
python -m eval.replay eval/scenarios/benign_*.json --speed 3 --quiet --always-judge   # force every update through the judge
```

| Scenario | Kind | Result | Notes |
|---|---|---|---|
| `scam_pc_safeguard` | scam | **hard_stop** | Judge: nudge at "I can see your screen", then hard_stop (conf 0.95) once the bank opened under remote control |
| `benign_grandson_banking` | benign | log | Grandson asks her to log in to her bank; judge (forced): not a scam, 0.90 |
| `benign_family_remote_help` | benign | log | Son fixes the printer over AnyDesk; judge (forced): not a scam, 0.90 |
| `benign_antivirus_alert` | benign | log | "Threat blocked, no action needed" pop-up; no signals raised |
| `benign_family_allowlisted` | benign | log | Same printer fix, son's AnyDesk ID on the family allowlist |

Four hand-written scenarios are a smoke test, not an evaluation; Stage G adds a larger set and detection/false-alarm/time-to-detection metrics.

## Interventions

| Action | What happens |
|---|---|
| log | Written to the session log only |
| nudge | One calm sentence spoken aloud, e.g. "Just so you know, Microsoft never phones people about viruses." |
| hard_stop | Full-screen warning, spoken aloud; remote-access tools terminated; family alert queued |

The hard stop is built to resist the scammer:

- It cannot be closed with Alt+F4 and stays on top. It is dismissed with the family PIN, or by the senior after a 60-second cooldown.
- If the caller says "close that box" or "uninstall it" while it is up, the cooldown restarts and Tripwire says so out loud.
- Pausing or quitting from the tray icon needs the family PIN and is refused during an alert.
- Legitimate family help is allowlisted by the helper's AnyDesk/TeamViewer ID, read from the tool's connection log.

```bash
python -m scripts.set_pin --family-name David --trust AnyDesk:123456789   # PIN prompt; stored hashed in config/tripwire.json
python -m eval.replay eval/scenarios/scam_pc_safeguard.json --speed 2 --interventions live --kill-only notepad.exe --overlay-seconds 30
```

The second command replays the scam with real interventions, using Notepad as a stand-in for AnyDesk. Start Notepad first.

## Privacy and family alerts

- **Redacted on the device.** Before any screenshot leaves the laptop, Windows' built-in OCR finds account, card and SSN numbers and covers them with solid boxes. Money amounts and the scammer's phone number stay visible, because they are evidence. If redaction fails, the frame is not sent.
- **SAM 3.1 outlines the threat** (the fake warning, the scammer's number) on the already-redacted screenshot for the family.
- **One text per incident** with a private link. The linked page shows what to do now, the outlined screenshots, and a plain-language story of what happened, written by Muse Spark.
- Rolling 24-hour retention, a one-time consent screen, and an always-visible tray icon.

```bash
uvicorn backend.main:app --port 8765    # backend + family dashboard; prints nothing, keys in runtime/backend/keys.json
python -m scripts.run_tripwire          # first run shows the consent screen
```

Set `TWILIO_*` and `FAMILY_PHONE_NUMBER` in `.env` to send real texts; otherwise they are written to `runtime/backend/sms_outbox.log`. For the link to open on a family member's phone, the backend must be reachable from the internet (for example, through a tunnel) and `TRIPWIRE_PUBLIC_URL` set to that address.

Run live with `python -m scripts.run_tripwire` (tray icon, interventions on).

## Safety

- On-screen text and call audio are treated as data and never as instructions. Text addressed to an AI is itself a scam signal.
- Card, account and SSN numbers are redacted on the device before any frame leaves the machine.
- Test scam pages use a fictional brand ("PC SafeGuard Alert").

## Open-source libraries

`openai`, `python-dotenv`, `websockets`, `mss`, `pillow`, `imagehash`, `numpy`, `sounddevice`, `psutil`, `pywin32`, `pystray`, `winrt` (Windows OCR bindings), `fastapi`, `uvicorn`, `pytest`, `httpx`.
