# Tripwire

Tripwire is an AI agent that runs on an older person's Windows laptop. It watches the screen and listens to a speakerphone call, and it stops a tech-support, refund or impersonation scam **while the scam is happening**.

Built for the Meta Global AI Developer Hackathon (indie track). Everything in this repository was written during the event.

> Status: Stage G done: evaluation harness with a synthetic (Muse Image) screen set and 12 replayed scenarios. Results below.

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

## Results

### Scenario replays (whole sessions)

Evaluated 2026-10-27: 12 scenarios x 2 runs (10 scam runs, 14 benign runs), text replay at real-time speed.

| Metric | Tripwire (Tier 1 + CaseJudge) | Tier-1 score alone (ablation) |
|---|---|---|
| Scam detection rate (hard stop) | **100%** | 80% |
| False-alarm rate (hard stop on benign) | **0%** | 0% |
| Median time to detection | **27.0 s** | 36.0 s |
| Scams stopped before money was asked for | **50%** | |
| Benign runs that got a spoken nudge | 0% | |
| Model calls per run (Tier 1 / Tier 2) | 8.8 / 1.1 | |

| Scenario | Kind | Result per run | Time to detection (s) | Before money ask |
|---|---|---|---|---|
| `benign_antivirus_alert` | benign | log, log | -, - | -, - |
| `benign_family_allowlisted` | benign | log, log | -, - | -, - |
| `benign_family_remote_help` | benign | log, log | -, - | -, - |
| `benign_granddaughter_gift_card` | benign | log, log | -, - | -, - |
| `benign_grandson_banking` | benign | log, log | -, - | -, - |
| `benign_real_bank_call` | benign | log, log | -, - | -, - |
| `benign_update_with_son` | benign | log, log | -, - | -, - |
| `scam_bank_safe_account` | scam | hard_stop, hard_stop | 28.0, 28.2 | no, no |
| `scam_browser_lock_quickassist` | scam | hard_stop, hard_stop | 16.9, 20.6 | -, - |
| `scam_government_crypto` | scam | hard_stop, hard_stop | 28.5, 26.9 | no, no |
| `scam_pc_safeguard` | scam | hard_stop, hard_stop | 18.4, 19.3 | yes, yes |
| `scam_refund_quickassist` | scam | hard_stop, hard_stop | 27.1, 33.5 | yes, yes |

**What the numbers say.** Every scam was stopped and no benign session was, including a relative telling her to log in to her bank, a son on AnyDesk, a granddaughter's gift card and a genuine bank fraud call. The CaseJudge matters: the Tier-1 score alone would have missed 2 of 10 scam runs.

**Stopping earlier.** The first version stopped most scams only when the money request arrived. Event logs showed two causes: the judge was asked too late (a fake FTC officer's arrest threat is a single kill-chain stage, so the cheap score stayed low), and it was too patient once asked. Three changes moved the stop earlier without adding false alarms:

| Version | Median time to stop | Stopped before the money request | False alarms |
|---|---|---|---|
| Baseline | 46.5 s | 25% | 0% |
| + escalate on strong early signs, explicit early-stop rules for the judge | 31.1 s | 38% | 0% |
| + judge on low reasoning effort (about 3x faster) | **27.0 s** | **50%** | **0%** |

The two remaining late stops (a fake bank "safe account" call and a fake FTC officer) have the money request less than a second after the threat. We stopped tuning there on purpose, because pushing further on scenarios we wrote ourselves would be overfitting.

**Caveats.** These scenarios were written by us, replayed as text (the speech path is tested separately), with 2 runs each. They are a regression suite and a sanity check, not a field study.

### Screen analyst on single screens

29 screens (14 scam, 15 benign look-alikes); 16 generated with **Muse Image**, 13 hand-written HTML pages for the fraud screens Muse Image's content filter declined to draw (wire forms, Bitcoin ATM instructions, gift-card codes). Flagged = rated medium/high risk.

| Recall | Precision | False-positive rate | Hidden "note to AI" flagged |
|---|---|---|---|
| 100% (14/14) | 100% | 0% (0/15) | 1/1 |

The benign set includes a $50 birthday gift card, a real-looking antivirus "threat blocked" notice, a software update screen, a bank dashboard and a family remote-help window.

Reproduce with `python -m eval.run_eval` and `python -m eval.run_frames`; raw results are in `eval/results/`.

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

Warnings are spoken in a natural female US-English voice (Google Cloud Text-to-Speech, Chirp 3 HD). The urgent phrases are synthesized at start-up, so they play instantly and without internet; if synthesis ever fails, the built-in Windows voice speaks instead.


| Action | What happens |
|---|---|
| log | Written to the session log only |
| nudge | One calm sentence spoken aloud in a natural voice, chosen to match who the caller claims to be, e.g. "Just so you know, Microsoft and Apple never phone people about viruses. It is okay to hang up." |
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

**Texts run in demo mode.** Twilio trial accounts can only send fixed templates to verified US numbers, so Tripwire's own alert cannot be sent on a trial. Without full Twilio settings, the text Tripwire would send is logged and shown on the incident page, labelled "Demo mode: not sent". To send real texts, set `TWILIO_*` and a US `FAMILY_PHONE_NUMBER` on an upgraded Twilio account with US texting registration (toll-free verification or A2P 10DLC). For the link to open on a family member's phone, the backend must be reachable from the internet (for example, through a tunnel) and `TRIPWIRE_PUBLIC_URL` set to that address.

Run live with `python -m scripts.run_tripwire` (tray icon, interventions on).

## Deployment

The backend and the family dashboard (the web frontend: live status page and incident pages) are one FastAPI service, deployed to **Google Cloud Run**:

```bash
bash deploy/deploy.sh   # project nixora-project, region us-east1
```

The script is idempotent. It:

- enables the APIs;
- creates a least-privilege service account;
- creates a private Cloud Storage bucket for incidents, with objects deleted after 30 days;
- loads the secrets from `.env` into Secret Manager (they are never printed or baked into the image);
- builds the container from `Dockerfile` and deploys it.

The service is public so a family member's phone can open the alert link, but every page and API needs a private key: the dashboard key, or an unguessable per-incident token in the texted link. The laptop agent reports to it when `TRIPWIRE_BACKEND_URL` is set in `.env`.

## Safety

- On-screen text and call audio are treated as data and never as instructions. Text addressed to an AI is itself a scam signal.
- Card, account and SSN numbers are redacted on the device before any frame leaves the machine.
- Test scam pages use a fictional brand ("PC SafeGuard Alert").

## Open-source libraries

`openai`, `python-dotenv`, `websockets`, `mss`, `pillow`, `imagehash`, `numpy`, `sounddevice`, `psutil`, `pywin32`, `pystray`, `winrt` (Windows OCR bindings), `fastapi`, `uvicorn`, `google-auth`, `requests`, `google-cloud-storage` (backend), `pytest`, `httpx`.
