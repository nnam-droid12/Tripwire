# Tripwire

Tripwire is an AI agent that stops tech-support, refund and impersonation scams against older people **while the scam is happening**. It works in two places:

- **On any phone, with no app**: iPhone, Android or landline. Tripwire works on the phone line itself: it hears both sides of the call, warns the person privately, and cuts the scammer off. See [On any phone](#on-any-phone-the-tripwire-phone-line).
- **On a Windows computer**, where it also watches the screen: fake virus pop-ups, remote-access tools, banking opened under a stranger's control.

Built for the Meta Global AI Developer Hackathon (indie track). Everything in this repository was written during the event.

**At a glance:**
- **Third-party phone calls** (scored once, on calls we didn't write): **100%** of 160 scam calls stopped with **0%** false alarms on 160 legitimate calls, and **95%** of 20 real recorded scam calls.
- **Scripted whole sessions:** every scam stopped, a median of **21.8 s** after the first sign, **88%** of them before money was asked for.
- **No action without evidence:** no stop has ever been taken on a claim that failed verification.

See [Results](#results).

### Meta tools, and what each one does here

| Tool | Job in Tripwire |
|---|---|
| **Muse Spark Open** (Baseten) | Always-on Tier-1 narrator: reads every changed screenshot and every call line, and tags kill-chain signals |
| **Muse Spark** (`muse-spark-1.3`, Meta Model API) | The CaseJudge: reasons over the whole session and is the only component that can authorize a hard stop. Also plays Margaret in the arena, runs the tool-calling recovery agent, and writes the family's plain-language incident story |
| **Muse Voice Transcribe** | Live, speaker-separated transcription of the speakerphone call (realtime WebSocket, diarization mode), and push-to-talk transcription of the scammer in the arena |
| **SAM 3.1** | Outlines the threat (the fake warning, the scammer's number) on already-redacted screenshots for the family |
| **Muse Image** | Generated the synthetic scam and look-alike screens used to evaluate the screen analyst |

## On any phone: the Tripwire phone line

Phone apps can't hear calls: iPhone and Android both block it. So the phone version of Tripwire works on the phone line instead (Twilio Programmable Voice + Media Streams), and protects any phone with nothing installed.

**Protecting a person** (`backend/phone/guard_line.py`). Calls reach Tripwire's number first. In practice, unknown callers are forwarded to it, for example with iPhone's "Silence Unknown Callers" plus carrier no-answer forwarding. Then:

1. **Before it rings:** the caller's number is checked against [Community Shield](#community-shield). The caller hears "This call is protected by Tripwire, and may be monitored to prevent fraud." The protected person picks up and hears a private whisper before the call connects: a warning if the number was reported in other homes' stopped scams, otherwise "Tripwire is listening to protect you."
2. **During the call:** both sides stream to Tripwire (`both_tracks`). Each side is cut into utterances on the telephone audio and transcribed by Muse Voice Transcribe, the caller as speaker A and the protected person as B. The lines run through the same pipeline as the computer: CallAnalyst, kill-chain CaseFile, Sentinel, CaseJudge, verification, policy.
3. **On a hard stop:** Tripwire redirects the protected person's leg of the call (Twilio REST) to a spoken explanation in its own voice, then hangs up, leaving the scammer on a dead line. The family gets the incident page, and Community Shield learns the scammer's number from the caller ID.

There are no spoken nudges on this line: Twilio can't speak into a connected two-way call without breaking the bridge, so on the phone Tripwire only steps in when it is sure.

**Call Margaret** (`backend/phone/margaret_line.py`). The arena game below, over a real phone call: phone Tripwire's number and try to scam Margaret by voice. Margaret answers in her own voice, Tripwire listens, and when it stops you, its warning cuts in over Margaret mid-sentence. She says she's hanging up, and the line goes dead.

**How the line is built:**

| Piece | How |
|---|---|
| Telephone audio | 8 kHz G.711 mu-law in both directions. Decoded and upsampled to 24 kHz PCM for the ASR; voices synthesized directly as 8 kHz mu-law (Chirp 3 HD) |
| Turn-taking | Speech is detected on the phone audio, and each utterance gets its own push-to-talk ASR session. The text arrives about 1 s after the caller stops; a continuous session waited about 10 s for a long silence. |
| Security | Every webhook checks Twilio's `X-Twilio-Signature`. Media streams need a one-time token that only a signed webhook hands out. In the Margaret game, the caller's own number is never stored or added to Community Shield. |
| Cost control | Demo calls share the arena's limit of 4 games at once and 8 minutes each, plus a daily cap on minutes. A protected person's line is never capped. |

Both modes were tested end to end with simulated Twilio streams (synthesized voices in, audio out, Twilio REST stubbed). The live number is the last step: Twilio's 2026 trial accounts can't own a number or use Media Streams, and buying one needs an identity check.

## Try it now: "Can you scam Margaret?"

**[tripwire-4j2p5vomta-ue.a.run.app/arena](https://tripwire-4j2p5vomta-ue.a.run.app/arena)**: no login, works in Chrome or Edge.

You play the scammer. Hold the button and speak, or type. Margaret, 78, answers out loud and does what you tell her on her laptop: she installs a remote-access app, logs in to her bank, opens a gift-card page. The real Tripwire pipeline watches her screen and the call the whole time:

- the kill-chain meter lights up as you move through the scam;
- the CaseJudge explains its reasoning;
- a calm spoken nudge comes first, then the red warning over her laptop, in a natural voice;
- if you say "just close that box", Tripwire notices.

When it stops you, a **recovery agent** takes over. Muse Spark uses tools to end the remote session, freeze her card on the bank's security page, draft an FTC fraud report and alert her family. Your score is how far you got.

Try being her grandson Tom instead: Tripwire should stay quiet.

| Who | Played by |
|---|---|
| The scammer | You (voice via Muse Voice Transcribe, or text) |
| Margaret | Muse Spark, with her own Chirp 3 HD voice and actions on her simulated laptop |
| Tripwire | The real pipeline: Muse Spark Open analysts, the kill-chain CaseFile, the Muse Spark CaseJudge |
| Recovery agent | Muse Spark with tool calling |

Everything in the arena is fictional. The on-device agent below is the real product; the arena runs the same detection pipeline in the cloud so anyone can test it. A desktop demo is also available: `python -m scripts.demo` stages a scam in a window ([docs/DEMO.md](docs/DEMO.md)).

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
| + judge on low reasoning effort (about 3x faster) | 27.0 s | 50% | 0% |
| + independent reviewer before every stop ([Verification](#verification-tripwire-checks-its-own-work-before-it-acts)) | 29.4 s | 50% | 0% |
| + [Tripwire Sentinel](#tripwire-sentinel-a-small-model-of-our-own) as a second opinion | **21.8 s** | **88%** | **0%** |

We stopped tuning the judge at 27.0 s on purpose, because pushing further on scenarios we wrote ourselves would be overfitting. The later gains came from Sentinel, which was developed on third-party data (below), not on these scenarios. With Sentinel, all 24 runs still pass, including the genuine bank fraud-alert call.

**Caveats.** These scenarios were written by us, replayed as text (the speech path is tested separately), with 2 runs each. They are a regression suite and a sanity check, not a field study.

### Calls we did not write (independent test)

Scoring well on your own scripts proves little, so Tripwire is also measured on **340 third-party conversations** (Apache-2.0): [BothBosu/scam-dialogue](https://huggingface.co/datasets/BothBosu/scam-dialogue) (160 scams, 160 legitimate calls, including pushy telemarketing and insurance calls) and [youtube-scam-conversations](https://huggingface.co/datasets/BothBosu/youtube-scam-conversations) (20 real scam calls from scam-baiting channels). These are calls only, with no screen evidence. Each one is replayed turn by turn through the real pipeline.

| | First version | + scam signals | **+ Sentinel (now)** |
|---|---|---|---|
| Scam calls stopped (160) | 61% | 92% | **100%** |
| False alarms on legitimate calls (160) | 0% | 0% | **0%** |
| Point in the call where it stopped (median) | 56% | 45% | **7%** (usually the scammer's opening line) |
| Refund scams / prize scams stopped | 42% / 32% | 92% / 80% | **100% / 100%** |
| **Real scam-baiting calls stopped (20)** | 55% | 55% | **95%** (19 of 20), at 31% of the call |
| Judge claims checked against the record | n/a | 1,624: 0 unsupported | **564: 2 not found, discarded; 349 of 351 stop reasons confirmed by the [independent reviewer](#verification-tripwire-checks-its-own-work-before-it-acts)** |

**How the improvement was made without tuning to the test.** The first version recognised refund and prize scams but only nudged, because it had no signals for prizes, advance fees or requests for Social Security or bank details. Those signals and the matching judge rules were developed on the dataset's **training split only**: 98% stopped, 0% false alarms there. The test split was then scored once.

**Real calls.** The 20 real scam-baiting calls are long and rambling (up to 71 turns). There is no training split for them, so nothing was ever tuned on them. The judge-only system stopped 55%: it recognised the patterns but kept nudging. Sentinel, trained on different data, was the second opinion that broke the tie: 95%. The one miss is a 19-turn tech-support call that ended in a nudge.

**How Sentinel was added without tuning to the test.** Sentinel trained on the training split, so its scores there aren't honest. The integration rule (a `sentinel_flag` signal and one judge instruction) was developed on the 128 training calls Sentinel never saw: 84% → 100% stopped, 0% false alarms. The 12 scripted scenarios came next, then the test split, scored once. Eight test conversations logged temporary API errors (rate limits under 6 parallel runs). All eight were legitimate calls that ended correctly, and all eight reran cleanly with the same result.

### Tripwire Sentinel: a small model of our own

Tripwire Sentinel is **Llama 3.2 1B, fine-tuned with LoRA** on the training split of the scam-dialogue set (2,304 examples, 288 steps), trained on Modal CPU containers (`modal_app/sentinel.py`). Training, choosing the alarm threshold on 128 held-out training calls, and saving the result all run in the cloud. The threshold (0.96) was the lowest that kept held-out false alarms at 1% or less. It was then scored once on the untouched test split:

| | Sentinel alone | Full Tripwire (for comparison) |
|---|---|---|
| Scam dialogues flagged (160) | **100%**, at 7% of the call (median) | 92% stopped, at 45% |
| Real scam-baiting calls flagged (20) | **100%**, at 8% of the call | 55% |
| Legitimate calls flagged (160) | **10.6%**: all 17 are pushy telemarketing calls (17 of 40); 0 delivery, insurance or wrong-number calls | 0% |

Alone, Sentinel would be a poor product: one in ten legitimate calls flagged. Combined, it's the opposite. Sentinel raises a `sentinel_flag` signal that the CaseJudge weighs as an independent second opinion. It can never be quoted as a reason, so a stop still needs words actually said and the independent reviewer's confirmation. The judge filters out Sentinel's false alarms (0 of its 17 telemarketing flags led to a stop), and Sentinel stops the judge from hesitating (real calls 55% → 95%).

Live, Sentinel runs as a deployed Modal service (`SentinelService`, 8 CPUs, ~1.6 s per turn when warm, ~27 s cold start; scores identical to the batch export). The arena and the desktop agent warm a container when a call starts. If Modal is slow or down, Tripwire runs as it would without Sentinel.

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

## Verification: Tripwire checks its own work before it acts

A model that stops a phone call, freezes a card or writes a fraud report must not be able to make things up. Every output that leads to an action passes checks first, placed at the points where an action happens. Checks add latency, so they run only there.

| Checkpoint | Deterministic check | Independent check | If it fails |
|---|---|---|---|
| **Stopping the call** (CaseJudge verdict) | Every reason must quote, word for word, a line of what was actually said or shown (`core/grounding.py`) | A second model, **Muse Spark Open**, which didn't make the decision, confirms each quote really shows what its reason claims, in context (`analysts/reviewer.py`) | The judge is told exactly which quotes weren't found or were rejected, and answers again (once). With no reason left standing, there is no hard stop. |
| **Recovery tools** | Only four tools exist; any other tool name is discarded and logged. Card numbers must match the card on file. | | |
| **Fraud report** | No number (phone, ID, amount) that isn't in the record; the claimed identity must be named in the record; it must cover **≥80%** of the key facts the record establishes (who they claimed to be, remote access, what they asked for, the number they used) (`core/output_checks.py`) | | Not delivered. The tool returns the list of problems to the agent, which fixes the draft and submits again. |
| **Family message and story** | No invented numbers | | Rejected and rewritten; story sentences that fail are removed |
| **Filing** | | **A human:** the report stays a draft until a family member signs it off on the incident page | |

If the reviewer is unreachable, the deterministic layer still applies and the receipt says so. Every incident page shows a **verification receipt**: each reason with the exact words it rests on, the reviewer's note, what was dropped, retries, and the checks on the report and message.

Measured on 80 development conversations (the train split): 104 reasons behind stops were re-checked by the reviewer and 103 were confirmed. Detection was unchanged (98% stopped, 0% false alarms). In a live arena run, the recovery agent wrote a phone number into the fraud report that wasn't in the record. The check rejected it before delivery, and the agent fixed the draft. That test also showed numbers read off the screen must count as observed: they now do.

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

## Who's in control, and family rules before payments

**Who's in control.** When someone drives the computer through AnyDesk, TeamViewer or Quick Assist, their clicks and keystrokes reach Windows as *injected* input, which the operating system marks as such. Physical input never carries that mark. Tripwire watches for it (`agent/control.py`), so "someone else is controlling this computer" is an observed fact, not a model's guess. Only counts are kept, never keystrokes. It is reported only while a remote-access tool is running, so accessibility software is not mistaken for a scammer.

**Family rules.** Before a sensitive action (a wire or transfer, a gift-card purchase, a crypto deposit), plain rules chosen by the family decide:

| Decision | Example |
|---|---|
| Allow | Nothing applies, or the caller is a trusted family member |
| Verify | A payment during a call with someone who isn't family: Tripwire asks out loud, "did you call them, or did they call you?" |
| Hold | Gift cards during such a call, or a large transfer: the payment waits until a family member taps Approve or Deny. No answer within 30 minutes counts as a no |
| Deny | Any payment while someone else controls the computer |

The rules (`core/rules.py`) cannot hallucinate, and they work alongside the CaseJudge: the stricter of the two always wins, and neither can relax the other.

## Community Shield

When Tripwire stops a scam, the scammer's own identifiers join Community Shield (`core/shield.py`, `backend/shield.py`): the callback number on a fake pop-up, the remote-access ID they connected from, the crypto address they wanted paid, and, on the phone line, their caller ID. When any of them shows up again on any protected screen, call or phone line, Tripwire flags it instantly as `known_scam_indicator`. That flag is an exact match against real reports, so the judge can cite it as evidence.

Only the scammer's side is ever learned. The protected person's own words are skipped, remote-access IDs are taken only from the screen or connection data (a victim reads out her own), and the protected person's own numbers are excluded. No names, account numbers or conversation content are shared.

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
