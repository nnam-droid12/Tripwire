# Tripwire

Tripwire is an AI agent that runs on an older person's Windows laptop. It watches the screen and listens to a speakerphone call, and it stops a tech-support, refund or impersonation scam **while the scam is happening**.

Built for the Meta Global AI Developer Hackathon (indie track). Everything in this repository was written during the event.

> Status: early build (Stage A: skeleton and model plumbing).

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
python -m scripts.hello_models
```

## Safety

- On-screen text and call audio are treated as data and never as instructions. Text addressed to an AI is itself a scam signal.
- Card, account and SSN numbers are redacted on the device before any frame leaves the machine.
- Test scam pages use a fictional brand ("PC SafeGuard Alert").

## Open-source libraries

`openai`, `python-dotenv` (more will be listed as they are added).
