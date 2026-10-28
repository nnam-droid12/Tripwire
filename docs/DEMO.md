# Recording the 3-minute demo

> **Recommended video:** record the web arena, [/arena](https://tripwire-4j2p5vomta-ue.a.run.app/arena), in a browser window. You play the scammer live; Margaret answers; Tripwire stops you; the recovery agent acts. The shot list below for the desktop demo still applies for the on-device part (0:20-0:35 and 2:15-3:00).

## Before you record

1. **Screen recorder.** Use OBS Studio (free) with a *Display Capture* source, so the full-screen warning is recorded. Windows' Game Bar (Win+Alt+R) records only one app window and will miss it. Record system audio too: the call and Tripwire's voice both come out of the speakers.
2. **Warm up once.** Run `python -m scripts.demo` once before recording. This makes the voice cache, the call audio and the Google credentials ready, so nothing lags on camera.
3. **Phone.** Open your family dashboard link on your phone (the `https://tripwire-…run.app/?k=…` link). Lay the phone next to the laptop, or plan to cut to a phone screen recording.
4. **Close other windows**, turn off notifications (Focus Assist), and set the volume to about 60%.

## Shot list (about 3:00)

| Time | On screen | You say (suggested) |
|---|---|---|
| 0:00–0:20 | Title card, then your face or slides | "Every year older Americans lose billions to tech-support and refund scams. The scam isn't one moment. It's a 20-minute story: a pop-up, a call, remote access, the bank, gift cards. Tripwire watches that story and stops it while it's happening." |
| 0:20–0:35 | The README diagram, or a slide of the three tiers | "It runs on the senior's laptop. A cheap always-on model, Muse Spark Open on Baseten, narrates the screen and the call. When the story turns, Muse Spark on Meta's API reads the whole session and makes the call." |
| 0:35–1:25 | Run `python -m scripts.demo --report`. The fake "PC SafeGuard" pop-up fills the screen, and the "Microsoft" caller starts talking. | Let the call play. Then: "Fictional brand, real script. Watch the timing." |
| ~0:45 | **Hard stop**: the red screen appears and Tripwire speaks in its natural voice | "Seven seconds into the call. The pop-up's 'Microsoft' and the caller's 'Microsoft' match, and real Microsoft never calls. It stopped before he even asked for remote access. The stand-in AnyDesk has been closed." |
| 1:25–1:45 | Point at the countdown and the PIN box | "The scammer will say 'just close that box'. Tripwire hears that, restarts the countdown and tells her so out loud. Only the family PIN, or a minute of cooldown, dismisses it." |
| 1:45–2:15 | Phone: the dashboard, then tap the new alert | "The family gets the alert: what to do now, the screenshot with the fake warning outlined by SAM 3.1, account numbers blacked out on the laptop before anything left it, and the whole story in plain words. Here's the exact text they'd get. On a Twilio trial it's in demo mode." |
| 2:15–2:40 | README Results table | "We tested it on 12 scenarios: 5 scams and 7 look-alikes, like a grandson helping with banking or a son fixing the printer over AnyDesk. Every scam was stopped, with zero false alarms, a median of 27 seconds. Half were stopped before money was even asked for." |
| 2:40–3:00 | Back to you or the title card | "Muse Spark Open, Muse Spark, Muse Voice Transcribe, SAM 3.1 and Muse Image, all working on one job: making sure the next phone call doesn't take someone's savings." |

## Useful variants

- `python -m scripts.demo --scenario scam_refund_quickassist --report`: a refund scam, stopped when Quick Assist connects.
- `python -m scripts.demo --hold 30`: the warning hides after 30 s. The scam then keeps going, and Tripwire raises the warning again on its own, without texting the family twice.
- Click **"I have hung up. I am safe."** after the 60 s countdown to dismiss the warning on camera.

## Notes

- Only Notepad is ever closed by the demo, never a real remote-access tool.
- The family link in the alert opens on any phone.
- The demo replays a scripted call through the real speech-to-text. For a fully live take, have a friend read `eval/scenarios/scam_pc_safeguard.json` on speakerphone while `python -m scripts.run_tripwire` runs.
