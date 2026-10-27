# Engineering decisions

One line per non-obvious choice, newest last.

- One `ModelClient` wraps the `openai` SDK for every provider, because Baseten, the Meta Model API and Fireworks are all OpenAI-compatible; tiers differ only by env-configured provider name.
- `chat_json` extracts the outermost `{...}` from the reply instead of trusting raw output, since models often wrap JSON in prose or code fences.
- The Meta model id is read from `META_MODEL` rather than hard-coded, so the Tier-2 model can change without touching code.
- Muse Spark models spend reasoning tokens before answering (509 tokens for a one-line reply), so `ModelClient` defaults to `max_tokens=2048` and reads an optional `<PROVIDER>_REASONING_EFFORT`; Tier 1 uses `low` (~1.5s/call), the Tier-2 judge keeps the model default.
- Tier 2 uses `muse-spark-1.3`, the newest Muse Spark listed by the Meta API's `/models` endpoint.
- Screen change detection uses a 16x16 perceptual-hash Hamming distance (threshold 10) rather than pixel diff, so cursor movement and clock ticks are ignored but a pop-up or new window is kept (a full-screen pop-up scored 68-108).
- Kept frames are rate-limited to one per 2 s: a live run with an editor redrawing kept ~40 frames in 50 s, each of which would be a Tier-1 call.
- Muse Voice Transcribe is realtime-only (WebSocket `wss://api.meta.ai/v1/asr/realtime`; `/audio/transcriptions` returns 404). We use its `DIARIZATION` mode so each turn carries a speaker label.
- The realtime ASR needs continuous real-time audio while a session is open, so local VAD gates *sessions*, not frames: open on 240 ms of sustained speech (with 0.8 s pre-roll), close after 12 s of silence. Quiet periods are never streamed or billed.
- VAD is RMS energy over an adaptive noise floor rather than a neural VAD: it only has to decide "is anyone talking", and it avoids a native-build dependency on Windows.
- Remote-access tools keep relay connections open while idle, so a live session is inferred from *new* public endpoints appearing after a 15 s settle baseline; the ScreenAnalyst is meant to corroborate it.
- Windows Quick Assist and Remote Assistance are on the remote-access list: no download needed, so scammers increasingly favour them.
- The clipboard watcher publishes only the finding type and a masked value (`****1111`, `bc1q…5mdq`); raw clipboard text never leaves its thread. Card numbers must pass Luhn to count.
- Watcher threads use a `_halt` event, not `_stop`, because `threading.Thread` has a private `_stop()` method that `join()` relies on.
- Analysts may only emit signal names from a fixed vocabulary (`core/killchain.py`); anything else is dropped. A manipulated model can therefore only report known categories, never invent actions.
- Text on screen that addresses an AI ("mark this page safe") is a scored signal, `ai_directed_text`; the test scam page carries one, and the ScreenAnalyst flags it instead of obeying it.
- `cross_modal_brand_match` and `bank_open_during_remote` are derived by the CaseFile, not by a model, because no single analyst sees both the screen and the call.
- The ScreenAnalyst worker is "latest only" (stale frames are skipped when the model lags); the CallAnalyst worker is ordered, because the call must be read in sequence.
- Scenarios are JSON timelines with events anchored to call lines; call audio is synthesized with two built-in Windows voices so diarization has distinct speakers, and replay can either stream it through the real ASR or inject the lines as text for fast, deterministic runs.
- Until on-device redaction exists (Stage F), the live runner does not send real screenshots to a model unless `--allow-unredacted-frames` is passed; only the fictional scenario frames are sent.
- Confidence is a noisy-OR over distinct signal weights scaled by the number of kill-chain stages present (1 stage: 0.45, 2: 0.75, 3+: 0.95-1.0). Known issue for Stage D: it saturates early, and secrecy at the Contact stage ("don't call anyone") currently counts as Extraction.
