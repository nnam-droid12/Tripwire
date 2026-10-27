# Engineering decisions

One line per non-obvious choice, newest last.

- One `ModelClient` wraps the `openai` SDK for every provider, because Baseten, the Meta Model API and Fireworks are all OpenAI-compatible; tiers differ only by env-configured provider name.
- `chat_json` extracts the outermost `{...}` from the reply instead of trusting raw output, since models often wrap JSON in prose or code fences.
- The Meta model id is read from `META_MODEL` rather than hard-coded, so the Tier-2 model can change without touching code.
