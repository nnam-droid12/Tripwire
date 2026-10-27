"""Stage A gate: confirm each configured provider returns text.

Usage::

    python -m scripts.hello_models            # baseten + meta
    python -m scripts.hello_models fireworks  # any subset
"""

from __future__ import annotations

import sys

from core.model_client import ModelClient

PROMPT = [{"role": "user", "content": "Reply with exactly: Tripwire online."}]


def check(provider: str) -> bool:
    """Call one provider and print the reply. Returns True on success."""
    try:
        client = ModelClient.for_provider(provider)
        reply = client.chat(PROMPT, max_tokens=32)
    except Exception as exc:  # report every failure, keep checking the rest
        print(f"[FAIL] {provider}: {type(exc).__name__}: {exc}")
        return False
    print(f"[ OK ] {provider} ({client.config.model}): {reply.strip()!r}")
    return True


def main(argv: list[str]) -> int:
    providers = argv or ["baseten", "meta"]
    results = [check(p) for p in providers]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
