"""Set the family PIN and household details in ``config/tripwire.json``.

Usage::

    python -m scripts.set_pin                       # prompts for the PIN (not echoed)
    python -m scripts.set_pin --family-name David --trust AnyDesk:123456789

Only a salted hash of the PIN is stored.
"""

from __future__ import annotations

import argparse
import getpass

from core.settings import SETTINGS_PATH, Settings, mask_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--family-name")
    parser.add_argument("--protected-name")
    parser.add_argument("--trust", action="append", default=[], metavar="TOOL:ID", help="trusted remote-support ID, e.g. AnyDesk:123456789")
    parser.add_argument("--keep-pin", action="store_true", help="only update names / trusted IDs")
    args = parser.parse_args()

    settings = Settings.load()
    if args.family_name:
        settings.family_name = args.family_name
    if args.protected_name:
        settings.protected_name = args.protected_name
    for item in args.trust:
        tool, _, remote_id = item.partition(":")
        settings.trusted_remote_ids.setdefault(tool, [])
        if remote_id and remote_id not in settings.trusted_remote_ids[tool]:
            settings.trusted_remote_ids[tool].append(remote_id.replace(" ", ""))
    if not args.keep_pin:
        pin = getpass.getpass("New family PIN (4-8 digits): ")
        if getpass.getpass("Repeat PIN: ") != pin:
            raise SystemExit("PINs do not match")
        settings.set_pin(pin)
    settings.save()
    trusted = {t: [mask_id(i) for i in ids] for t, ids in settings.trusted_remote_ids.items()}
    print(f"Saved {SETTINGS_PATH} (family: {settings.family_name}, trusted: {trusted}, PIN set: {settings.has_pin})")


if __name__ == "__main__":
    main()
