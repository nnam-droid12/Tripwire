"""Margaret's simulated laptop: the pages it can show.

Each page is a fictional HTML page (shown to the visitor in an iframe) with a
pre-rendered PNG of the same page (what Tripwire's ScreenAnalyst sees). Some
pages also imply system events, exactly as the desktop agent would report
them: opening RemoteDesk launches a remote-access tool, and connecting it
starts a remote session.
"""

from __future__ import annotations

from pathlib import Path

from core.config import REPO_ROOT

PAGES_DIR = REPO_ROOT / "eval" / "scenarios" / "pages"
FRAMES_DIR = REPO_ROOT / "eval" / "scenarios" / "frames"

# page id -> (file stem, what Margaret sees, for her prompt)
PAGES: dict[str, tuple[str, str]] = {
    "desktop": ("desktop_idle", "her photo gallery, nothing else open"),
    "fake_alert": ("pc_safeguard_alert", "a red 'PC SafeGuard Alert' saying the computer is blocked, with a phone number to call"),
    "remotedesk_download": ("remotedesk_download", "the RemoteDesk app, showing her desk address 482 113 907, waiting for a connection"),
    "remotedesk_connected": ("remotedesk_connected", "a RemoteDesk bar saying a support agent is controlling her computer"),
    "bank": ("bank_dashboard", "her Riverbend Community Bank online banking: checking $4,310.55, savings $20,000.00"),
    "wire_transfer": ("scam_wire_form", "the bank's 'send a wire' form"),
    "gift_cards": ("gift_card_checkout", "a Northgate Market gift card checkout"),
    "bitcoin": ("scam_crypto_atm", "instructions for depositing cash at a Bitcoin ATM"),
    "bank_freeze": ("bank_freeze", "the bank's card security page"),
    "shop_email": ("site_shopwave_email", "her e-mail inbox, open on a ShopWave message about an order of $1,249 she did not place, with a 'Review order' button"),
    "shop_signin": ("site_shopwave_signin", "the ShopWave sign-in page that opened from the e-mail's 'Review order' button, asking for her e-mail and password"),
}

# The browser's real address for each page, as the desktop agent reads it from the browser itself (agent/browser.py).
# The ShopWave sign-in page is a clone: its address uses a Cyrillic "а", so it reads "shopwave.com" but is not.
URLS: dict[str, str] = {
    "bank": "https://www.riverbendbank.com/accounts",
    "wire_transfer": "https://www.riverbendbank.com/transfers/wire",
    "bank_freeze": "https://www.riverbendbank.com/security/card",
    "shop_email": "https://mail.example.com/inbox",
    "shop_signin": "https://www.shopw\u0430ve.com/signin",
}

# pages Margaret may open herself; bank_freeze is only opened by Tripwire's recovery agent
MARGARET_PAGES = [p for p in PAGES if p != "bank_freeze"]


def html_path(page: str) -> Path:
    return PAGES_DIR / f"{PAGES[page][0]}.html"


def png_path(page: str) -> Path:
    return FRAMES_DIR / f"{PAGES[page][0]}.png"


def menu() -> str:
    return "\n".join(f"- {p}: {PAGES[p][1]}" for p in MARGARET_PAGES)
