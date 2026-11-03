"""Site Check: is the website really who it says it is?

A scammer can clone a bank's or a shop's site in minutes, and "check the address and
the padlock" no longer protects anyone. The four ways a clone passes that test, and the check for each:

1. **Look-alike address.** ``amazon.com`` spelt with a Cyrillic "о", or ``arnazon.com`` ("rn" reads as "m").
   The scammer owns that domain, so the padlock is real. :func:`lookalike` compares the address with
   official domains after folding look-alike letters (a "skeleton", as in Unicode's confusables).
2. **Fake browser window.** A pop-up drawn *inside* the page, with its own painted address bar showing
   ``https://www.amazon.com`` and a padlock. It is pixels; the browser's real address is something else.
   The vision model reports any address it sees drawn inside the page; :func:`check_page` compares it with
   the real address the browser reports (never read from the pixels).
3. **Right brand, wrong address.** The page looks exactly like the bank and asks for the password, but the
   real address is not one of the bank's. The vision model says which brand the page presents itself as;
   :data:`OFFICIAL` says where that brand really lives.
4. **Same address, same padlock, tampered computer.** After a remote-access session, a scammer can edit
   the computer's hosts file and install their own certificate authority, so the real address opens their
   server *with* a padlock. Nothing on screen differs; :mod:`core.device_trust` checks the computer itself.

Plus supporting evidence: a domain registered days ago (:func:`domain_age_days`, public RDAP).

The model reads what a page *claims*; these rules establish what it *is*. Every finding names both.
"""

from __future__ import annotations

import json
import time
import unicodedata
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

# Where brands really live. Real brands most often cloned in phishing, plus the fictional brands of
# Tripwire's test pages (marked). A brand not listed here is never called a mismatch.
OFFICIAL: dict[str, tuple[str, ...]] = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in", "amazon.com.au", "amazon.co.jp", "amazon.fr", "amazon.es", "amazon.it"),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "xbox.com", "bing.com"),
    "google": ("google.com", "gmail.com", "youtube.com"),
    "paypal": ("paypal.com",),
    "facebook": ("facebook.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "netflix": ("netflix.com",),
    "ebay": ("ebay.com", "ebay.co.uk"),
    "walmart": ("walmart.com",),
    "costco": ("costco.com",),
    "chase": ("chase.com", "jpmorganchase.com"),
    "bank of america": ("bankofamerica.com", "bofa.com"),
    "wells fargo": ("wellsfargo.com",),
    "citibank": ("citi.com", "citibank.com"),
    "capital one": ("capitalone.com",),
    "us bank": ("usbank.com",),
    "american express": ("americanexpress.com",),
    "coinbase": ("coinbase.com",),
    "usps": ("usps.com",),
    "ups": ("ups.com",),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com",),
    "irs": ("irs.gov",),
    "social security administration": ("ssa.gov",),
    "medicare": ("medicare.gov",),
    "norton": ("norton.com",),
    "mcafee": ("mcafee.com",),
    "geek squad": ("geeksquad.com", "bestbuy.com"),
    # fictional brands of Tripwire's own test pages
    "shopwave": ("shopwave.com",),
    "riverbend community bank": ("riverbendbank.com",),
    "northgate market": ("northgatemarket.com",),
}
_ALIASES = {"bofa": "bank of america", "boa": "bank of america", "amex": "american express", "ssa": "social security administration",
            "riverbend bank": "riverbend community bank", "riverbend": "riverbend community bank", "office 365": "microsoft",
            "outlook": "microsoft", "icloud": "apple", "gmail": "google", "jpmorgan chase": "chase"}
_TWO_LEVEL = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "com.br", "co.in", "co.nz", "com.mx", "com.ng", "co.za", "com.sg"}

# Letters that look like Latin ones (a subset of Unicode's confusables, the ones seen in phishing), and digit swaps.
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h",
    "ԛ": "q", "ԝ": "w", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "ϲ": "c", "ӧ": "o",
    "0": "o", "1": "l", "3": "e", "5": "s", "ı": "i", "ł": "l", "ø": "o",
})
_PAIRS = (("rn", "m"), ("vv", "w"), ("cl", "d"))
# endings scammers pick for "the brand's name, another ending" (amazon.co, paypal.help); a real country site (apple.de) is not flagged
_SCAM_TLDS = {"co", "cm", "om", "con", "info", "top", "xyz", "online", "site", "help", "support", "live", "shop", "app", "icu", "click",
              "link", "vip", "store", "services", "secure", "account", "login", "net"}


@dataclass(frozen=True)
class SiteFinding:
    signal: str
    evidence: str


def host_of(url: str) -> str:
    """The host of a URL or bare domain, lower-case, without "www." or a port; punycode decoded to what people see."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        if "xn--" in host:
            host = host.encode("ascii").decode("idna")
    except UnicodeError:
        pass
    return host


def registrable(host: str) -> str:
    """The part of a host someone registers: ``secure.login.amazon.com`` -> ``amazon.com``."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def skeleton(text: str) -> str:
    """Fold look-alike characters so that ``аmazоn`` and ``arnazon`` both read ``amazon``."""
    s = unicodedata.normalize("NFKC", text.lower()).translate(_CONFUSABLE)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    for a, b in _PAIRS:
        s = s.replace(a, b)
    return s


def brand_key(name: str | None) -> str | None:
    if not name:
        return None
    n = " ".join(name.lower().replace("&", "and").split())
    n = _ALIASES.get(n, n)
    if n in OFFICIAL:
        return n
    for key in OFFICIAL:  # "Amazon.com", "Chase Bank", "Wells Fargo Online"
        if n.startswith(key) or key.startswith(n) and len(n) >= 4:
            return key
    return None


def is_official(host: str, brand: str) -> bool:
    return registrable(host) in OFFICIAL.get(brand, ())


def _mixed_script(host: str) -> bool:
    return any(ord(c) > 127 for c in host)


def _edit1(a: str, b: str) -> bool:
    """One letter added, dropped, changed or two swapped."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def lookalike(host: str) -> tuple[str, str, str, bool] | None:
    """``(brand, official domain, how, certain)`` if ``host`` imitates an official domain it is not.

    ``certain``: foreign look-alike letters in a brand's name. No honest site does that, so it needs no
    reading of the page. "One letter off" is not certain on its own (``ample.com`` is not ``apple.com``)."""
    reg = registrable(host)
    name, _, tld = reg.partition(".")
    for brand, domains in OFFICIAL.items():
        if reg in domains:
            return None  # the real thing
        for official in domains:
            oname, _, otld = official.partition(".")
            if len(oname) < 4:
                continue
            if _mixed_script(reg) and skeleton(name) == skeleton(oname):
                odd = "".join(sorted({c for c in name if ord(c) > 127}))
                return brand, official, f"it uses look-alike foreign letters ({', '.join(repr(c) + ' ' + unicodedata.name(c, '?').title() for c in odd)})", True
            if skeleton(name) == skeleton(oname) and name != oname:
                return brand, official, "letters are swapped for look-alikes (like 'rn' for 'm' or '0' for 'o')", False
            if _edit1(name, oname) and len(oname) >= 5:
                return brand, official, "it is one letter away from the real name", False
            if name == oname and tld in _SCAM_TLDS and tld != otld:
                return brand, official, f"it ends in .{tld}, not .{otld}", False
    return None


def check_page(real_url: str, claimed_brand: str | None = None, asks_for: str = "none", drawn_urls: list[str] = ()) -> list[SiteFinding]:
    """Compare what a page claims (from the vision model) with where the browser really is (from the browser).

    ``asks_for``: what the page asks the person to type: login, payment, personal or none.
    """
    findings: list[SiteFinding] = []
    host = host_of(real_url)
    if not host:
        return findings
    look = lookalike(host)
    if look:
        brand, official, how, _certain = look
        findings.append(SiteFinding("lookalike_domain", f"The browser's real address is {host}, made to look like {official}: {how}"))
    key = brand_key(claimed_brand)
    sensitive = asks_for in ("login", "payment", "personal")
    if key and sensitive and not is_official(host, key) and not look:
        official = ", ".join(OFFICIAL[key][:3])
        findings.append(SiteFinding("brand_domain_mismatch",
                                    f"The page presents itself as {claimed_brand} and asks for a {asks_for}, but the browser's real address is "
                                    f"{host}, which is not {claimed_brand}'s ({official})"))
    for drawn in drawn_urls:
        d = host_of(drawn)
        if d and registrable(d) != registrable(host):
            findings.append(SiteFinding("fake_browser_window",
                                        f"A window drawn inside the page shows the address {d} with a padlock, but the browser's real address is "
                                        f"{host}: that window is part of the page, not a real browser window"))
            break
    return findings


_AGE: dict[str, tuple[float, int | None]] = {}


def domain_age_days(host: str, timeout: float = 4.0) -> int | None:
    """Days since the domain was registered, from public RDAP records (rdap.org). None if unknown."""
    reg = registrable(host)
    if any(reg in d for d in OFFICIAL.values()):
        return None
    if reg in _AGE and time.time() - _AGE[reg][0] < 3600:
        return _AGE[reg][1]
    days = None
    try:
        idna = reg.encode("idna").decode("ascii")
        req = urllib.request.Request(f"https://rdap.org/domain/{idna}", headers={"Accept": "application/rdap+json"})
        data = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                registered = time.mktime(time.strptime(event["eventDate"][:10], "%Y-%m-%d"))
                days = int((time.time() - registered) // 86400)
    except Exception:
        days = None
    _AGE[reg] = (time.time(), days)
    return days


NEW_DOMAIN_DAYS = 60


def age_finding(host: str, days: int | None) -> SiteFinding | None:
    if days is None or days > NEW_DOMAIN_DAYS:
        return None
    return SiteFinding("new_domain", f"{registrable(host)} was registered {days} day{'s' if days != 1 else ''} ago (public domain records)")
