"""Site Check and Device Trust: clones with the "right" address and padlock, and real sites left alone."""

import ssl

import pytest

from analysts.screen_analyst import ScreenFinding
from core import device_trust
from core.casefile import CaseFile
from core.device_trust import certificate_check, hosts_overrides
from core.events import EventBus
from core.orchestrator import Orchestrator
from core.site_check import brand_key, check_page, host_of, lookalike, registrable, skeleton


def signals(url, brand=None, asks="login", drawn=()):
    return {f.signal for f in check_page(url, brand, asks, list(drawn))}


@pytest.mark.parametrize("url", [
    "https://www.аmazon.com/ap/signin",  # Cyrillic "а"
    "https://xn--mazon-3ve.com/",  # the same, as the browser may show it
    "https://arnazon.com", "https://paypa1.com/login", "https://amazon.co/x", "https://shopvvave.com",
])
def test_lookalike_addresses_are_caught(url):
    assert "lookalike_domain" in signals(url)


@pytest.mark.parametrize("url", ["https://www.amazon.com/ap/signin", "https://smile.amazon.co.uk", "https://secure.chase.com",
                                 "https://www.apple.de", "https://shopwave.com/signin", "https://github.com", "https://www.bbc.co.uk"])
def test_real_and_unrelated_addresses_are_not(url):
    assert lookalike(host_of(url)) is None


def test_skeleton_and_registrable():
    assert skeleton("аrnаzon") == "amazon"
    assert registrable("secure.login.amazon.co.uk") == "amazon.co.uk"
    assert registrable(host_of("https://riverbendbank.com.account-verify.help/x")) == "account-verify.help"


def test_brand_on_the_wrong_address_only_matters_when_the_page_asks_for_something():
    assert signals("https://chase-secure-verify.help/login", "Chase Bank", "login") == {"brand_domain_mismatch"}
    assert signals("https://chase-secure-verify.help/news", "Chase", "none") == set()
    assert signals("https://www.chase.com/login", "Chase", "login") == set()
    assert signals("https://smallbank.example/login", "Some Local Credit Union", "login") == set()  # unknown brand: no claim
    assert brand_key("Riverbend Bank") == "riverbend community bank"


def test_window_drawn_inside_the_page():
    s = signals("https://account-help.top/x", "Google", "login", ["https://accounts.google.com/signin"])
    assert "fake_browser_window" in s
    assert signals("https://accounts.google.com/x", "Google", "login", ["https://accounts.google.com/signin"]) == set()


def test_hosts_file():
    text = "127.0.0.1 localhost\n203.0.113.7  www.chase.com   # added\n0.0.0.0 ads.tracker.example\n0.0.0.0 www.paypal.com\n10.0.0.5 intranet.local"
    found = hosts_overrides(text)
    assert [f.signal for f in found] == ["hosts_file_hijack"] and "203.0.113.7" in found[0].evidence


def test_certificate_trusted_only_by_this_computer(monkeypatch):
    """Simulate a rogue root: the computer's store accepts the site, the public roots do not."""
    class Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    class TLS(Sock):
        def getpeercert(self): return {"issuer": ((("organizationName", "Totally Secure Support CA"),),)}
    class Ctx:
        def __init__(self, public): self.public = public
        def wrap_socket(self, sock, server_hostname):
            if self.public:
                raise ssl.SSLCertVerificationError("unable to get local issuer certificate")
            return TLS()
    monkeypatch.setattr(device_trust.socket, "create_connection", lambda *a, **k: Sock())
    monkeypatch.setattr(device_trust.ssl, "create_default_context", lambda cafile=None: Ctx(public=cafile is not None))
    f = certificate_check("https://www.chase.com/login")
    assert f.signal == "rogue_certificate" and "Totally Secure Support CA" in f.evidence


class _Screen:
    def __init__(self, finding):
        self.finding = finding

    def analyze(self, _path):
        return self.finding


def test_orchestrator_raises_site_signals_from_the_real_address(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "test-key-never-used")  # clients are built, never called
    monkeypatch.setattr("core.site_check.domain_age_days", lambda host: 3)  # no network in tests
    finding = ScreenFinding("A ShopWave sign-in page", "low", ["ShopWave"], [], page_brand="ShopWave", asks_for="login")
    case = CaseFile()
    orch = Orchestrator(EventBus(), case, screen=_Screen(finding), log=lambda _: None)
    orch.check_site("https://www.shopwаve.com/signin", finding)
    names = {s.name for s in case.signals}
    assert {"lookalike_domain", "new_domain"} <= names
    assert orch.action.label == "hard_stop" and orch.decisions[0][1].reasons[0]["source_kind"] == "site"
    assert any(t["source"] == "site" for t in case.snapshot()["timeline"])


def test_one_letter_off_waits_for_the_page_but_foreign_letters_do_not(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "test-key-never-used")  # clients are built, never called
    monkeypatch.setattr("core.site_check.domain_age_days", lambda host: None)
    finding = ScreenFinding("A ShopWave product page", "low", ["ShopWave"], [], page_brand="ShopWave", asks_for="none")
    orch = Orchestrator(EventBus(), CaseFile(), screen=_Screen(finding), log=lambda _: None)
    orch.check_site("https://shopwave.co/deals", finding)  # an imitation, but the page asks for nothing: a signal, no stop
    assert orch.action.label != "hard_stop" and any(s.name == "lookalike_domain" for s in orch.case.signals)
    orch._precheck_url("https://www.shopw\u0430ve.com/deals")  # foreign letters: stopped from the address alone
    assert orch.action.label == "hard_stop"
