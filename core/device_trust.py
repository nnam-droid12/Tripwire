"""Device Trust: when the address and the padlock are both right, but the computer has been tampered with.

During a remote-access session a scammer can make the real address of a bank open *their* server, padlock
and all, with two changes that nothing on screen reveals:

* **the hosts file** (``C:\\Windows\\System32\\drivers\\etc\\hosts``): one line like ``203.0.113.7 www.chase.com``
  sends the bank's real name to the scammer's server;
* **a certificate authority of their own**, installed in the computer's trusted roots: the browser then shows
  a padlock for the fake server, because this computer, and only this one, trusts it.

So Tripwire checks the computer, not the page:

* :func:`hosts_overrides` lists hosts-file lines that redirect a bank's, shop's or agency's real domain;
* :func:`certificate_check` opens the site twice: once trusting this computer's certificate store (what the
  browser does) and once trusting only the public roots every browser ships (``certifi``). A padlock that only
  this computer trusts is a padlock someone installed.

Both are facts about the machine, not a model's opinion, so their findings are ground truth for the judge.
(A company network that inspects encrypted traffic also installs its own root; the finding names the issuer
so a family can tell the difference.)
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from pathlib import Path

import certifi

from core.site_check import OFFICIAL, SiteFinding, host_of, registrable

HOSTS = Path(r"C:\Windows\System32\drivers\etc\hosts")
_PROTECTED = {d for domains in OFFICIAL.values() for d in domains}


def hosts_overrides(text: str | None = None, protected: set[str] = _PROTECTED) -> list[SiteFinding]:
    """Hosts-file lines that point a protected domain (or any of its subdomains) somewhere else."""
    if text is None:
        try:
            text = HOSTS.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
    findings = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split()
        if len(line) < 2:
            continue
        ip, names = line[0], line[1:]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_unspecified:  # 0.0.0.0 blocks a site (ad blockers); it cannot impersonate one
            continue
        for name in names:
            host = host_of(name)
            if registrable(host) in protected:
                findings.append(SiteFinding("hosts_file_hijack",
                                            f"This computer's hosts file sends {name} to {ip} instead of the real {registrable(host)}: "
                                            f"the real address opens someone else's server"))
    return findings


def _issuer(cert: dict) -> str:
    parts = dict(x[0] for x in cert.get("issuer", ()) if x)
    return parts.get("organizationName") or parts.get("commonName") or "an unknown issuer"


def certificate_check(url: str, timeout: float = 5.0) -> SiteFinding | None:
    """A ``rogue_certificate`` finding if the site's padlock is trusted by this computer but not by the public roots."""
    host = host_of(url)
    if not host:
        return None
    name = host if host.isascii() else host.encode("idna").decode("ascii")
    try:
        system = ssl.create_default_context()  # this computer's trust store: what the browser uses
        with socket.create_connection((name, 443), timeout=timeout) as sock, system.wrap_socket(sock, server_hostname=name) as tls:
            cert = tls.getpeercert()
    except (ssl.SSLError, OSError):
        return None  # the browser would show its own warning; not this check's case
    try:
        public = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((name, 443), timeout=timeout) as sock, public.wrap_socket(sock, server_hostname=name):
            return None  # trusted publicly: an ordinary padlock
    except ssl.SSLCertVerificationError:
        return SiteFinding("rogue_certificate",
                           f"The padlock on {host} comes from '{_issuer(cert)}', a certificate authority installed on this computer that "
                           f"the public internet does not trust: the connection can be read or faked by whoever installed it")
    except (ssl.SSLError, OSError):
        return None
