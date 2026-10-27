"""CORS misconfiguration checks against a single URL.

Each check sends one request with a crafted Origin and inspects the
Access-Control-Allow-Origin (ACAO) and Access-Control-Allow-Credentials (ACAC)
response headers. Nothing is exploited; the scanner only reports which origins a
server would trust.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

import requests

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    check: str
    severity: str
    origin_sent: str
    acao: str | None
    acac: bool
    detail: str


@dataclass
class Probe:
    """One response's CORS-relevant facts."""

    origin_sent: str
    status: int
    acao: str | None
    acac: bool


def _derive_origins(url: str) -> dict[str, str]:
    """Build the test origins from the target's own host."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or "target"
    scheme = parts.scheme or "https"
    # Registrable-ish base: last two labels. Good enough to craft the classic
    # "attacker.<target-domain>" and "<target-domain>.evil.com" cases.
    labels = host.split(".")
    base = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return {
        "reflect": "https://evil-cors-test.example",
        "null": "null",
        "subdomain": f"{scheme}://attacker.{host}",
        "prefix": f"{scheme}://{base}.evil-cors-test.example",
        "suffix": f"{scheme}://evil-cors-test.example{base}",
        "sibling": f"{scheme}://not{base}",
        "scheme_down": f"http://{host}",
    }


class CorsScanner:
    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        proxy: str | None = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.verify = False
        self.origins = _derive_origins(url)

    def probe(self, origin: str) -> Probe:
        resp = self.session.get(
            self.url,
            headers={"Origin": origin},
            timeout=self.timeout,
            allow_redirects=False,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        return Probe(origin, resp.status_code, acao, acac)

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        checks: list[tuple[str, str, Callable[[Probe], tuple[bool, str, str]]]] = [
            ("reflected-origin", "reflect", self._check_reflected),
            ("null-origin", "null", self._check_null),
            ("trusts-subdomain", "subdomain", self._check_exact),
            ("prefix-match-bypass", "prefix", self._check_exact),
            ("suffix-match-bypass", "suffix", self._check_exact),
            ("sibling-domain-bypass", "sibling", self._check_exact),
            ("scheme-downgrade", "scheme_down", self._check_scheme),
        ]

        # Run every check independently: a server might trust only "null" or only
        # a crafted subdomain while ignoring a generic foreign origin, so there's
        # no single baseline we can short-circuit on.
        seen: dict[str, Probe] = {}
        any_acao = False
        for name, origin_key, fn in checks:
            origin = self.origins[origin_key]
            probe = seen.get(origin) or self.probe(origin)
            seen[origin] = probe
            any_acao = any_acao or probe.acao is not None
            hit, severity, detail = fn(probe)
            if hit:
                findings.append(
                    Finding(name, severity, probe.origin_sent, probe.acao, probe.acac, detail)
                )

        if not findings and not any_acao:
            findings.append(
                Finding(
                    "no-cors", "info", self.origins["reflect"], None, False,
                    "No Access-Control-Allow-Origin returned for any tested origin.",
                )
            )

        findings.sort(key=lambda f: SEV_ORDER[f.severity], reverse=True)
        return findings

    # Each check returns (is_finding, severity, detail). ACAO reflection with
    # credentials is the dangerous case: the attacker's page can read authed
    # responses. Reflection + wildcard-with-credentials is impossible per spec,
    # so credentials are what escalate reflection to high/critical.
    @staticmethod
    def _severity(acac: bool, base: str = "medium") -> str:
        return "critical" if acac and base == "high" else ("high" if acac else base)

    def _check_reflected(self, p: Probe) -> tuple[bool, str, str]:
        if p.acao == p.origin_sent:
            return True, self._severity(p.acac, "high"), (
                "Server reflects an arbitrary Origin in ACAO"
                + (" with credentials enabled — any site can read authenticated "
                   "responses." if p.acac else " (no credentials).")
            )
        if p.acao == "*":
            return True, "low", (
                "Wildcard ACAO (*). Low risk without credentials, but exposes any "
                "non-credentialed data to all origins."
            )
        return False, "", ""

    def _check_null(self, p: Probe) -> tuple[bool, str, str]:
        if p.acao == "null":
            return True, self._severity(p.acac, "high"), (
                "Server trusts the 'null' origin, reachable from sandboxed iframes "
                "and data: URLs"
                + (" with credentials." if p.acac else ".")
            )
        return False, "", ""

    def _check_exact(self, p: Probe) -> tuple[bool, str, str]:
        if p.acao == p.origin_sent:
            return True, self._severity(p.acac, "high"), (
                f"Server trusts {p.origin_sent!r}"
                + (" with credentials." if p.acac else ".")
            )
        return False, "", ""

    def _check_scheme(self, p: Probe) -> tuple[bool, str, str]:
        if p.acao == p.origin_sent and p.origin_sent.startswith("http://"):
            return True, "medium", (
                "Server trusts the insecure http:// origin of its own host, "
                "enabling a MITM on cleartext to read responses."
            )
        return False, "", ""
