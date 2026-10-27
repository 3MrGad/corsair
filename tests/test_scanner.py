"""Tests for corsair, driven by a configurable in-process CORS endpoint."""

from __future__ import annotations

import threading
from wsgiref.simple_server import make_server

import pytest

from corsair.scanner import CorsScanner


class CorsPolicy:
    """A WSGI app whose CORS behaviour the tests set per-case."""

    def __init__(self) -> None:
        self.mode = "none"

    def __call__(self, environ, start_response):
        origin = ""
        for key, val in environ.items():
            if key == "HTTP_ORIGIN":
                origin = val
        acao, acac = self._decide(origin)
        headers = [("Content-Type", "text/plain")]
        if acao is not None:
            headers.append(("Access-Control-Allow-Origin", acao))
        if acac:
            headers.append(("Access-Control-Allow-Credentials", "true"))
        start_response("200 OK", headers)
        return [b"ok"]

    def _decide(self, origin: str) -> tuple[str | None, bool]:
        if self.mode == "none":
            return None, False
        if self.mode == "wildcard":
            return "*", False
        if self.mode == "reflect":
            return origin, True
        if self.mode == "null" and origin == "null":
            return "null", True
        if self.mode == "suffix" and origin.endswith("example"):
            return origin, True
        return None, False


@pytest.fixture(scope="module")
def policy_server():
    policy = CorsPolicy()
    httpd = make_server("127.0.0.1", 0, policy)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}/api"
    yield policy, url
    httpd.shutdown()


def checks(scanner: CorsScanner) -> dict[str, str]:
    return {f.check: f.severity for f in scanner.scan()}


def test_no_cors_headers_is_clean(policy_server):
    policy, url = policy_server
    policy.mode = "none"
    result = checks(CorsScanner(url))
    assert result == {"no-cors": "info"}


def test_wildcard_is_low(policy_server):
    policy, url = policy_server
    policy.mode = "wildcard"
    result = checks(CorsScanner(url))
    assert result.get("reflected-origin") == "low"


def test_reflected_with_credentials_is_critical(policy_server):
    policy, url = policy_server
    policy.mode = "reflect"
    result = checks(CorsScanner(url))
    # Reflection + credentials is the worst case.
    assert result.get("reflected-origin") == "critical"


def test_null_origin_trusted(policy_server):
    policy, url = policy_server
    policy.mode = "null"
    result = checks(CorsScanner(url))
    assert result.get("null-origin") in {"high", "critical"}


def test_suffix_bypass_detected(policy_server):
    policy, url = policy_server
    policy.mode = "suffix"
    result = checks(CorsScanner(url))
    # The suffix origin ends in "example" and gets reflected -> flagged.
    assert "suffix-match-bypass" in result or "reflected-origin" in result


def test_findings_sorted_by_severity(policy_server):
    policy, url = policy_server
    policy.mode = "reflect"
    findings = CorsScanner(url).scan()
    from corsair.scanner import SEV_ORDER

    severities = [SEV_ORDER[f.severity] for f in findings]
    assert severities == sorted(severities, reverse=True)
