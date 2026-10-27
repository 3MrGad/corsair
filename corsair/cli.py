"""CLI for corsair: a CORS misconfiguration scanner for authorized testing."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import __version__
from .scanner import CorsScanner, Finding

COLORS = {
    "critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[94m", "info": "\033[90m",
}
RESET = "\033[0m"

CONSENT = (
    "Scan only hosts you are authorized to test (your lab, a signed engagement, "
    "or an in-scope bug bounty asset)."
)


def parse_headers(raw: list[str]) -> dict[str, str]:
    headers = {}
    for item in raw:
        if ":" not in item:
            raise SystemExit(f"bad header (expected 'Name: value'): {item!r}")
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def format_text(url: str, findings: list[Finding], color: bool) -> str:
    lines = [f"CORS scan: {url}", "=" * (len(url) + 11)]
    actionable = [f for f in findings if f.severity != "info"]
    if not actionable:
        lines.append("No CORS misconfigurations detected.")
        for f in findings:
            lines.append(f"  [info] {f.detail}")
        return "\n".join(lines)
    for f in findings:
        tag = f.severity.upper()
        if color and f.severity in COLORS:
            tag = f"{COLORS[f.severity]}{tag}{RESET}"
        lines.append(f"[{tag}] {f.check}")
        lines.append(f"    Origin sent : {f.origin_sent}")
        lines.append(f"    ACAO        : {f.acao}")
        lines.append(f"    Credentials : {f.acac}")
        lines.append(f"    {f.detail}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="corsair",
        description="Detect CORS misconfigurations on an authorized target.",
        epilog=CONSENT,
    )
    p.add_argument("--version", action="version", version=f"corsair {__version__}")
    p.add_argument("url", help="target URL (an endpoint that returns CORS headers)")
    p.add_argument(
        "-H", "--header", action="append", default=[], metavar="'Name: value'",
        help="extra request header; repeatable (e.g. a session cookie)",
    )
    p.add_argument("--proxy", help="proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (s)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument(
        "--fail-on", choices=["low", "medium", "high", "critical"],
        help="exit non-zero if a finding at or above this severity is found (for CI)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.json:
        print(f"[!] {CONSENT}\n", file=sys.stderr)

    scanner = CorsScanner(
        args.url, headers=parse_headers(args.header),
        timeout=args.timeout, proxy=args.proxy,
    )
    try:
        findings = scanner.scan()
    except Exception as exc:  # network errors, bad URL, etc.
        raise SystemExit(f"[-] scan failed: {exc}")

    if args.json:
        print(json.dumps({"url": args.url, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(format_text(args.url, findings, color))

    if args.fail_on:
        from .scanner import SEV_ORDER

        threshold = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
