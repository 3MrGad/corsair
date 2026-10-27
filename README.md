# corsair

A focused **CORS misconfiguration scanner**. Point it at an endpoint that
returns CORS headers and it reports which origins the server would trust — and
how badly that can be abused — ranked by severity.

CORS bugs are easy to get wrong and easy to miss by eye, because the dangerous
part is the *combination* of `Access-Control-Allow-Origin` and
`Access-Control-Allow-Credentials`. corsair tests the common bypass patterns in
one shot and tells you which ones land.

> ⚠️ **Authorized use only.** Scan your own lab, a signed engagement, or an
> in-scope bug bounty asset. The tool prints this reminder on every run.

## What it checks

| Check | What it means |
|-------|---------------|
| `reflected-origin` | Server echoes any `Origin` back in ACAO. With credentials, **critical** — any site reads authenticated responses. |
| `null-origin` | Server trusts `Origin: null`, reachable from sandboxed iframes and `data:` URLs. |
| `trusts-subdomain` | Server trusts an arbitrary subdomain (`attacker.target.com`) — exploitable via subdomain takeover or a vulnerable sibling. |
| `prefix-match-bypass` | Server trusts `target.com.evil.com` — a naive "startswith" origin check. |
| `suffix-match-bypass` | Server trusts `eviltarget.com` — a naive "endswith" origin check. |
| `sibling-domain-bypass` | Server trusts `nottarget.com` — substring matching gone wrong. |
| `scheme-downgrade` | Server trusts the `http://` version of its own host — readable via a MITM on cleartext. |

Severity escalates when `Access-Control-Allow-Credentials: true` is present,
because that's what lets an attacker's page read a victim's authenticated data.

## Install

```bash
git clone https://github.com/3MrGad/corsair
cd corsair
pip install -e .
```

## Usage

```bash
# Basic scan
corsair https://api.target.com/me

# With a session cookie (credentials make reflection much worse)
corsair https://api.target.com/me -H "Cookie: session=..."

# Through Burp, JSON output for tooling
corsair https://api.target.com/me --proxy http://127.0.0.1:8080 --json

# In CI: exit non-zero on anything medium or worse
corsair https://api.target.com/me --fail-on medium
```

Example:

```
[CRITICAL] reflected-origin
    Origin sent : https://evil-cors-test.example
    ACAO        : https://evil-cors-test.example
    Credentials : True
    Server reflects an arbitrary Origin in ACAO with credentials enabled — any
    site can read authenticated responses.
```

## How it works

The test origins are derived from the target's own hostname, so the
subdomain/prefix/suffix/sibling cases are tailored to the domain you're testing.
Each check sends one `GET` with a crafted `Origin` and reads back ACAO/ACAC —
corsair reports what the server *would* trust; it never exploits anything.

Checks run independently (no single baseline), so a server that trusts *only*
`null` or *only* a crafted subdomain is still caught.

## Testing

Tests run against an in-process WSGI endpoint whose CORS policy is set per case —
no network, no real target.

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
