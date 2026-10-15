# SonarQube Secure Code Review — Before / After
n[![security](https://github.com/tharun-1704/sonarqube-secure-review/actions/workflows/security.yml/badge.svg)](https://github.com/tharun-1704/sonarqube-secure-review/actions/workflows/security.yml)

A hands-on secure-code-review lab: a deliberately vulnerable Flask app scanned
with SonarQube, then remediated and re-scanned to show the delta. Demonstrates
finding, classifying, and fixing security issues in source code.

> Tool credit: [SonarQube](https://www.sonarsource.com/products/sonarqube/)
> (Community Edition). All application code here is my own, written for this lab.

---

## Overview

SonarQube performs static analysis (SAST) and sorts findings into **Bugs**,
**Vulnerabilities**, **Security Hotspots**, and **Code Smells**, each with a
severity. This repo scans two versions of the same app — one insecure, one
fixed — and compares the results.

- `app-vulnerable/` — same functionality, intentionally insecure
- `app-fixed/` — remediated version
- `docs/before.png`, `docs/after.png` — dashboard screenshots

---

## The Vulnerable App

A small Flask app with intentionally planted flaws (each marked `# FLAW:` in code):

| # | Flaw | SonarQube category |
|---|------|--------------------|
| 1 | Hardcoded secret key / DB password | Vulnerability / Hotspot |
| 2 | SQL injection (string-built query) | Vulnerability |
| 3 | Command injection (`os.system`) | Vulnerability |
| 4 | Weak hashing (MD5 for passwords) | Hotspot |
| 5 | `eval()` on user input | Vulnerability |
| 6 | TLS verification disabled (`verify=False`) | Hotspot |
| 7 | Debug mode on in production | Hotspot |

---

## Findings (Before)

Scanned with SonarQube Community Edition (`sonarqube:lts-community`).

| Category | Vulnerable app |
|----------|----------------|
| Vulnerabilities (open issues) | **1** |

*(Dashboard screenshot with hotspot / smell counts: `docs/before.png`, pending.)*

**Confirmed issue:**

- **`python:S4830`, CRITICAL Vulnerability (line 86):** *"Enable server
  certificate validation on this SSL/TLS connection."* `requests.get(..., verify=False)`
  accepts any certificate, so anyone on the network path can impersonate the
  remote server and read or alter the traffic (man-in-the-middle).

**What was *not* reported as a Vulnerability, and why that matters:**

SQL injection, command injection, and `eval()` on user input did **not** show up
as Vulnerability issues. Detecting them requires *taint analysis*, which traces
untrusted input (`request.args`) to a dangerous sink (`execute`, `os.system`,
`eval`). That engine ships only in SonarQube's commercial editions. In
Community Edition these patterns surface at most as Security Hotspots for a human
to review, or not at all.

Takeaway: a clean SAST dashboard is not a clean app. The scanner's edition and
rule set define what it can see, and manual review (plus the Level 2 checks
below) has to cover the gap.

---

## Remediation

| Flaw | Fix applied |
|------|-------------|
| Hardcoded secrets | Read from environment variables |
| SQL injection | Parameterized queries |
| Command injection | `subprocess.run([...], shell=False)` + input validation |
| Weak hashing | bcrypt / salted KDF |
| `eval()` | `ast.literal_eval` / json parsing |
| TLS disabled | Verification enabled |
| Debug mode | `debug=False` |

---

## Results (After)

| Category | Before | After |
|----------|--------|-------|
| Vulnerabilities (open issues) | 1 | **0** |

The remediated app scans with **0 open issues**. The TLS finding is gone because
verification is explicitly enabled and the target URL is allow-listed.

*(Dashboard screenshot: `docs/after.png`, pending.)*

---

## Level 2: Proof of Exploit

A scanner finding is a claim; an exploit is proof. [`tests/test_exploits.py`](tests/test_exploits.py)
attacks every planted flaw, first against the vulnerable app (attack succeeds)
and then against the fixed app (attack is blocked): **17 tests, all passing.**

| # | Attack | Vulnerable app | Fixed app |
|---|--------|----------------|-----------|
| 1 | SQLi: `x' UNION SELECT id, password_hash ... --` | Dumps alice's password hash | Treated as a literal username, returns nothing |
| 2 | Command injection: `127.0.0.1; touch /tmp/pwned` | Attacker's command runs on the server | `400`, hostname validation rejects it |
| 3 | `eval`: `__import__('os').getpid()` | Arbitrary Python executes | `400`, `literal_eval` only allows literals |
| 4 | Crack MD5 with a wordlist | `password123` recovered instantly | bcrypt: salted, two users with the same password get different hashes |
| 5 | Forge a session with the leaked `SECRET_KEY` | Signed `is_admin: true` cookie accepted | Signature rejected; key lives only in env |
| 6 | Fetch over TLS / hit `169.254.169.254` | `verify=False` (MITM possible) | `verify=True`, non-allow-listed URLs blocked (SSRF) |
| 7 | Start-up config | `debug=True` on `0.0.0.0` (Werkzeug console = RCE) | `debug=False` on `127.0.0.1` |

Note the SonarQube gap: Community Edition reported only #6 as a Vulnerability,
yet #1–#3 are fully exploitable. The tests catch what the scanner missed.

Run them (no local Python needed):

```bash
./run-tests.sh
```

---

## Level 2: CI Pipeline and Quality Gate

[`.github/workflows/security.yml`](.github/workflows/security.yml) runs on every
push and pull request to `main`:

| Job | What it does | Fails the build when |
|-----|--------------|----------------------|
| Proof-of-exploit tests | Runs the pytest suite above | Any fix regresses |
| Bandit | Python SAST; reports on `app-vulnerable`, gates `app-fixed` | Any finding in `app-fixed` |
| Semgrep | Taint-aware SAST (`p/python`, `p/flask`, `p/secrets`) | Any finding in `app-fixed` |

SonarQube itself runs locally, so the cloud pipeline uses serverless scanners.

### Three scanners, same vulnerable code

| Planted flaw | SonarQube CE | Bandit | Semgrep |
|--------------|:-----------:|:------:|:-------:|
| Hardcoded secrets | – | ✅ B105 | – |
| SQL injection | – | ✅ B608 | ✅ tainted-sql-string |
| Command injection | – | ✅ B605 | ✅ os-system-injection |
| Weak hashing (MD5) | – | ✅ B324 | ✅ md5-used-as-password |
| `eval()` on input | – | ✅ B307 | ✅ eval-injection |
| TLS verification off | ✅ S4830 | ✅ B501 | – |
| Debug mode | – | ✅ B201 | ✅ debug-enabled |

SonarQube column = open Vulnerability issues only (Hotspots not counted). No
single tool caught everything, which is the argument for layering scanners.

### The gate caught two real bugs in the "fixed" app

Wiring up the gate surfaced problems in my own remediation, which is exactly
what a gate is for:

1. **SSRF via URL parsing.** Semgrep flagged `/fetch`: the hostname was checked
   with `urlparse`, but the caller's raw string was then passed to `requests`.
   Different URL parsers can disagree (`https://example.com@169.254.169.254/`).
   Fix: compare against an allow-list and fetch the **allow-listed constant**,
   never user input.
2. **Argument injection into `ping`.** The hostname regex allowed labels that
   start with `-`, so `host=-f` would reach `ping` as an option, even with
   `shell=False`. Fix: labels must start and end alphanumeric. Covered by
   `test_ping_option_injection_rejected_by_fixed`.

Bandit's remaining LOW findings (`subprocess` usage) were reviewed and
suppressed inline with `# nosec` plus a written justification, the same as
marking a Hotspot "Safe" in SonarQube.

---

## What SonarQube's Categories Mean (in my own words)

- **Bug:** code that is demonstrably wrong and may break at runtime.
- **Vulnerability:** a security flaw an attacker could exploit.
- **Security Hotspot:** security-sensitive code that needs human review (not
  always a bug, but worth checking) — reviewing these is core to triage.
- **Code Smell:** maintainability issue, not a direct security risk.

**How this maps to real triage:** a Vulnerability is SonarQube's claim that
something is exploitable; a Hotspot is a question for a human. Triage means
confirming true positives (the `verify=False` finding is real), marking hotspots
that are safe in context as reviewed, and, just as important, knowing which
classes of bug the tool *can't* see (here, injection without taint analysis).
That is the same false-positive / false-negative judgement SOC analysts apply
to alerts every day.

---

## Credits

- [SonarQube](https://www.sonarsource.com/products/sonarqube/) Community Edition.

---

## Reproduce

```bash
# 1. Start SonarQube
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community
# 2. Log in at http://localhost:9000, then My Account -> Security -> Generate Token
# 3. Scan each app (token via env var, never stored in the repo)
cd app-vulnerable
docker run --rm -e SONAR_HOST_URL=http://host.docker.internal:9000 -e SONAR_TOKEN=<token> -v "$(pwd):/usr/src" sonarsource/sonar-scanner-cli
cd ../app-fixed
docker run --rm -e SONAR_HOST_URL=http://host.docker.internal:9000 -e SONAR_TOKEN=<token> -v "$(pwd):/usr/src" sonarsource/sonar-scanner-cli
```

> The vulnerable app is for local scanning only. Never deploy it.
