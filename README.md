# SonarQube Secure Code Review — Before / After

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

| Category | Count |
|----------|-------|
| Bugs | <fill in> |
| Vulnerabilities | <fill in> |
| Security Hotspots | <fill in> |
| Code Smells | <fill in> |

*(Screenshot: `docs/before.png`.)*

<Write 1–2 sentences per key finding: what SonarQube flagged and why it's a risk.>

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
| Bugs | <x> | <y> |
| Vulnerabilities | <x> | <y> |
| Security Hotspots | <x> | <y> |
| Code Smells | <x> | <y> |

*(Screenshot: `docs/after.png`.)*

---

## What SonarQube's Categories Mean (in my own words)

- **Bug:** code that is demonstrably wrong and may break at runtime.
- **Vulnerability:** a security flaw an attacker could exploit.
- **Security Hotspot:** security-sensitive code that needs human review (not
  always a bug, but worth checking) — reviewing these is core to triage.
- **Code Smell:** maintainability issue, not a direct security risk.

<Add a note on how this maps to real triage: separating true positives from
hotspots that are actually fine is exactly the false-positive work in a SOC.>

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
