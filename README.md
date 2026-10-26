# php2shell-audit

**Non-destructive exposure checker for CVE-2026-109618 / CVE-2026-109619**

A lightweight, read-only Python script that helps security teams quickly assess whether a PHP deployment may be affected by the PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619). It sends **no exploit traffic** and performs **no memory-corruption attempts**.

> **This is a defensive audit tool, not an exploit.** It cannot confirm exploitability — only a full patch or a binary symbol check on the host can do that.

---

## ⚠️ Legal & Ethical Notice

This tool is intended **exclusively** for:

- Authorized security assessments of systems you own or have **written permission** to test
- Internal vulnerability management and asset inventory
- Lab / CTF / research environments

Running it against systems you do not own or lack permission to test may violate computer-misuse laws. The authors assume **no liability** for misuse.

---

## What It Does

| Check | How | Confidence |
|---|---|---|
| PHP version detection | `X-Powered-By` header + page body | High (if disclosed) |
| Affected-range matching | Compares against official patched versions | High |
| EOL detection | PHP ≤ 8.1 = permanently vulnerable | High |
| `session.upload_progress` hint | Optional non-destructive POST probe | Low / heuristic |
| `memory_limit` hint | Scans response for OOM signatures | Low / heuristic |
| Local backport check | Reads `changelog.Debian.gz` / `rpm -q --changelog` | High (local only) |
| Live reporting | Prints each target immediately | — |
| JSON output | For CI / pipelines | — |

### Patched versions (official)

| Branch | Patched from |
|---|---|
| PHP 8.5 | 8.5.12 |
| PHP 8.4 | 8.4.27 |
| PHP 8.3 | 8.3.36 |
| PHP 8.2 | 8.2.35 |
| PHP ≤ 8.1 | EOL — no official fix |

---

## What It Does **NOT** Do

- ❌ Does **not** send exploit payloads
- ❌ Does **not** trigger Use-After-Free or OOM corruption
- ❌ Does **not** confirm RCE is possible
- ❌ Does **not** replace a full patch or vendor security advisory
- ❌ Does **not** reliably detect vendor backports from a remote host

If you need to **confirm** exploitability, use a binary symbol check on the host (e.g. `gei-git/php2shell-poc`) or follow your vendor's advisory.

---

## Installation

```
pip install requests
```
Only requests is required. Everything else is Python standard library.

Usage
Basic version check (safe, GET only)
```
python3 php2shell-audit.py -u https://target.example.com
```
Scan a list of targets (live output)
```
python3 php2shell-audit.py -l targets.txt
```
Enable the optional session probe
```
# Only on authorized targets. Sends one multipart POST.
python3 php2shell-audit.py -u https://target.example.com --probe
```
JSON output for CI
```
python3 php2shell-audit.py -l targets.txt --json
```
Local backport check (on the PHP host)
```
python3 php2shell-audit.py --local -u https://target.example.com
```
Print remediation guide
```
python3 php2shell-audit.py --harden
```
Full help
```
python3 php2shell-audit.py -h
```
Exit Codes
Code	Meaning
0	All targets appear patched or backported
1	At least one target is vulnerable / EOL
2	Usage error / missing dependency
Output Example
```
============================================================
PHP2Shell Exposure Report (Live)
============================================================

[Target] https://target.example.com
  PHP: 8.4.26
  [!!] Status: VULNERABLE (version < official fix)
  [!!] session.upload_progress appears ENABLED (session cookie set)
  [~] memory_limit may be finite (OOM trigger possible)

============================================================
[!] 1 target(s) require action. Run --harden for remediation.
Limitations (Read This)
This tool is a triage aid, not a verdict.

Version numbers can lie. Many distributions backport security fixes without bumping the version string. A server reporting 8.1.34 may already be patched.

New versions can be inert. If PHP-FPM/Apache was not restarted after an update, the old vulnerable code may still be running.

Hidden versions yield UNKNOWN. If expose_php = Off or a CDN masks the header, the tool cannot judge.

The probe is heuristic. It infers session.upload_progress state indirectly; false positives and negatives are possible.

Remote backport detection is impossible. Only a local changelog check can confirm it.

RCE confirmation is out of scope. Memory-corruption exploitability cannot be proven without sending exploit traffic — which this tool deliberately avoids.

For authoritative guidance, consult the official PHP advisory and your distribution's security tracker.

Remediation Quick Guide

python3 php2shell-audit.py --harden

Key points:

Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 — then restart PHP-FPM/Apache.

CVE-2026-109619 partial mitigation: disable session.upload_progress.enabled.

CVE-2026-109618 partial mitigation: set memory_limit = -1.

EOL branches (≤ 8.1): migrate, or verify a vendor backport.

Mitigations reduce exposure; only a full update is a complete fix.
```
Disclaimer
This tool reflects publicly available information at the time of writing. Vulnerability details, patched versions, and mitigations may change. Always cross-check with official vendor advisories before making security decisions.

The authors are not responsible for any damage, legal consequences, or misuse arising from this tool.

License
MIT License — see LICENSE for details.


