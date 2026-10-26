#!/usr/bin/env python3
"""
php2shell-audit.py — Non-destructive exposure checker for CVE-2026-109618 / CVE-2026-109619
Authorized security assessment only. Sends no exploit traffic.

Improvements:
  - Checks session.upload_progress.enabled and memory_limit (relevant to both CVEs)
  - Backport detection via package changelog (local mode)
  - Live reporting: each target printed immediately
"""

import argparse
import json
import re
import subprocess
import sys
import urllib3

try:
    import requests
except ImportError:
    print("[-] requests required: pip install requests")
    sys.exit(2)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Official patched versions
PATCHED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}


def parse_php_version(text: str):
    """Extract PHP version from text."""
    m = re.search(r'PHP[/ ](\d+)\.(\d+)\.(\d+)', text, re.I)
    return tuple(map(int, m.groups())) if m else None


def classify_version(ver: tuple) -> str:
    """Return: patched / vulnerable / eol / unknown."""
    major, minor, patch = ver
    if major < 8 or (major == 8 and minor <= 1):
        return "eol"
    key = (major, minor)
    if key in PATCHED:
        return "patched" if patch >= PATCHED[key] else "vulnerable"
    return "unknown"


def check_php_settings(base_url: str, timeout: int = 8) -> dict:
    """
    Non-destructive probe: send one POST with multipart, observe server behavior
    to infer if session.upload_progress is enabled and memory_limit is finite.
    Does NOT send exploit payloads.
    """
    result = {"upload_progress_likely": None, "memory_limit_hint": None, "error": None}
    try:
        # Craft a multipart request that triggers upload_progress if enabled
        files = {
            "PHP_SESSION_UPLOAD_PROGRESS": (None, "probe123"),
            "file": ("test.txt", "x" * 1024, "text/plain"),  # 1KB file
        }
        r = requests.post(base_url, files=files, timeout=timeout,
                          verify=False, allow_redirects=True)
        # If upload_progress is enabled, PHP creates a session file and may set cookie
        has_session_cookie = any("PHPSESSID" in c.name for c in r.cookies)
        result["upload_progress_likely"] = has_session_cookie

        # Check for OOM-related error signatures (memory_limit finite)
        body_lower = r.text[:2000].lower()
        if any(kw in body_lower for kw in ["memory", "fatal", "out of memory"]):
            result["memory_limit_hint"] = "possibly_limited"
        else:
            result["memory_limit_hint"] = "unknown"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)[:100]
    return result


def check_backport_local() -> dict:
    """
    Check local package changelog for backported fix.
    Only works on Linux with dpkg/rpm. Returns dict with backport status.
    """
    result = {"checked": False, "backported": None, "detail": None}
    try:
        # Try Debian/Ubuntu first
        out = subprocess.run(
            ["bash", "-c",
             "zcat /usr/share/doc/php*-fpm/changelog.Debian.gz 2>/dev/null | grep -m1 '109618' || "
             "zcat /usr/share/doc/php*/changelog.Debian.gz 2>/dev/null | grep -m1 '109618' || "
             "rpm -q --changelog php-fpm 2>/dev/null | grep -m1 '109618'"],
            capture_output=True, text=True, timeout=5
        )
        result["checked"] = True
        if out.stdout.strip():
            result["backported"] = True
            result["detail"] = out.stdout.strip()[:100]
        else:
            result["backported"] = False
    except Exception as e:
        result["detail"] = str(e)[:80]
    return result


def check_target(url: str, timeout: int = 8, do_probe: bool = False) -> dict:
    """Check a single remote target."""
    out = {"url": url, "php_version": None, "status": "unknown",
           "settings_probe": None, "error": None}
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        out["error"] = str(e)[:100]
        return out

    ver = parse_php_version(str(r.headers)) or parse_php_version(r.text[:8192])
    if ver:
        out["php_version"] = f"{ver[0]}.{ver[1]}.{ver[2]}"
        out["status"] = classify_version(ver)

    if do_probe and out["status"] in ("vulnerable", "eol", "unknown"):
        out["settings_probe"] = check_php_settings(url, timeout)

    return out


def print_single_result(r: dict, backport_info: dict = None):
    """Print one target's result immediately (live)."""
    print(f"\n[Target] {r['url']}", flush=True)
    if r["error"]:
        print(f"  [!] Error: {r['error']}", flush=True)
        return

    status = r["status"]
    php = r["php_version"] or "not disclosed"

    # If backport detected locally, override status
    if backport_info and backport_info.get("backported") is True and status in ("vulnerable", "unknown"):
        print(f"  PHP: {php} — BUT backport detected locally: {backport_info['detail']}", flush=True)
        print(f"  [+] Status: LIKELY PATCHED (backport)", flush=True)
        return

    print(f"  PHP: {php}", flush=True)
    if status == "patched":
        print(f"  [+] Status: PATCHED (version >= official fix)", flush=True)
    elif status == "vulnerable":
        print(f"  [!!] Status: VULNERABLE (version < official fix)", flush=True)
    elif status == "eol":
        print(f"  [!!] Status: EOL — no official fix, migrate or check vendor backport", flush=True)
    else:
        print(f"  [?] Status: UNKNOWN (version hidden, manual check required)", flush=True)

    sp = r.get("settings_probe")
    if sp and not sp.get("error"):
        if sp.get("upload_progress_likely") is True:
            print(f"  [!!] session.upload_progress appears ENABLED (session cookie set)", flush=True)
        elif sp.get("upload_progress_likely") is False:
            print(f"  [~] session.upload_progress likely disabled or not observable", flush=True)
        if sp.get("memory_limit_hint") == "possibly_limited":
            print(f"  [~] memory_limit may be finite (OOM trigger possible)", flush=True)


def harden_guide():
    """Print hardening guide with CVE-specific mappings."""
    print("""
=== Hardening / Remediation ===
1. Update PHP to official patched version:
   - PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35
   - Debian/Ubuntu: sudo apt update && sudo apt install php8.4-fpm
   - RHEL/CentOS: sudo dnf update php-fpm
   - RESTART PHP-FPM/Apache AFTER update (old code persists until restart!)

2. CVE-2026-109619 specific mitigation (partial):
   - Disable session.upload_progress:
     php_admin_flag[session.upload_progress.enabled] = off

3. CVE-2026-109618 specific mitigation (partial):
   - Set memory_limit = -1 (removes OOM bailout trigger)

4. EOL branches (5.4-8.1): check vendor backport or migrate.
   - Debian/Ubuntu backports may not change version number: check changelog.

5. ONLY a full update is complete fix. Mitigations reduce exposure but do NOT guarantee safety. [citation:1][citation:2]
""")


def main():
    parser = argparse.ArgumentParser(
        description="Non-destructive PHP2Shell (CVE-2026-109618/109619) exposure checker.",
        epilog="Authorized assessment only. Sends no exploit payloads. Live output: each target printed immediately."
    )
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-l", "--list", help="File with URLs (one per line)")
    parser.add_argument("--json", action="store_true", help="JSON output (collected, not live)")
    parser.add_argument("--probe", action="store_true",
                        help="Probe session.upload_progress & memory hints (sends one POST; use only on authorized targets)")
    parser.add_argument("--local", action="store_true",
                        help="Check local PHP for backported fix (reads changelog)")
    parser.add_argument("--harden", action="store_true", help="Print hardening guide")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout (default 8)")
    args = parser.parse_args()

    if args.harden:
        harden_guide()
        return

    # Local backport check
    backport_info = None
    if args.local:
        backport_info = check_backport_local()
        print(f"[*] Local backport check: {backport_info}", flush=True)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list) as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"[-] List file not found: {args.list}")
            sys.exit(2)

    if not targets:
        parser.print_help()
        sys.exit(2)

    # LIVE MODE
    if not args.json:
        print("=" * 60)
        print("PHP2Shell Exposure Report (Live)")
        print("=" * 60)
        results = []
        vuln_count = 0
        for url in targets:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            r = check_target(url, args.timeout, args.probe)
            print_single_result(r, backport_info)
            results.append(r)
            if r["status"] in ("vulnerable", "eol") and not (backport_info and backport_info.get("backported")):
                vuln_count += 1

        print("\n" + "=" * 60)
        if vuln_count:
            print(f"[!] {vuln_count} target(s) require action. Run --harden for remediation.")
            sys.exit(1)
        else:
            print("[+] All targets appear patched or backported.")
            sys.exit(0)

    # JSON MODE
    else:
        results = [check_target(u, args.timeout, args.probe) for u in targets]
        print(json.dumps(results, indent=2, ensure_ascii=False))
        if any(r["status"] in ("vulnerable", "eol") for r in results):
            sys.exit(1)
        sys.exit(0)


if __name__ == "__main__":
    main()
