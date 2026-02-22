#!/usr/bin/env python3
"""
Master PoC Runner — Keycloak 26.5.4 Security Research
Runs all 6 PoC scripts sequentially and displays a summary table.
"""

import subprocess
import sys
import os
import time
import argparse
import urllib.parse

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

POCS = [
    {
        "file": "poc_f1_cors_bypass.py",
        "finding": "Finding #1",
        "title": "CORS OPTIONS Preflight Bypass",
        "severity": "MEDIUM",
    },
    {
        "file": "poc_f2_alg_none_npe.py",
        "finding": "Finding #2",
        "title": "alg:none JWT → HTTP 500 (NPE)",
        "severity": "MEDIUM",
    },
    {
        "file": "poc_f3_offline_token.py",
        "finding": "Finding #3",
        "title": "Offline Token Persistence",
        "severity": "HIGH",
    },
    {
        "file": "poc_f4_ssrf_idp.py",
        "finding": "Finding #4",
        "title": "SSRF + Open Redirect via IdP",
        "severity": "HIGH",
    },
    {
        "file": "poc_dcr_hijack.py",
        "finding": "Finding #5",
        "title": "DCR Trusted Hosts Bypass",
        "severity": "HIGH",
        "extra_args_template": True,  # needs attacker-host from parsed host
        "setup_script": "setup_dcr_admin.py",
    },
    {
        "file": "poc_f6_dcr_jwks_ssrf.py",
        "finding": "Finding #6",
        "title": "SSRF via DCR jwks_uri",
        "severity": "MEDIUM",
    },
]

def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   Keycloak 26.5.4 — Security Research PoC Suite                  ║
║   Master Runner: All 6 Findings                                  ║
║                                                                  ║
║   Researcher: Anggi Pradana                                      ║
║   Date: 2026-02-21                                               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")

def run_poc(poc_dir, poc_file, host, timeout=120, extra_args=None):
    """Run a single PoC script and return (exit_code, duration, output)."""
    script = os.path.join(poc_dir, poc_file)
    if not os.path.exists(script):
        return -1, 0.0, f"File not found: {script}"

    cmd = [sys.executable, script, "--host", host]
    if extra_args:
        cmd.extend(extra_args)
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=poc_dir,
        )
        duration = time.time() - start
        output = result.stdout + result.stderr
        return result.returncode, duration, output
    except subprocess.TimeoutExpired:
        duration = time.time() - start
        return -2, duration, "TIMEOUT"
    except Exception as e:
        duration = time.time() - start
        return -3, duration, str(e)

def severity_color(severity):
    if severity == "HIGH":
        return RED
    elif severity == "MEDIUM":
        return YELLOW
    return RESET

def main():
    parser = argparse.ArgumentParser(
        description="Master PoC Runner — Keycloak 26.5.4 Security Research")
    parser.add_argument("--host", default="http://46.101.162.187:8080",
                        help="Keycloak base URL (default: http://46.101.162.187:8080)")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Timeout per PoC in seconds (default: 120)")
    parser.add_argument("--only", type=int, nargs="+",
                        help="Run only specific findings (e.g., --only 1 3 5)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress individual PoC output (show summary only)")
    parser.add_argument("--setup", action="store_true",
                        help="Run admin setup scripts before PoCs that need them (e.g., F5)")
    args = parser.parse_args()

    # Derive attacker-host from --host URL for F5 (when running on KC server)
    parsed_host = urllib.parse.urlparse(args.host)
    attacker_ip = parsed_host.hostname or "46.101.162.187"

    banner()

    poc_dir = os.path.dirname(os.path.abspath(__file__))
    results = []

    # Filter PoCs if --only specified
    pocs_to_run = POCS
    if args.only:
        pocs_to_run = [p for i, p in enumerate(POCS, 1) if i in args.only]

    print(f"{CYAN}Target:{RESET} {args.host}")
    print(f"{CYAN}PoCs to run:{RESET} {len(pocs_to_run)}")
    print(f"{CYAN}Timeout:{RESET} {args.timeout}s per PoC")
    print()

    for i, poc in enumerate(pocs_to_run, 1):
        sev_c = severity_color(poc["severity"])
        print(f"{BOLD}{'━' * 70}{RESET}")
        print(f"{BOLD}  [{i}/{len(pocs_to_run)}] {poc['finding']}: {poc['title']}")
        print(f"  Severity: {sev_c}{poc['severity']}{RESET}")
        print(f"{BOLD}{'━' * 70}{RESET}")
        print()

        # Run setup script if --setup and poc has one
        if args.setup and poc.get("setup_script"):
            setup_script = os.path.join(poc_dir, poc["setup_script"])
            if os.path.exists(setup_script):
                print(f"  {CYAN}Running setup: {poc['setup_script']}...{RESET}")
                subprocess.run(
                    [sys.executable, setup_script, "--host", args.host],
                    capture_output=True, text=True, timeout=30, cwd=poc_dir)

        # Build extra_args — handle template for F5
        extra_args = poc.get("extra_args")
        if poc.get("extra_args_template"):
            extra_args = ["--attacker-host", attacker_ip, "--auto-victim", "--timeout", "30"]

        exit_code, duration, output = run_poc(poc_dir, poc["file"], args.host, args.timeout,
                                             extra_args=extra_args)

        if not args.quiet:
            # Print output with slight indent
            for line in output.split("\n"):
                print(f"  {line}")
            print()

        if exit_code == 0:
            status = "VULNERABLE"
            status_color = RED
        elif exit_code == 1:
            status = "NOT VULNERABLE"
            status_color = GREEN
        elif exit_code == -1:
            status = "FILE NOT FOUND"
            status_color = YELLOW
        elif exit_code == -2:
            status = "TIMEOUT"
            status_color = YELLOW
        else:
            status = f"ERROR (exit {exit_code})"
            status_color = YELLOW

        results.append({
            "finding": poc["finding"],
            "title": poc["title"],
            "severity": poc["severity"],
            "status": status,
            "status_color": status_color,
            "duration": duration,
            "exit_code": exit_code,
        })

        print(f"  {status_color}{BOLD}Result: {status}{RESET} ({duration:.1f}s)")
        print()

    # ── Final Summary Table ──
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║  FINAL RESULTS SUMMARY                                           ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")

    # Header
    print(f"  {'Finding':<12} {'Title':<35} {'Severity':<10} {'Result':<18} {'Time':<8}")
    print(f"  {'─' * 12} {'─' * 35} {'─' * 10} {'─' * 18} {'─' * 8}")

    vuln_count = 0
    for r in results:
        sev_c = severity_color(r["severity"])
        print(f"  {r['finding']:<12} {r['title']:<35} {sev_c}{r['severity']:<10}{RESET} "
              f"{r['status_color']}{r['status']:<18}{RESET} {r['duration']:.1f}s")
        if r["status"] == "VULNERABLE":
            vuln_count += 1

    print()
    total_time = sum(r["duration"] for r in results)
    print(f"  {BOLD}Total time: {total_time:.1f}s{RESET}")
    print()

    if vuln_count > 0:
        print(f"  {RED}{BOLD}[!] {vuln_count}/{len(results)} findings confirmed VULNERABLE{RESET}")
    else:
        print(f"  {GREEN}{BOLD}[+] No vulnerabilities confirmed{RESET}")

    print()
    print(f"{DIM}  Keycloak 26.5.4 | Researcher: Anggi Pradana | {time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print()

    # Return 0 if any vulnerability found (success for security research)
    return 0 if vuln_count > 0 else 1

if __name__ == "__main__":
    sys.exit(main())
