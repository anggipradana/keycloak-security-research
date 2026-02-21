# Keycloak 26.5.4 — PoC Execution Guide (Video Recording)

**Researcher:** Anggi Pradana
**Date:** 2026-02-21
**Target:** Keycloak 26.5.4 on `http://46.101.162.187:8080`

---

## Prerequisites

### Environment
- Python 3.8+ (stdlib only — no pip install needed)
- SSH access to the VPS: `ssh anggi@46.101.162.187`
- Keycloak 26.5.4 running on port 8080

### Start Keycloak (if not running)
```bash
cd /home/anggi/keycloak-research
bash start-keycloak.sh
# Wait ~30 seconds for startup
curl -s http://localhost:8080/realms/test | python3 -m json.tool | head -3
```

### Verify Test Environment
```bash
# Check Keycloak is up
curl -s http://localhost:8080/realms/test/.well-known/openid-configuration | python3 -c "import sys,json; print(json.load(sys.stdin)['issuer'])"

# Check test user exists
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users?username=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['username'])"
```

---

## Quick Run: All PoCs at Once

```bash
cd /home/anggi/keycloak-research
python3 pocs/run_all_pocs.py --host http://localhost:8080
```

This runs all 6 PoCs sequentially and shows a summary table at the end.

### Options
```bash
# Run specific findings only
python3 pocs/run_all_pocs.py --only 1 2 3

# Quiet mode (summary only)
python3 pocs/run_all_pocs.py --quiet

# Custom target
python3 pocs/run_all_pocs.py --host http://your-keycloak:8080
```

---

## Individual PoC Execution

### Finding #1: CORS OPTIONS Preflight Bypass (MEDIUM)

**What it shows:** `webOrigins` client configuration is not enforced for OPTIONS preflight requests.

**Run:**
```bash
python3 pocs/poc_f1_cors_bypass.py --host http://localhost:8080
```

**What to show on screen:**
1. The script verifies `webOrigins` is configured to `["https://legitimate-app.com"]`
2. OPTIONS from `https://evil.com` gets `Access-Control-Allow-Origin: https://evil.com` (BYPASS)
3. OPTIONS from `null` also reflected (sandboxed iframe attack)
4. Admin API preflight also bypassed
5. Control: actual POST correctly has NO ACAO header

**Expected output highlights:**
```
[!] VULNERABLE — evil.com reflected with credentials:true!
[!] VULNERABLE — null origin reflected! (sandboxed iframe bypass)
[!] VULNERABLE — admin API preflight bypassed!
[+] Actual response correctly has NO ACAO header (browser blocks reading)
```

**Duration:** ~5 seconds

---

### Finding #2: alg:none JWT → HTTP 500 (MEDIUM)

**What it shows:** JWT with `"alg":"none"` causes unhandled NullPointerException on all Bearer-authenticated endpoints.

**Run:**
```bash
python3 pocs/poc_f2_alg_none_npe.py --host http://localhost:8080
```

**What to show on screen:**
1. Script crafts a JWT with `{"alg":"none","typ":"JWT"}` — no authentication needed
2. Sends to `/userinfo` → HTTP 500 (should be 401)
3. Sends to `/admin/users` → HTTP 500
4. Sends to `/admin/clients` → HTTP 500
5. Control: random string → HTTP 401 (correct)
6. Control: wrong-sig JWT → HTTP 401 (correct)

**Expected output highlights:**
```
[!] VULNERABLE — HTTP 500 returned instead of 401!
[!] Server threw NullPointerException in JWT validation pipeline
[+] Control test passed — random string returns 401 correctly
```

**Duration:** ~3 seconds

---

### Finding #3: Offline Token Persistence (HIGH)

**What it shows:** Offline tokens survive admin force-logout and push-revocation; admin API cannot delete them.

**Run:**
```bash
python3 pocs/poc_f3_offline_token.py --host http://localhost:8080
```

**What to show on screen:**
1. Attacker obtains offline token with compromised credentials
2. Verifies token works (baseline)
3. Admin forces logout of ALL user sessions → HTTP 204 (success)
4. Offline token STILL WORKS after logout
5. Admin pushes not-before revocation
6. Offline token STILL WORKS after push-revocation
7. Admin tries to DELETE offline sessions → HTTP 404 (fails!)
8. Offline sessions still exist in the system

**Expected output highlights:**
```
[!] VULNERABLE — Offline token STILL WORKS after force-logout!
[!] VULNERABLE — Offline token STILL WORKS after push-revocation!
[!] Admin API returns 404 — cannot delete offline sessions!
```

**Duration:** ~10 seconds

---

### Finding #4: SSRF + Open Redirect via IdP (HIGH)

**What it shows:** Three attack paths via Identity Provider configuration.

**Run:**
```bash
python3 pocs/poc_f4_ssrf_idp.py --host http://localhost:8080 --listen-port 49990
```

**What to show on screen:**
1. **Path A:** GET SSRF via `import-config` — Keycloak fetches attacker's URL server-side
2. **Path B:** Open redirect via `kc_idp_hint` — victim redirected to evil.com from trusted Keycloak URL
3. **Path C:** POST SSRF via `tokenUrl` — Keycloak POSTs auth data to internal address

**Expected output highlights:**
```
[!] SSRF CONFIRMED: GET /.well-known/openid-configuration
    User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.10)
[!] VULNERABLE — Victim redirected to evil.com from trusted Keycloak URL!
[!] POST SSRF CONFIRMED: POST /token
```

**Duration:** ~15 seconds

**Note:** The PoC starts its own HTTP listener to capture SSRF requests. Ensure port 49990 is available.

---

### Finding #5: DCR Trusted Hosts Bypass (HIGH)

**What it shows:** Authenticated DCR bypasses Trusted Hosts policy; attacker steals victim's tokens.

**Run:**
```bash
python3 pocs/poc_f5_dcr_hijack.py --host http://localhost:8080
```

**What to show on screen:**
1. Attacker gets token with low-privilege account
2. Registers malicious OIDC client with `redirect_uri: https://evil.com/steal` (NO rejection!)
3. Control: Anonymous DCR correctly blocked by Trusted Hosts
4. Control: Admin API correctly returns 403 — privilege gap confirmed
5. Victim clicks auth URL → logs in on legitimate Keycloak page
6. Auth code redirected to evil.com
7. Attacker exchanges code for victim's tokens — full identity theft

**Expected output highlights:**
```
[!] VULNERABLE — Malicious client registered with NO Trusted Hosts rejection!
[+] Anonymous DCR correctly blocked: "Policy 'Trusted Hosts' rejected request..."
[!] Auth code sent to evil.com!
[!] TOKEN THEFT SUCCESSFUL!
    Username:      victim
    Email:         victim@test.com
```

**Duration:** ~10 seconds

---

### Finding #6: SSRF via DCR jwks_uri (MEDIUM)

**What it shows:** Low-privilege user triggers SSRF by registering a client with arbitrary `jwks_uri`.

**Run:**
```bash
python3 pocs/poc_f6_dcr_jwks_ssrf.py --host http://localhost:8080 --listen-port 49997
```

**What to show on screen:**
1. Attacker gets token (low-privilege)
2. Registers DCR client with `jwks_uri` pointing to attacker-controlled listener
3. Triggers JWKS fetch via JWT client authentication
4. HTTP listener captures Keycloak's server-side request
5. Port scanning demonstration via timing analysis

**Expected output highlights:**
```
[!] SSRF CONFIRMED: GET /internal-jwks
    Host: 46.101.162.187:49997
    User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.10)
```

**Duration:** ~15 seconds

**Note:** The PoC starts its own HTTP listener. Ensure port 49997 is available.

---

## Video Recording Tips

### Terminal Setup
```bash
# Set a clean terminal
clear
# Use a large font (if recording terminal)
# Recommended: 18-20pt monospace font, dark background

# Optional: set PS1 for clean prompt
export PS1='\[\033[01;32m\]anggi@keycloak\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
```

### Recording Order (Recommended)
1. Show Keycloak version: `curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; d=json.load(sys.stdin); print('Keycloak realm:', d['realm'])"`
2. Run all PoCs with master runner: `python3 pocs/run_all_pocs.py`
3. Or run individually for detailed walkthrough per finding
4. End with summary table from master runner

### Screen Layout
- **Full screen terminal** — the PoC scripts have colorful output designed for dark backgrounds
- ANSI colors are used: red for vulnerabilities, green for passing tests, yellow for info, cyan for steps

---

## File Reference

| File | Description |
|---|---|
| `pocs/poc_f1_cors_bypass.py` | Finding #1: CORS preflight bypass |
| `pocs/poc_f2_alg_none_npe.py` | Finding #2: alg:none JWT NPE |
| `pocs/poc_f3_offline_token.py` | Finding #3: Offline token persistence |
| `pocs/poc_f4_ssrf_idp.py` | Finding #4: SSRF + open redirect via IdP |
| `pocs/poc_f5_dcr_hijack.py` | Finding #5: DCR trusted hosts bypass |
| `pocs/poc_f6_dcr_jwks_ssrf.py` | Finding #6: SSRF via DCR jwks_uri |
| `pocs/run_all_pocs.py` | Master runner — all 6 PoCs |
| `findings/finding-1-cors-preflight-bypass-MEDIUM.md` | Finding #1 report |
| `findings/finding-2-alg-none-npe-MEDIUM.md` | Finding #2 report |
| `findings/finding-3-offline-token-persistence-HIGH.md` | Finding #3 report |
| `findings/finding-4-ssrf-open-redirect-idp-HIGH.md` | Finding #4 report |
| `findings/finding-5-dcr-trusted-hosts-bypass-HIGH.md` | Finding #5 report |
| `findings/finding-6-ssrf-dcr-jwks-uri-MEDIUM.md` | Finding #6 report |
| `VALIDATED_FINDINGS.md` | Complete findings document |
| `REPORT.md` | Bug bounty submission format |

---

## Troubleshooting

### Keycloak not responding
```bash
# Check if running
curl -s http://localhost:8080/realms/master 2>&1 | head -1

# Restart if needed
pkill -f keycloak
bash /home/anggi/keycloak-research/start-keycloak.sh
sleep 30
```

### Port already in use (for F4/F6 listeners)
```bash
# Kill process on port
fuser -k 49990/tcp
fuser -k 49997/tcp
```

### Token expired errors
The PoC scripts obtain fresh admin tokens for each step. If you see token errors, ensure the admin password is correct (`Admin1234`).

### Offline token test (F3) — token already revoked
If a previous run changed the user's password, reset it:
```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users?username=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"password","temporary":false,"value":"Password123"}' \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/reset-password"
```
