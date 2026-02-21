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
| 1 | [CORS webOrigins Bypass — Cross-Origin Token Theft](#finding-1) | **HIGH** | 8.1 |
| 2 | [alg:none JWT causes HTTP 500 (NullPointerException)](#finding-2) | **MEDIUM** | 5.3 |

---

## Finding #1 — CORS webOrigins Bypass {#finding-1}

**Type:** CORS with real security impact
**Affected:** `/token`, `/userinfo`, `/account`, `/admin/*`

Keycloak reflects **any arbitrary `Origin` header** with `Access-Control-Allow-Credentials: true` on all OIDC endpoints, completely ignoring the per-client `webOrigins` allowlist. This allows any website to make credentialed cross-origin requests and read authenticated responses — including full `access_token`, `refresh_token`, and `id_token`.

The `null` origin variant (sandboxed iframe / `data:` URI) is also fully allowed.

**Quick reproduction:**
```bash
# Client webapp has webOrigins: ["https://legitimate-app.com"]
# evil.com is NOT in webOrigins — should be blocked
curl -X POST http://<KC_HOST>/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=webapp&username=testuser&password=Password123&scope=openid"

# Returns ACAO: https://evil.com + Access-Control-Allow-Credentials: true
# Full access_token, refresh_token, id_token readable cross-origin
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

## PoC Files

| File | Description |
|---|---|
| [`pocs/poc1_cors_token_hijack.html`](pocs/poc1_cors_token_hijack.html) | Browser PoC — CORS cross-origin token theft |
| [`pocs/poc2_cors_null_origin.html`](pocs/poc2_cors_null_origin.html) | Browser PoC — `null`-origin sandboxed iframe attack |
| [`pocs/poc3_alg_none_npe.py`](pocs/poc3_alg_none_npe.py) | Python PoC — alg:none → HTTP 500 |

## Full Report

See [`REPORT.md`](REPORT.md) for the complete bug bounty submission document including:
- Detailed technical description
- Step-by-step reproduction with HTTP requests/responses
- Attack scenarios
- Security impact analysis
- Remediation recommendations

---

*This research is conducted under the Keycloak bug bounty program on a private, researcher-controlled environment. No production systems or real user data were accessed.*
