#!/bin/bash
BASE="http://localhost:8080"

get_token() {
  curl -s -X POST "$BASE/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=Admin1234&grant_type=password&client_id=admin-cli" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['access_token'])"
}

TOKEN=$(get_token)
echo "[*] Got admin token"

# Create test realm
curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/realms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "test",
    "enabled": true,
    "registrationAllowed": true,
    "sslRequired": "none",
    "bruteForceProtected": false,
    "duplicateEmailsAllowed": false
  }' | xargs -I{} echo "[*] Create realm test: HTTP {}"

TOKEN=$(get_token)

# Create confidential client (code flow with secret)
curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/realms/test/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "test-confidential",
    "enabled": true,
    "publicClient": false,
    "secret": "mysecret123",
    "redirectUris": [
      "https://legitimate-app.com/callback",
      "https://legitimate-app.com/oauth/callback"
    ],
    "webOrigins": ["https://legitimate-app.com"],
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "protocol": "openid-connect",
    "implicitFlowEnabled": false
  }' | xargs -I{} echo "[*] Create confidential client: HTTP {}"

TOKEN=$(get_token)

# Create public client  
curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/realms/test/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "test-public",
    "enabled": true,
    "publicClient": true,
    "redirectUris": [
      "https://legitimate-app.com/callback",
      "http://localhost:3000/callback"
    ],
    "webOrigins": ["https://legitimate-app.com", "http://localhost:3000"],
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": false,
    "protocol": "openid-connect"
  }' | xargs -I{} echo "[*] Create public client: HTTP {}"

TOKEN=$(get_token)

# Create test user
curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/realms/test/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "testuser@example.com",
    "enabled": true,
    "credentials": [{"type":"password","value":"Password123","temporary":false}]
  }' | xargs -I{} echo "[*] Create test user: HTTP {}"

TOKEN=$(get_token)

# Create second user (victim)
curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/realms/test/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "victim",
    "email": "victim@example.com",
    "enabled": true,
    "credentials": [{"type":"password","value":"Password123","temporary":false}]
  }' | xargs -I{} echo "[*] Create victim user: HTTP {}"

echo "[+] Setup complete"
echo "[+] Keycloak: http://46.101.162.187:8080"
echo "[+] Admin Console: http://46.101.162.187:8080/admin"
echo "[+] Test realm: http://46.101.162.187:8080/realms/test"
