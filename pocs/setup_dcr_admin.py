#!/usr/bin/env python3
"""
DCR Trusted Hosts Bypass — Admin Setup Script
One-time environment preparation (NOT part of the attack).

Creates testuser + victim users and assigns create-client role to testuser.
Run this on the Keycloak server or any machine with admin access.

Usage:
  python3 setup_dcr_admin.py --host http://localhost:8080
  python3 setup_dcr_admin.py --host http://46.101.162.187:8080
"""

import http.client
import json
import argparse
import sys
import urllib.parse

# ═══ ANSI Colors ═══
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


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


def http_put_json(host, port, path, data, token=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("PUT", path, json.dumps(data), headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    status = resp.status
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"_raw": raw}


def create_user_if_missing(host, port, realm, token, username, password, email, first, last):
    """Create a user if they don't already exist. Returns user ID."""
    _, users = http_get_json(host, port,
        f"/admin/realms/{realm}/users?username={username}&exact=true", token)

    if isinstance(users, list) and len(users) > 0:
        uid = users[0]["id"]
        info(f"User '{username}' already exists (ID: {uid})")
        return uid

    user_data = {
        "username": username,
        "email": email,
        "firstName": first,
        "lastName": last,
        "enabled": True,
        "emailVerified": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}]
    }
    status, resp = http_post_json(host, port, f"/admin/realms/{realm}/users", user_data, token)

    if status == 201 or status == 409:
        # 201 = created, 409 = already exists (race condition)
        _, users = http_get_json(host, port,
            f"/admin/realms/{realm}/users?username={username}&exact=true", token)
        if isinstance(users, list) and len(users) > 0:
            uid = users[0]["id"]
            success(f"User '{username}' created (ID: {uid})")
            return uid

    fail(f"Failed to create user '{username}' (HTTP {status}): {resp}")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="DCR Trusted Hosts Bypass — Admin Setup (create users and assign create-client role)")
    parser.add_argument("--host", default="http://localhost:8080",
                        help="Keycloak admin URL (default: http://localhost:8080)")
    parser.add_argument("--realm", default="test",
                        help="Target realm (default: test)")
    parser.add_argument("--admin-user", default="admin",
                        help="Admin username (default: admin)")
    parser.add_argument("--admin-pass", default="Admin1234",
                        help="Admin password (default: Admin1234)")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.host)
    host = parsed.hostname
    port = parsed.port or 8080
    realm = args.realm

    print(f"\n{BOLD}{CYAN}[Setup] DCR Trusted Hosts Bypass — Admin Environment Preparation{RESET}")
    info(f"Keycloak: {host}:{port}")
    info(f"Realm: {realm}")

    # Step 1: Get admin token
    info("Getting admin token...")
    status, data = http_post_form(host, port,
        "/realms/master/protocol/openid-connect/token",
        {"client_id": "admin-cli", "grant_type": "password",
         "username": args.admin_user, "password": args.admin_pass})

    admin_token = data.get("access_token", "")
    if not admin_token:
        fail(f"Failed to get admin token: {data}")
        return 1
    success("Admin token OK")

    # Step 2: Create testuser (attacker)
    info("Ensuring testuser exists...")
    testuser_id = create_user_if_missing(
        host, port, realm, admin_token,
        "testuser", "Password123", "testuser@test.com", "Test", "User")
    if not testuser_id:
        return 1

    # Step 3: Create victim user
    info("Ensuring victim user exists...")
    victim_id = create_user_if_missing(
        host, port, realm, admin_token,
        "victim", "Password123", "victim@test.com", "Victim", "User")
    if not victim_id:
        return 1

    # Step 4: Assign create-client role to testuser
    info("Assigning create-client role to testuser...")

    _, rm_clients = http_get_json(host, port,
        f"/admin/realms/{realm}/clients?clientId=realm-management", admin_token)
    if not isinstance(rm_clients, list) or len(rm_clients) == 0:
        fail("realm-management client not found!")
        return 1
    rm_client_id = rm_clients[0]["id"]

    _, create_role = http_get_json(host, port,
        f"/admin/realms/{realm}/clients/{rm_client_id}/roles/create-client", admin_token)
    if not isinstance(create_role, dict) or "id" not in create_role:
        fail(f"create-client role not found: {create_role}")
        return 1

    status, _ = http_post_json(host, port,
        f"/admin/realms/{realm}/users/{testuser_id}/role-mappings/clients/{rm_client_id}",
        [create_role], admin_token)
    # 204 = success, 409 = already assigned
    if status in (204, 409):
        success("create-client role assigned to testuser")
    else:
        # Check if already assigned by listing current mappings
        _, current = http_get_json(host, port,
            f"/admin/realms/{realm}/users/{testuser_id}/role-mappings/clients/{rm_client_id}",
            admin_token)
        if isinstance(current, list) and any(r.get("name") == "create-client" for r in current):
            success("create-client role already assigned to testuser")
        else:
            warn(f"Role assignment returned HTTP {status} (may already be assigned)")

    # Step 5: Ensure webapp client exists (public client for attacker login)
    info("Checking webapp client...")
    _, webapp_clients = http_get_json(host, port,
        f"/admin/realms/{realm}/clients?clientId=webapp", admin_token)
    if isinstance(webapp_clients, list) and len(webapp_clients) > 0:
        success("webapp client exists")
    else:
        warn("webapp client not found — attacker login may fail. Create it in Admin Console.")

    print(f"\n{GREEN}{BOLD}[+] Setup complete!{RESET}")
    print(f"    Attacker user : testuser / Password123 (has create-client role)")
    print(f"    Victim user   : victim / Password123")
    print(f"    Realm         : {realm}")
    print(f"\n    Now run the attack from any machine:")
    print(f"    python3 poc_dcr_hijack.py --host {args.host} --attacker-host <YOUR_IP>")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
