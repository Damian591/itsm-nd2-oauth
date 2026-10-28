"""Automated security test log (step 12).

Runs inside the app container, which trusts the mkcert CA and reaches every
service through Caddy over HTTPS, the same way a browser does:

    Get-Content tests\\scripts\\security_tests.py | docker compose exec -T app python -

Before running:
  * sign in at https://app.itsm.test as alice and as bob (two browsers or a
    normal + private window), optionally also as admin1;
  * wait at least 1 minute after a previous run (the last test trips the
    /login rate limit on purpose).

The API and session tests use the signed-in users' server-side sessions from
Redis, i.e. they act like an attacker who has stolen a token or a cookie.
Afterwards alice and bob have to sign in again: the script signs bob out and
uses alice's refresh token on purpose.

Tokens, cookies and passwords are never printed.
Each line: PASS / FAIL / SKIP, test id, what was tested.
"""
import base64
import email.utils
import hashlib
import html
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import warnings

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

warnings.filterwarnings("ignore", category=DeprecationWarning)  # T3/T4 use old TLS versions on purpose
sys.path.insert(0, "/srv")
import app as webapp  # noqa: E402  the app's own Redis connection and session format

APP = "https://app.itsm.test"
API = "https://api.itsm.test"
AUTH = "https://auth.itsm.test"
ISSUER = os.environ["OIDC_ISSUER"]
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
CA_FILE = os.environ["SSL_CERT_FILE"]
COOKIE = "__Host-session"
TIMEOUT = 10

results = []


def record(test_id, name, ok, detail=""):
    """Print and remember one result. ok: True = PASS, False = FAIL, None = SKIP."""
    status = {True: "PASS", False: "FAIL", None: "SKIP"}[ok]
    results.append((test_id, status, name))
    print(f"{status}  {test_id:<4} {name}" + (f"  [{detail}]" if detail else ""))


def section(title):
    print(f"\n== {title} ==")


def get(url, **kw):
    return requests.get(url, allow_redirects=False, timeout=TIMEOUT, **kw)


def post(url, **kw):
    return requests.post(url, allow_redirects=False, timeout=TIMEOUT, **kw)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def claims_of(token):
    return jwt.decode(token, options={"verify_signature": False})


def cookie_value(set_cookie):
    m = re.match(rf"{COOKIE}=([^;]*)", set_cookie or "")
    return m.group(1) if m else None


# --- Server-side sessions (Redis) --------------------------------------------
rdb = webapp.rdb
iface = webapp.app.session_interface
PREFIX = iface.key_prefix


def load_session(sid):
    raw = rdb.get(PREFIX + sid)
    if raw is None:
        return None
    return iface.serializer.decode(raw)


def find_session(username):
    """Return (sid, data) of the newest app session of a user, or None."""
    best = None
    for key in rdb.scan_iter(PREFIX + "*"):
        sid = key.decode()[len(PREFIX):]
        try:
            data = load_session(sid) or {}
        except Exception:
            continue
        if (data.get("user") or {}).get("username") != username:
            continue
        if best is None or data.get("created_at", 0) > best[1].get("created_at", 0):
            best = (sid, data)
    return best


def fresh_session(username):
    """Load the user's page once (the app refreshes the access token if needed), then read the session."""
    found = find_session(username)
    if found:
        get(f"{APP}/", cookies={COOKIE: found[0]})
        found = find_session(username)
    return found


# --- Keycloak helpers ---------------------------------------------------------
meta = requests.get(f"{ISSUER}/.well-known/openid-configuration", timeout=TIMEOUT).json()


def auth_params(**overrides):
    verifier = secrets.token_urlsafe(48)
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": f"{APP}/callback",
        "scope": "openid",
        "state": secrets.token_urlsafe(16),
        "nonce": secrets.token_urlsafe(16),
        "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v is not None}


def refresh(refresh_token, scope=None):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if scope:
        data["scope"] = scope
    return post(meta["token_endpoint"], auth=(CLIENT_ID, CLIENT_SECRET), data=data)


def login_error_message(username):
    """Submit a wrong password on the Keycloak login form and return the error text shown."""
    s = requests.Session()
    page = s.get(meta["authorization_endpoint"], params=auth_params(), timeout=TIMEOUT)
    form = re.search(r'<form\b[^>]*\bid="kc-form-login"[^>]*>', page.text)
    action = re.search(r'\baction="([^"]+)"', form.group(0)) if form else None
    if not action:
        return None
    resp = s.post(html.unescape(action.group(1)), timeout=TIMEOUT, allow_redirects=False,
                  data={"username": username, "password": "wrong-" + secrets.token_hex(8),
                        "credentialId": ""})
    m = re.search(r'id="input-error[^"]*"[^>]*>(.*?)</span>', resp.text, re.S)
    return html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else None


def api(method, path, token=None, **kw):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return requests.request(method, f"{API}{path}", headers=headers, timeout=TIMEOUT, **kw)


# ==============================================================================
print(f"Security test run {time.strftime('%Y-%m-%d %H:%M:%S')}")
if get(f"{APP}/login").status_code == 429:
    sys.exit("The /login rate limit from the previous run is still active. Wait 1 minute and run again.")

users = {name: fresh_session(name) for name in ("alice", "bob", "admin1")}
for name, found in users.items():
    print(f"  {name}: {'signed in' if found else 'no session (some tests will be skipped)'}")


# --- 1. Transport security ----------------------------------------------------
section("1. Transport security (ASVS V12)")

bad = []
for host in ("app.itsm.test", "api.itsm.test", "auth.itsm.test"):
    r = get(f"http://{host}/")
    if r.status_code not in (301, 308) or not r.headers.get("Location", "").startswith(f"https://{host}"):
        bad.append(f"{host}: {r.status_code}")
record("T1", "HTTP is redirected to HTTPS on all three hosts", not bad, ", ".join(bad))


def tls_handshake(version):
    ctx = ssl.create_default_context(cafile=CA_FILE)
    ctx.minimum_version = ctx.maximum_version = version
    if version < ssl.TLSVersion.TLSv1_2:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # let the client offer old versions at all
    with socket.create_connection(("app.itsm.test", 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname="app.itsm.test") as tls:
            return tls.version()


try:
    ok = tls_handshake(ssl.TLSVersion.TLSv1_3) == "TLSv1.3" and tls_handshake(ssl.TLSVersion.TLSv1_2) == "TLSv1.2"
    record("T2", "TLS 1.3 and TLS 1.2 are accepted", ok)
except ssl.SSLError as exc:
    record("T2", "TLS 1.3 and TLS 1.2 are accepted", False, exc.reason)

for test_id, label, version in (("T3", "TLS 1.1", ssl.TLSVersion.TLSv1_1), ("T4", "TLS 1.0", ssl.TLSVersion.TLSv1)):
    name = f"{label} is refused by the server"
    try:
        record(test_id, name, False, f"handshake succeeded: {tls_handshake(version)}")
    except ssl.SSLError as exc:
        text = str(exc).upper()
        # A refusal by the server comes as a TLS alert; anything else means our own client couldn't try.
        if "ALERT" not in text and ("NO_PROTOCOLS_AVAILABLE" in text or "UNSUPPORTED_PROTOCOL" in text):
            record(test_id, name, None, f"client could not offer this version: {exc.reason}")
        else:
            record(test_id, name, True, exc.reason)
    except OSError as exc:
        record(test_id, name, True, type(exc).__name__)

EXPECTED_HEADERS = {
    f"{APP}/": {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin",
                "Permissions-Policy": "camera=()"},
    f"{API}/health": {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'none'",
                      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"},
    f"{ISSUER}/.well-known/openid-configuration": {"Strict-Transport-Security": "max-age=31536000",
                                                   "X-Content-Type-Options": "nosniff",
                                                   "Referrer-Policy": "no-referrer"},
}
for test_id, (url, expected) in zip(("T5", "T6", "T7"), EXPECTED_HEADERS.items()):
    r = get(url)
    missing = [h for h, v in expected.items() if v not in r.headers.get(h, "")]
    if "Server" in r.headers:
        missing.append(f"Server header present ({r.headers['Server']})")
    host = url.split("/")[2]
    record(test_id, f"Security headers on {host} (HSTS, CSP, nosniff, Referrer-Policy, no Server)",
           not missing, ", ".join(missing))

bad = [u for u in (f"{APP}/", f"{API}/health", f"{API}/notes")
       if "no-store" not in get(u).headers.get("Cache-Control", "")]
record("T8", "Cache-Control: no-store on app and API responses", not bad, ", ".join(bad))


# --- 2. Session cookie and login entry points -----------------------------------
section("2. Session cookie, login and CSRF (ASVS V7, V3, V10)")

r = get(f"{APP}/login")
set_cookie = r.headers.get("Set-Cookie", "")
attrs = [a.strip().lower() for a in set_cookie.split(";")]
problems = []
if not set_cookie.startswith(f"{COOKIE}="):
    problems.append("no __Host-session cookie")
for flag in ("secure", "httponly", "samesite=lax", "path=/"):
    if flag not in attrs:
        problems.append(f"missing {flag}")
if any(a.startswith("domain=") for a in attrs):
    problems.append("has Domain")
record("S1", "Session cookie: __Host- prefix, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain",
       not problems, ", ".join(problems))

expires = next((a for a in set_cookie.split(";") if a.strip().lower().startswith("expires=")), None)
if expires:
    lifetime = email.utils.parsedate_to_datetime(expires.split("=", 1)[1].strip()).timestamp() - time.time()
    record("S2", "Session cookie expires after 30 min idle (same as Keycloak SSO Session Idle)",
           1700 <= lifetime <= 1900, f"{int(lifetime)} s")
else:
    record("S2", "Session cookie expires after 30 min idle", False, "no Expires attribute")

planted = "fixation-" + secrets.token_hex(8)
r = get(f"{APP}/login", cookies={COOKIE: planted})
new_sid = cookie_value(r.headers.get("Set-Cookie"))
record("S3", "Session fixation: a session id chosen by the attacker is not accepted",
       new_sid is not None and new_sid != planted)

accepted = []
for target in ("//evil.example", "https://evil.example", "/\\evil.example", "/\t/evil.example",
               "/notes?x=1"):
    r = get(f"{APP}/login", params={"next": target})
    data = load_session(cookie_value(r.headers.get("Set-Cookie")) or "") or {}
    expected = target if target == "/notes?x=1" else "/"   # a real local path must still work
    if data.get("next") != expected:
        accepted.append(repr(target))
record("S4", "Open redirect: /login?next= accepts only local paths", not accepted,
       f"wrong result for: {', '.join(accepted)}" if accepted else "")

s = requests.Session()
s.get(f"{APP}/login", allow_redirects=False, timeout=TIMEOUT)
r = s.get(f"{APP}/callback", params={"code": "stolen-code", "state": "forged-state"},
          allow_redirects=False, timeout=TIMEOUT)
record("S5", "OAuth callback with a forged state is rejected (login CSRF)", r.status_code == 400,
       f"HTTP {r.status_code}")

r = s.post(f"{APP}/notes", data={"title": "csrf test", "body": "x"}, allow_redirects=False, timeout=TIMEOUT)
record("S6", "Form POST without a CSRF token is rejected", r.status_code == 400, f"HTTP {r.status_code}")


# --- 3. Keycloak / OAuth configuration ------------------------------------------
section("3. Authorization server (ASVS V10, V6)")

r = get(meta["authorization_endpoint"], params=auth_params(redirect_uri="https://evil.example/callback"))
record("K1", "Unregistered redirect_uri is rejected", r.status_code == 400 and "redirect_uri" in r.text,
       f"HTTP {r.status_code}")

for test_id, name, overrides in (
        ("K2", "PKCE is required (request without code_challenge)", {"code_challenge": None, "code_challenge_method": None}),
        ("K3", "PKCE method 'plain' is refused, only S256", {"code_challenge": secrets.token_urlsafe(48),
                                                             "code_challenge_method": "plain"})):
    loc = get(meta["authorization_endpoint"], params=auth_params(**overrides)).headers.get("Location", "")
    record(test_id, name, loc.startswith(f"{APP}/callback") and "error=invalid_request" in loc,
           re.search(r"error=[^&#]+", loc).group(0) if "error=" in loc else "no error returned")

loc = get(meta["authorization_endpoint"], params=auth_params(response_type="token")).headers.get("Location", "")
record("K4", "Implicit flow (response_type=token) is disabled", "error=" in loc and "access_token=" not in loc,
       re.search(r"error=[^&#]+", loc).group(0) if "error=" in loc else "no error returned")

r = post(meta["token_endpoint"], auth=(CLIENT_ID, CLIENT_SECRET),
         data={"grant_type": "password", "username": "alice", "password": "not-the-password"})
err = r.json().get("error") if r.headers.get("Content-Type", "").startswith("application/json") else r.status_code
record("K5", "Password grant (direct access) is disabled for webapp", err == "unauthorized_client", str(err))

r = post(meta["token_endpoint"], auth=(CLIENT_ID, "wrong-secret"), data={"grant_type": "client_credentials"})
record("K6", "Wrong client secret is rejected", r.status_code == 401, f"HTTP {r.status_code}")

msg_real = login_error_message("alice")
msg_fake = login_error_message("no-such-user-" + secrets.token_hex(4))
if msg_real is None or msg_fake is None:
    record("K7", "Same login error for existing and unknown users (no enumeration)", None,
           "could not read the error text from the login page")
else:
    record("K7", "Same login error for existing and unknown users (no enumeration)", msg_real == msg_fake,
           f"'{msg_real}' / '{msg_fake}'")

r = get(f"{ISSUER}/protocol/openid-connect/registrations", params=auth_params())
open_registration = r.status_code == 200 and "kc-register-form" in r.text
record("K8", "Self-registration is disabled", not open_registration,
       "anyone can create an account" if open_registration else f"HTTP {r.status_code}")


# --- 4. Notes API -------------------------------------------------------------
section("4. Notes API: tokens and access control (ASVS V8, V9)")

alice, bob, admin1 = users["alice"], users["bob"], users["admin1"]
if not alice:
    print("SKIP  API tests: sign in as alice first")
else:
    a_tokens = alice[1]["tokens"]
    a_at = a_tokens["access_token"]

    r = api("GET", "/notes", a_at)
    record("A1", "Valid access token is accepted (control)", r.status_code == 200, f"HTTP {r.status_code}")

    r = api("GET", "/notes")
    record("A2", "No token -> 401 with WWW-Authenticate: Bearer",
           r.status_code == 401 and r.headers.get("WWW-Authenticate", "").startswith("Bearer"), f"HTTP {r.status_code}")

    r = api("GET", "/notes", "not.a.jwt")
    record("A3", "Malformed token -> 401", r.status_code == 401, f"HTTP {r.status_code}")

    header = jwt.get_unverified_header(a_at)
    forged = jwt.encode(claims_of(a_at), None, algorithm="none", headers={"kid": header.get("kid")})
    r = api("GET", "/notes", forged)
    record("A4", "Unsigned token (alg=none) -> 401", r.status_code == 401, f"HTTP {r.status_code}")

    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(claims_of(a_at), attacker_key, algorithm="RS256", headers={"kid": header.get("kid")})
    r = api("GET", "/notes", forged)
    record("A5", "Token signed with an attacker's key (real kid) -> 401", r.status_code == 401, f"HTTP {r.status_code}")

    head, payload, sig = a_at.split(".")
    changed = claims_of(a_at)
    changed["sub"] = (bob[1]["user"]["sub"] if bob else "00000000-0000-0000-0000-000000000000")
    changed["scope"] = changed.get("scope", "") + " admin"
    tampered = ".".join((head, b64url(json.dumps(changed).encode()), sig))
    r = api("GET", "/notes", tampered)
    record("A6", "Token with modified claims (sub, scope) -> 401", r.status_code == 401, f"HTTP {r.status_code}")

    r = api("GET", "/notes", a_tokens.get("id_token"))
    record("A7", "ID token used as access token -> 401", r.status_code == 401, f"HTTP {r.status_code}")

    r = api("GET", "/notes", a_tokens.get("refresh_token"))
    record("A8", "Refresh token used as access token -> 401", r.status_code == 401, f"HTTP {r.status_code}")

    if bob:
        b_at = bob[1]["tokens"]["access_token"]
        created = api("POST", "/notes", b_at, json={"title": "bob private test note", "body": "secret"})
        if created.status_code == 201:
            note = created.json()["id"]
            read = api("GET", f"/notes/{note}", a_at).status_code
            delete = api("DELETE", f"/notes/{note}", a_at).status_code
            still = api("GET", f"/notes/{note}", b_at).status_code
            record("A9", "alice can't read or delete bob's note (IDOR) -> 404",
                   read == 404 and delete == 404 and still == 200, f"read {read}, delete {delete}, bob still sees it {still}")
            api("DELETE", f"/notes/{note}", b_at)
        else:
            record("A9", "alice can't read or delete bob's note (IDOR)", None, f"bob could not create a note: {created.status_code}")
    else:
        record("A9", "alice can't read or delete bob's note (IDOR)", None, "sign in as bob first")

    r = api("GET", "/admin/notes", a_at)
    record("A10", "Non-admin (alice) on /admin/notes -> 403", r.status_code == 403, f"HTTP {r.status_code}")
    if admin1:
        r = api("GET", "/admin/notes", admin1[1]["tokens"]["access_token"])
        record("A11", "Admin (admin1) on /admin/notes -> 200 (control)", r.status_code == 200, f"HTTP {r.status_code}")
    else:
        record("A11", "Admin (admin1) on /admin/notes -> 200 (control)", None, "sign in as admin1 first")

    codes = [api("POST", "/notes", a_at, json={"title": "x" * 101}).status_code,
             api("POST", "/notes", a_at, json=["not", "an", "object"]).status_code,
             api("POST", "/notes", a_at, json={"title": "   "}).status_code]
    record("A12", "Invalid input (title too long, not an object, empty title) -> 400",
           codes == [400, 400, 400], str(codes))

    r = api("POST", "/notes", a_at, json={"title": "big", "body": "x" * 20000})
    record("A13", "Request body over 16 KB -> 413", r.status_code == 413, f"HTTP {r.status_code}")

    payload = "x' OR '1'='1'; DROP TABLE notes; --"
    created = api("POST", "/notes", a_at, json={"title": payload})
    if created.status_code == 201:
        note = created.json()["id"]
        back = api("GET", f"/notes/{note}", a_at)
        record("A14", "SQL injection text is stored as plain text, table intact",
               back.status_code == 200 and back.json()["title"] == payload and api("GET", "/notes", a_at).status_code == 200)
        api("DELETE", f"/notes/{note}", a_at)
    else:
        record("A14", "SQL injection text is stored as plain text", False, f"HTTP {created.status_code}")


# --- 5. Session lifecycle (changes alice's and bob's sessions) --------------------
section("5. Logout and refresh tokens (ASVS V7, V10)")

if not bob:
    record("L1", "Sign-out destroys the session and revokes the refresh token", None, "sign in as bob first")
else:
    sid = bob[0]
    page = get(f"{APP}/", cookies={COOKIE: sid})
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    old_refresh = (load_session(sid) or {}).get("tokens", {}).get("refresh_token")
    if "Signed in as" not in page.text or not csrf or not old_refresh:
        record("L1", "Sign-out destroys the session and revokes the refresh token", None, "bob's session is no longer valid")
    else:
        r = post(f"{APP}/logout", cookies={COOKIE: sid}, headers={"Referer": f"{APP}/"})
        record("L1", "Sign-out without CSRF token is rejected (no logout CSRF)", r.status_code == 400, f"HTTP {r.status_code}")

        r = post(f"{APP}/logout", cookies={COOKIE: sid}, headers={"Referer": f"{APP}/"},
                 data={"csrf_token": csrf.group(1)})
        record("L2", "Sign-out redirects to Keycloak end-session (SSO session ended too)",
               r.status_code == 302 and r.headers.get("Location", "").startswith(meta["end_session_endpoint"]),
               f"HTTP {r.status_code}")

        page = get(f"{APP}/", cookies={COOKIE: sid})
        record("L3", "Old session cookie is useless after sign-out (deleted from Redis)",
               "Signed in as" not in page.text and not rdb.exists(PREFIX + sid))

        r = refresh(old_refresh)
        record("L4", "Refresh token is revoked at sign-out -> invalid_grant",
               r.status_code == 400 and r.json().get("error") == "invalid_grant", f"HTTP {r.status_code}")

if not alice:
    record("L5", "Refresh token rotation", None, "sign in as alice first")
else:
    rt0 = (load_session(alice[0]) or {}).get("tokens", {}).get("refresh_token")
    r1 = refresh(rt0) if rt0 else None
    if r1 is None or r1.status_code != 200:
        record("L5", "Refresh gives a new refresh token (rotation)", None,
               "alice's session is no longer valid" if r1 is None else
               f"refresh failed: HTTP {r1.status_code}; alice's refresh token was used by an earlier run, "
               "sign out and sign in as alice again")
    else:
        rt1 = r1.json().get("refresh_token")
        record("L5", "Refresh gives a new refresh token (rotation)", bool(rt1) and rt1 != rt0)

        r2 = refresh(rt1, scope="openid notes.read")
        if r2.status_code == 200:
            narrow = r2.json()["access_token"]
            scopes = claims_of(narrow).get("scope", "").split()
            if "notes.write" in scopes:
                record("L6", "Token without notes.write can't create notes -> 403", None,
                       "Keycloak did not narrow the scope on refresh")
            else:
                r = api("POST", "/notes", narrow, json={"title": "should fail"})
                record("L6", "Token without notes.write can't create notes -> 403",
                       r.status_code == 403 and "insufficient_scope" in r.headers.get("WWW-Authenticate", ""),
                       f"HTTP {r.status_code}")
        else:
            record("L6", "Token without notes.write can't create notes -> 403", None, f"refresh failed: HTTP {r2.status_code}")

        r = refresh(rt0)
        record("L7", "Used refresh token can't be used again -> invalid_grant",
               r.status_code == 400 and r.json().get("error") == "invalid_grant", f"HTTP {r.status_code}")


# --- 6. Rate limiting (last: blocks /login from this container for 1 minute) -------
section("6. Rate limiting (ASVS V6)")

codes = [get(f"{APP}/login").status_code for _ in range(25)]
first = codes.index(429) + 1 if 429 in codes else None
record("R1", "/login is rate limited (20 per minute) -> 429", first is not None,
       f"first 429 at request {first} of 25" if first else "no 429 in 25 requests")


# --- Summary ------------------------------------------------------------------
counts = {s: sum(1 for _, st, _ in results if st == s) for s in ("PASS", "FAIL", "SKIP")}
print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
for test_id, status, name in results:
    if status == "FAIL":
        print(f"  FAIL {test_id}: {name}")
print("alice and bob must sign in again before using the app (their sessions were used by the tests).")
sys.exit(1 if counts["FAIL"] else 0)
