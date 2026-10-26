"""Secure Notes web app (Backend for Frontend).

Acts as a confidential OAuth 2.0 / OpenID Connect client of Keycloak. Users sign in
with Authorization Code + PKCE; all tokens stay in the server-side session (Redis)
and the browser only receives an opaque session cookie. Notes are read and written
through the Notes API using the user's access token.
"""
import base64
import json
import logging
import os
import time
from urllib.parse import urlencode

import redis
import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

# --- Configuration ----------------------------------------------------------
ISSUER = os.environ["OIDC_ISSUER"]              # https://auth.itsm.test/realms/itsm
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]        # webapp
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
APP_URL = "https://app.itsm.test"
API_URL = "https://api.itsm.test"               # resource server, reached through Caddy over TLS
REDIRECT_URI = f"{APP_URL}/callback"            # fixed value, never built from the Host header
ABSOLUTE_SESSION_MAX = 10 * 3600                # absolute session limit (10 h), same as Keycloak SSO Session Max
REFRESH_MARGIN = 30                             # refresh the access token 30 s before it expires

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("auth")


def audit(event, **fields):
    """Write a security event to the log as one JSON line.

    Only identifiers and outcomes are logged (event name, client IP, user id, reason).
    Tokens, passwords and note contents must never be passed here.
    """
    log.info(json.dumps({"ts": int(time.time()), "event": event,
                         "ip": request.remote_addr, **fields}))


app = Flask(__name__)
# Trust exactly one proxy hop (Caddy) for X-Forwarded-For/Proto/Host,
# so the app sees the real client IP and knows the request came over HTTPS.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

rdb = redis.from_url(os.environ["REDIS_URL"])
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],
    SESSION_TYPE="redis",                       # session data lives in Redis, the cookie holds only the id
    SESSION_REDIS=rdb,
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=1800,            # 30 min idle timeout, same as Keycloak SSO Session Idle
    SESSION_COOKIE_NAME="__Host-session",       # __Host- prefix: Secure, Path=/, no Domain
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
)
Session(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri=os.environ["REDIS_URL"])

oauth = OAuth(app)
oauth.register(
    name="kc",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid profile email notes.read notes.write",
        "code_challenge_method": "S256",        # enables PKCE with SHA-256
    },
)


# --- Helpers ----------------------------------------------------------------
def current_user():
    """Return the signed-in user from the session, or None.

    Also enforces the absolute session lifetime: a session older than
    ABSOLUTE_SESSION_MAX is cleared even if the user has been active.
    """
    user = session.get("user")
    if not user:
        return None
    if time.time() - session.get("created_at", 0) > ABSOLUTE_SESSION_MAX:
        session.clear()
        return None
    return user


def jwt_payload(token):
    """Decode the payload of a JWT without verifying the signature.

    Used only to read the user's roles for the UI (e.g. whether to show the Admin
    link). This is acceptable because the token came straight from Keycloak over
    TLS; the real authorization checks (signature, audience, scope, role) are
    done by the Notes API.
    """
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


class LoginRequired(Exception):
    """Raised when the user has to sign in again.

    Happens when the access token can't be refreshed or the API rejects it.
    """


def refresh_tokens(tokens):
    """Get a new access token from Keycloak using the refresh token.

    This is a direct server-to-server call to the token endpoint, authenticated
    with the client secret; the browser is not involved. On success the new
    access, refresh and ID tokens and the user's roles are stored in the session
    and the new access token is returned. On failure LoginRequired is raised.
    """
    sub = (session.get("user") or {}).get("sub")
    meta = oauth.kc.load_server_metadata()
    resp = requests.post(meta["token_endpoint"], timeout=5,
                         auth=(CLIENT_ID, CLIENT_SECRET),
                         data={"grant_type": "refresh_token",
                               "refresh_token": tokens["refresh_token"]})
    if resp.status_code != 200:
        # invalid_grant means the SSO session has ended, an admin revoked it,
        # or this refresh token was already used (refresh token rotation).
        try:
            reason = resp.json().get("error", resp.status_code)
        except ValueError:
            reason = resp.status_code
        audit("refresh_failed", sub=sub, reason=reason)
        raise LoginRequired()

    new = resp.json()
    tokens.update(
        access_token=new["access_token"],
        # With "Revoke Refresh Token" on, Keycloak issues a new refresh token every time.
        refresh_token=new.get("refresh_token", tokens["refresh_token"]),
        id_token=new.get("id_token", tokens.get("id_token")),
        expires_at=int(time.time()) + int(new.get("expires_in", 300)),
    )
    session["tokens"] = tokens
    # Roles are refreshed together with the token, so role changes in Keycloak
    # reach the app within one access token lifetime (5 min).
    session["roles"] = jwt_payload(new["access_token"]).get("realm_access", {}).get("roles", [])
    audit("token_refreshed", sub=sub)
    return new["access_token"]


def access_token():
    """Return a valid access token for the current user.

    Uses the stored token while it has more than REFRESH_MARGIN seconds left,
    otherwise refreshes it. Raises LoginRequired if there is no refresh token.
    """
    tokens = session.get("tokens") or {}
    if tokens.get("access_token") and tokens.get("expires_at", 0) > time.time() + REFRESH_MARGIN:
        return tokens["access_token"]
    if not tokens.get("refresh_token"):
        raise LoginRequired()
    return refresh_tokens(tokens)


def api_call(method, path, **kwargs):
    """Call the Notes API on behalf of the current user.

    Sends the access token as a Bearer token and returns the response.
    A 401 from the API means the token was not accepted, so the user is sent
    to sign in again (LoginRequired).
    """
    access_token_value = access_token()
    resp = requests.request(
        method, f"{API_URL}{path}", timeout=5,
        headers={"Authorization": f"Bearer {access_token_value}"}, **kwargs,
    )
    if resp.status_code == 401:
        raise LoginRequired()
    return resp


@app.errorhandler(LoginRequired)
def login_required(_exc):
    """Clear the session and start a new login, returning to the same page afterwards."""
    session.clear()
    return redirect(url_for("login", next=request.path if request.method == "GET" else "/"))


@app.errorhandler(requests.RequestException)
def api_unreachable(exc):
    """Show a friendly 502 page when Keycloak or the Notes API can't be reached."""
    audit("api_unreachable", reason=type(exc).__name__)
    return render_template("error.html", title="Service unavailable",
                           message="Notes service is not reachable. Please try again later."), 502


@app.after_request
def no_store(resp):
    """Forbid caching of every response, so private pages aren't kept by the browser."""
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --- Routes -----------------------------------------------------------------
@app.get("/")
def index():
    """Home page: the user's notes when signed in, otherwise a Sign in button."""
    user = current_user()
    notes = []
    if user:
        resp = api_call("GET", "/notes")
        if resp.ok:
            notes = resp.json()["notes"]
        else:
            flash("Could not load notes.")
    return render_template("index.html", user=user, notes=notes,
                           is_admin="admin" in session.get("roles", []))


@app.post("/notes")
def create_note():
    """Create a note from the form through the Notes API (needs scope notes.write)."""
    if not current_user():
        return redirect(url_for("login"))
    resp = api_call("POST", "/notes", json={
        "title": request.form.get("title", ""),
        "body": request.form.get("body", ""),
    })
    if resp.status_code != 201:
        flash(resp.json().get("error_description", "Could not save the note."))
    return redirect(url_for("index"))


@app.post("/notes/<uuid:note_id>/delete")
def delete_note(note_id):
    """Delete one of the user's notes. Only UUIDs are accepted as the note id."""
    if not current_user():
        return redirect(url_for("login"))
    resp = api_call("DELETE", f"/notes/{note_id}")
    if resp.status_code != 204:
        flash("Note not found.")
    return redirect(url_for("index"))


@app.get("/admin")
def admin():
    """Admin page with note counts per user. The API enforces the admin role (403 otherwise)."""
    if not current_user():
        return redirect(url_for("login", next="/admin"))
    resp = api_call("GET", "/admin/notes")
    if resp.status_code == 403:
        abort(403)
    return render_template("admin.html", user=current_user(),
                           owners=resp.json().get("owners", []))


@app.get("/login")
@limiter.limit("20 per minute")
def login():
    """Start the Authorization Code + PKCE flow and redirect to Keycloak.

    Authlib generates state, nonce and the PKCE code verifier and keeps them in
    the session. The optional `next` parameter is accepted only as a local path
    to prevent open redirects.
    """
    nxt = request.args.get("next", "/")
    session["next"] = nxt if nxt.startswith("/") and not nxt.startswith("//") else "/"
    return oauth.kc.authorize_redirect(REDIRECT_URI)


@app.get("/callback")
@limiter.limit("20 per minute")
def callback():
    """Finish the login after Keycloak redirects back with an authorization code.

    Authlib checks state, exchanges the code (with the PKCE verifier and client
    secret) for tokens and validates the ID token (signature, issuer, audience,
    expiry, nonce). A new session id is issued to prevent session fixation, and
    the user data and tokens are stored server-side.
    """
    if "error" in request.args:
        audit("login_failure", reason=request.args.get("error"))
        return render_template("error.html"), 400
    try:
        token = oauth.kc.authorize_access_token()
    except Exception as exc:
        audit("login_failure", reason=type(exc).__name__)
        return render_template("error.html"), 400

    userinfo = token.get("userinfo") or {}
    next_url = session.get("next", "/")

    session.clear()
    app.session_interface.regenerate(session)

    session["user"] = {
        "sub": userinfo["sub"],
        "username": userinfo.get("preferred_username"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
    }
    session["tokens"] = {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token"),
        "id_token": token.get("id_token"),
        "expires_at": token.get("expires_at"),
    }
    session["roles"] = jwt_payload(token["access_token"]).get("realm_access", {}).get("roles", [])
    session["auth_time"] = userinfo.get("auth_time", int(time.time()))
    session["created_at"] = int(time.time())
    session["kc_sid"] = userinfo.get("sid")     # Keycloak session id, used by back-channel logout
    audit("login_success", sub=userinfo["sub"])
    return redirect(next_url)


@app.post("/logout")
def logout():
    """Sign the user out of both the app and Keycloak.

    1. Revoke the refresh token at Keycloak (RFC 7009).
    2. Delete the local session from Redis.
    3. Redirect to Keycloak's end-session endpoint to end the SSO session
       (RP-initiated logout), then back to the home page.
    Only POST with a CSRF token is accepted, so other sites can't log the user out.
    """
    tokens = session.get("tokens", {})
    sub = (session.get("user") or {}).get("sub")
    meta = oauth.kc.load_server_metadata()

    # 1) Revoke the refresh token at Keycloak (RFC 7009).
    if tokens.get("refresh_token"):
        try:
            requests.post(meta["revocation_endpoint"], timeout=5,
                          auth=(CLIENT_ID, CLIENT_SECRET),
                          data={"token": tokens["refresh_token"],
                                "token_type_hint": "refresh_token"})
        except requests.RequestException:
            pass

    # 2) Destroy the local session (Flask-Session deletes it from Redis).
    session.clear()
    audit("logout", sub=sub)

    # 3) End the Keycloak SSO session (RP-initiated logout).
    params = {"client_id": CLIENT_ID, "post_logout_redirect_uri": f"{APP_URL}/"}
    if tokens.get("id_token"):
        params["id_token_hint"] = tokens["id_token"]
    return redirect(f"{meta['end_session_endpoint']}?{urlencode(params)}")