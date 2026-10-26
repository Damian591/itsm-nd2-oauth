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

# --- Konfigūracija ----------------------------------------------------------
ISSUER = os.environ["OIDC_ISSUER"]              # https://auth.itsm.test/realms/itsm
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]        # webapp
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
APP_URL = "https://app.itsm.test"
API_URL = "https://api.itsm.test"               # resource server (via Caddy, with TLS)
REDIRECT_URI = f"{APP_URL}/callback"            # FIXED, not from the “Host” header
ABSOLUTE_SESSION_MAX = 10 * 3600                # absolute session limit (10 hours)

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("auth")


def audit(event, **fields):
    log.info(json.dumps({"ts": int(time.time()), "event": event,
                         "ip": request.remote_addr, **fields}))


app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

rdb = redis.from_url(os.environ["REDIS_URL"])
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],
    SESSION_TYPE="redis",
    SESSION_REDIS=rdb,
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=1800,
    SESSION_COOKIE_NAME="__Host-session",
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
        "code_challenge_method": "S256",
    },
)


def current_user():
    user = session.get("user")
    if not user:
        return None
    if time.time() - session.get("created_at", 0) > ABSOLUTE_SESSION_MAX:
        session.clear()
        return None
    return user


def jwt_payload(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


class LoginRequired(Exception):
    """The Access token has expired or was rejected by the API—you need to log in again."""


def api_call(method, path, **kwargs):
    tokens = session.get("tokens") or {}
    access_token = tokens.get("access_token")

    if not access_token or tokens.get("expires_at", 0) < time.time() + 10:
        raise LoginRequired()
    resp = requests.request(
        method, f"{API_URL}{path}", timeout=5,
        headers={"Authorization": f"Bearer {access_token}"}, **kwargs,
    )
    if resp.status_code == 401:
        raise LoginRequired()
    return resp


@app.errorhandler(LoginRequired)
def login_required(_exc):
    session.clear()
    return redirect(url_for("login", next=request.path if request.method == "GET" else "/"))


@app.errorhandler(requests.RequestException)
def api_unreachable(exc):
    audit("api_unreachable", reason=type(exc).__name__)
    return render_template("error.html", title="Service unavailable",
                           message="Notes service is not reachable. Please try again later."), 502


@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.get("/")
def index():
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
    if not current_user():
        return redirect(url_for("login"))
    resp = api_call("DELETE", f"/notes/{note_id}")
    if resp.status_code != 204:
        flash("Note not found.")
    return redirect(url_for("index"))


@app.get("/admin")
def admin():
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
    nxt = request.args.get("next", "/")
    session["next"] = nxt if nxt.startswith("/") and not nxt.startswith("//") else "/"
    return oauth.kc.authorize_redirect(REDIRECT_URI)


@app.get("/callback")
@limiter.limit("20 per minute")
def callback():
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
    session["kc_sid"] = userinfo.get("sid")
    audit("login_success", sub=userinfo["sub"])
    return redirect(next_url)


@app.post("/logout")
def logout():
    tokens = session.get("tokens", {})
    sub = (session.get("user") or {}).get("sub")
    meta = oauth.kc.load_server_metadata()

    if tokens.get("refresh_token"):
        try:
            requests.post(meta["revocation_endpoint"], timeout=5,
                          auth=(CLIENT_ID, CLIENT_SECRET),
                          data={"token": tokens["refresh_token"],
                                "token_type_hint": "refresh_token"})
        except requests.RequestException:
            pass

    session.clear()
    audit("logout", sub=sub)


    params = {"client_id": CLIENT_ID, "post_logout_redirect_uri": f"{APP_URL}/"}
    if tokens.get("id_token"):
        params["id_token_hint"] = tokens["id_token"]
    return redirect(f"{meta['end_session_endpoint']}?{urlencode(params)}")