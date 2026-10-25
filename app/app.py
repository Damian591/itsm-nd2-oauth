import json
import logging
import os
import time
from urllib.parse import urlencode

import redis
import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, request, session
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
REDIRECT_URI = f"{APP_URL}/callback"            # FIKSUOTAS, ne iš Host antraštės
ABSOLUTE_SESSION_MAX = 10 * 3600                # absoliutus sesijos limitas (10 h)

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("auth")


def audit(event, **fields):
    log.info(json.dumps({"ts": int(time.time()), "event": event,
                         "ip": request.remote_addr, **fields}))


app = Flask(__name__)
# Caddy perduoda X-Forwarded-For/Proto/Host – kad matytume tikrą kliento IP
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
        "code_challenge_method": "S256",        # įjungia PKCE
    },
)


# --- Pagalbinės funkcijos ---------------------------------------------------
def current_user():
    user = session.get("user")
    if not user:
        return None
    if time.time() - session.get("created_at", 0) > ABSOLUTE_SESSION_MAX:
        session.clear()
        return None
    return user


@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --- Maršrutai --------------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html", user=current_user())


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

    # 1) atšaukiame refresh žetoną Keycloak'e (RFC 7009)
    if tokens.get("refresh_token"):
        try:
            requests.post(meta["revocation_endpoint"], timeout=5,
                          auth=(CLIENT_ID, CLIENT_SECRET),
                          data={"token": tokens["refresh_token"],
                                "token_type_hint": "refresh_token"})
        except requests.RequestException:
            pass

    # 2) sunaikiname savo sesiją (Flask-Session ištrina ją iš Redis)
    session.clear()
    audit("logout", sub=sub)

    # 3) baigiame Keycloak SSO sesiją (RP-initiated logout)
    params = {"client_id": CLIENT_ID, "post_logout_redirect_uri": f"{APP_URL}/"}
    if tokens.get("id_token"):
        params["id_token_hint"] = tokens["id_token"]
    return redirect(f"{meta['end_session_endpoint']}?{urlencode(params)}")