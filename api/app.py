"""Notes API (resource server).

Accepts only access tokens issued by Keycloak realm `itsm` for audience `notes-api`.
Every request is checked for signature, issuer, audience, expiry and scope.
"""
import json
import logging
import os
import sqlite3
import time
import uuid
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request

ISSUER = os.environ["OIDC_ISSUER"]
AUDIENCE = "notes-api"
DB_PATH = os.environ.get("NOTES_DB", "/data/notes.db")
TITLE_MAX = 100
BODY_MAX = 2000


jwks_client = jwt.PyJWKClient(
    f"{ISSUER}/protocol/openid-connect/certs", cache_jwk_set=True, lifespan=300, timeout=5
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

log = logging.getLogger("audit")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def audit(event, **fields):
    log.info(json.dumps({"ts": int(time.time()), "event": event, **fields}))


# ---------- database ----------

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS notes (
                   id TEXT PRIMARY KEY,
                   owner TEXT NOT NULL,
                   title TEXT NOT NULL,
                   body TEXT NOT NULL,
                   created_at INTEGER NOT NULL)"""
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner)")


init_db()


def note_json(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "body": row["body"],
        "created_at": row["created_at"],
    }


# ---------- token validation ----------

def bearer_error(status, error, description, scope=None):
    value = f'Bearer realm="notes-api", error="{error}", error_description="{description}"'
    if scope:
        value += f', scope="{scope}"'
    resp = jsonify(error=error, error_description=description)
    resp.status_code = status
    resp.headers["WWW-Authenticate"] = value
    return resp


def validate_token(token):
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        leeway=30,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )

    if claims.get("typ") != "Bearer":
        raise jwt.InvalidTokenError("not an access token")
    return claims


def require_scope(scope, role=None):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                audit("api_denied", reason="missing_token", path=request.path)
                return bearer_error(401, "invalid_request", "Bearer token required")
            try:
                claims = validate_token(auth[len("Bearer "):].strip())
            except jwt.ExpiredSignatureError:
                audit("api_denied", reason="expired", path=request.path)
                return bearer_error(401, "invalid_token", "Token expired")
            except (jwt.PyJWTError, jwt.PyJWKClientError) as exc:
                audit("api_denied", reason=type(exc).__name__, path=request.path)
                return bearer_error(401, "invalid_token", "Token is not valid")

            scopes = claims.get("scope", "").split()
            if scope not in scopes:
                audit("api_denied", reason="insufficient_scope", sub=claims["sub"], path=request.path)
                return bearer_error(403, "insufficient_scope", f"Scope {scope} required", scope=scope)

            roles = claims.get("realm_access", {}).get("roles", [])
            if role and role not in roles:
                audit("api_denied", reason="missing_role", sub=claims["sub"], path=request.path)
                return jsonify(error="forbidden", error_description=f"Role {role} required"), 403

            g.sub = claims["sub"]
            g.username = claims.get("preferred_username", "")
            return view(*args, **kwargs)

        return wrapper

    return decorator


# ---------- routes ----------

@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/notes")
@require_scope("notes.read")
def list_notes():
    rows = db().execute(
        "SELECT * FROM notes WHERE owner = ? ORDER BY created_at DESC", (g.sub,)
    ).fetchall()
    return jsonify(notes=[note_json(r) for r in rows])


@app.get("/notes/<note_id>")
@require_scope("notes.read")
def get_note(note_id):
    row = db().execute(
        "SELECT * FROM notes WHERE id = ? AND owner = ?", (note_id, g.sub)
    ).fetchone()

    if row is None:
        return jsonify(error="not_found"), 404
    return jsonify(note_json(row))


@app.post("/notes")
@require_scope("notes.write")
def create_note():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="invalid_request", error_description="JSON object expected"), 400
    title = data.get("title")
    body = data.get("body", "")
    if not isinstance(title, str) or not title.strip() or len(title) > TITLE_MAX:
        return jsonify(error="invalid_request", error_description=f"title: 1-{TITLE_MAX} characters"), 400
    if not isinstance(body, str) or len(body) > BODY_MAX:
        return jsonify(error="invalid_request", error_description=f"body: up to {BODY_MAX} characters"), 400

    note_id = str(uuid.uuid4())
    now = int(time.time())
    conn = db()
    conn.execute(
        "INSERT INTO notes (id, owner, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
        (note_id, g.sub, title.strip(), body, now),
    )
    conn.commit()
    audit("note_created", sub=g.sub, note=note_id)
    return jsonify(id=note_id, title=title.strip(), body=body, created_at=now), 201


@app.delete("/notes/<note_id>")
@require_scope("notes.write")
def delete_note(note_id):
    conn = db()
    cur = conn.execute("DELETE FROM notes WHERE id = ? AND owner = ?", (note_id, g.sub))
    conn.commit()
    if cur.rowcount == 0:
        audit("note_delete_denied", sub=g.sub, note=note_id)
        return jsonify(error="not_found"), 404
    audit("note_deleted", sub=g.sub, note=note_id)
    return "", 204


@app.get("/admin/notes")
@require_scope("notes.read", role="admin")
def admin_list_notes():
    rows = db().execute(
        "SELECT owner, COUNT(*) AS count FROM notes GROUP BY owner"
    ).fetchall()
    audit("admin_notes_listed", sub=g.sub)
    # Admin sees how many notes each user has, not their contents.
    return jsonify(owners=[{"owner": r["owner"], "count": r["count"]} for r in rows])


# ---------- generic responses ----------

@app.errorhandler(404)
def not_found(_e):
    return jsonify(error="not_found"), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify(error="method_not_allowed"), 405


@app.errorhandler(413)
def too_large(_e):
    return jsonify(error="payload_too_large"), 413


@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp