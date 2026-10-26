"""Notes API (resource server).

Accepts only access tokens issued by Keycloak realm `itsm` for audience `notes-api`.
Every request is checked for signature, issuer, audience, expiry and scope.
Each user can see and change only their own notes; admins can see note counts.
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

# --- Configuration ----------------------------------------------------------
ISSUER = os.environ["OIDC_ISSUER"]              # https://auth.itsm.test/realms/itsm
AUDIENCE = "notes-api"                          # tokens must be issued for this API
DB_PATH = os.environ.get("NOTES_DB", "/data/notes.db")
TITLE_MAX = 100
BODY_MAX = 2000

# Keycloak public keys (JWKS) used to verify token signatures.
# Cached for 5 minutes and fetched again when a token has an unknown key id (kid),
# so key rotation in Keycloak works without restarting the API.
jwks_client = jwt.PyJWKClient(
    f"{ISSUER}/protocol/openid-connect/certs", cache_jwk_set=True, lifespan=300, timeout=5
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024    # reject request bodies larger than 16 KB

log = logging.getLogger("audit")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def audit(event, **fields):
    """Write a security event to the log as one JSON line.

    Only identifiers and outcomes are logged (event, user id, note id, reason, path).
    Tokens and note contents must never be passed here.
    """
    log.info(json.dumps({"ts": int(time.time()), "event": event, **fields}))


# --- Database ---------------------------------------------------------------
def db():
    """Return the SQLite connection for the current request, opening it on first use."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    """Close the request's database connection when the request ends."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    """Create the notes table and the owner index if they don't exist yet."""
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
    """Convert a database row to the JSON shape returned by the API (owner is not exposed)."""
    return {
        "id": row["id"],
        "title": row["title"],
        "body": row["body"],
        "created_at": row["created_at"],
    }


# --- Token validation -------------------------------------------------------
def bearer_error(status, error, description, scope=None):
    """Build an error response in the format defined by RFC 6750.

    Sets the WWW-Authenticate header so the client knows why the token was
    rejected, without revealing details that could help an attacker.
    """
    value = f'Bearer realm="notes-api", error="{error}", error_description="{description}"'
    if scope:
        value += f', scope="{scope}"'
    resp = jsonify(error=error, error_description=description)
    resp.status_code = status
    resp.headers["WWW-Authenticate"] = value
    return resp


def validate_token(token):
    """Verify an access token and return its claims.

    Checks the RS256 signature with Keycloak's public key, the issuer, the
    audience (`notes-api`), expiry and that the required claims are present.
    Only RS256 is allowed, so "none" and HS256 tokens are rejected.
    Raises a PyJWT exception if anything is wrong.
    """
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        leeway=30,                              # allow small clock differences between containers
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    # Keycloak marks access tokens with typ "Bearer"; ID and refresh tokens are not accepted.
    if claims.get("typ") != "Bearer":
        raise jwt.InvalidTokenError("not an access token")
    return claims


def require_scope(scope, role=None):
    """Decorator that protects a route with a valid access token.

    Returns 401 if the token is missing or invalid, 403 if it lacks the given
    scope or (optionally) the given realm role. On success the user's id is
    stored in `g.sub` for the route to use.
    """
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


# --- Routes -----------------------------------------------------------------
@app.get("/health")
def health():
    """Health check for monitoring. Needs no token and returns no data."""
    return jsonify(status="ok")


@app.get("/notes")
@require_scope("notes.read")
def list_notes():
    """Return all notes of the current user, newest first."""
    rows = db().execute(
        "SELECT * FROM notes WHERE owner = ? ORDER BY created_at DESC", (g.sub,)
    ).fetchall()
    return jsonify(notes=[note_json(r) for r in rows])


@app.get("/notes/<note_id>")
@require_scope("notes.read")
def get_note(note_id):
    """Return one note if it belongs to the current user.

    Someone else's note gives 404 (not 403), so note ids of other users
    can't be discovered.
    """
    row = db().execute(
        "SELECT * FROM notes WHERE id = ? AND owner = ?", (note_id, g.sub)
    ).fetchone()
    if row is None:
        return jsonify(error="not_found"), 404
    return jsonify(note_json(row))


@app.post("/notes")
@require_scope("notes.write")
def create_note():
    """Create a note for the current user from a JSON body {title, body}.

    The title must be 1-100 characters and the body at most 2000 characters.
    The owner is always taken from the token, never from the request body.
    """
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
    # Parameterized query: user input is never put into the SQL text (no SQL injection).
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
    """Delete a note if it belongs to the current user; otherwise return 404."""
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
    """Return how many notes each user has. Requires the admin role.

    Admins see only counts, not the contents of other users' notes.
    """
    rows = db().execute(
        "SELECT owner, COUNT(*) AS count FROM notes GROUP BY owner"
    ).fetchall()
    audit("admin_notes_listed", sub=g.sub)
    return jsonify(owners=[{"owner": r["owner"], "count": r["count"]} for r in rows])


# --- Error responses --------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    """Return unknown paths as JSON instead of an HTML page."""
    return jsonify(error="not_found"), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    """Return a JSON error when an endpoint is called with the wrong HTTP method."""
    return jsonify(error="method_not_allowed"), 405


@app.errorhandler(413)
def too_large(_e):
    """Return a JSON error when the request body is larger than MAX_CONTENT_LENGTH."""
    return jsonify(error="payload_too_large"), 413


@app.after_request
def no_store(resp):
    """Forbid caching of every response, since they contain private data."""
    resp.headers["Cache-Control"] = "no-store"
    return resp