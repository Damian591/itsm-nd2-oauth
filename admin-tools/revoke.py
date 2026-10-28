#!/usr/bin/env python3
"""Central revocation tool for the infrastructure owner.

Signs users out everywhere, disables accounts and resets credentials, for one
user or a whole group, through the Keycloak Admin REST API.

The tool authenticates as its own confidential client `admin-tool` with the
client credentials grant. Its service account has only the realm-management
roles view-users, query-groups and manage-users (least privilege): it can't
change clients, realm settings or roles.

Every Keycloak sign-out triggers back-channel logout, so the Secure Notes app
deletes the user's sessions at once. Each action is written as one JSON audit
line; tokens and passwords are never printed.

Run it through Docker Compose:
    docker compose run --rm admin-tool sessions alice
    docker compose run --rm admin-tool user-logout alice
    docker compose run --rm admin-tool user-reset alice
    docker compose run --rm admin-tool group-logout staff
"""
import argparse
import base64
import json
import os
import secrets
import sys
import time

import requests

ISSUER = os.environ["OIDC_ISSUER"]                       # https://auth.itsm.test/realms/itsm
REALM = ISSUER.rstrip("/").rsplit("/", 1)[-1]            # itsm
BASE = ISSUER.split("/realms/")[0]                       # https://auth.itsm.test
ADMIN = f"{BASE}/admin/realms/{REALM}"
CLIENT_ID = os.environ["ADMIN_TOOL_ID"]
CLIENT_SECRET = os.environ["ADMIN_TOOL_SECRET"]
MFA_CREDENTIALS = {"otp", "recovery-authn-codes"}


def audit(action, **fields):
    """Print one JSON audit line: who (this client), what, to whom, result."""
    print(json.dumps({"ts": int(time.time()), "actor": CLIENT_ID, "action": action, **fields}))


class Keycloak:
    """Minimal Admin REST API client using a client-credentials access token."""

    def __init__(self):
        if not CLIENT_SECRET:
            sys.exit("ADMIN_TOOL_SECRET is empty in .env (Clients -> admin-tool -> Credentials).")
        resp = requests.post(f"{ISSUER}/protocol/openid-connect/token", timeout=10,
                             auth=(CLIENT_ID, CLIENT_SECRET),
                             data={"grant_type": "client_credentials"})
        if resp.status_code != 200:
            sys.exit(f"Could not get an admin token: {resp.status_code} {resp.json().get('error')}")
        token = resp.json()["access_token"]
        self.http = requests.Session()
        self.http.headers["Authorization"] = f"Bearer {token}"
        # Roles of the service account, read from the token only for display.
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        self.roles = sorted(claims.get("resource_access", {}).get("realm-management", {}).get("roles", []))

    def call(self, method, path, **kwargs):
        resp = self.http.request(method, f"{ADMIN}{path}", timeout=10, **kwargs)
        if resp.status_code == 403:
            raise PermissionError(f"{method} {path}: 403 Forbidden")
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def user(self, username):
        found = self.call("GET", "/users", params={"username": username, "exact": "true"})
        if not found:
            sys.exit(f"User not found: {username}")
        return found[0]

    def group_members(self, name):
        groups = self.call("GET", "/groups", params={"search": name, "exact": "true"})
        group = next((g for g in groups if g["name"] == name), None)
        if not group:
            sys.exit(f"Group not found: {name}")
        return self.call("GET", f"/groups/{group['id']}/members",
                         params={"first": 0, "max": 1000, "briefRepresentation": "true"})

    def all_users(self):
        return self.call("GET", "/users", params={"first": 0, "max": 1000,
                                                  "briefRepresentation": "true"})


# --- Actions on one user ------------------------------------------------------
def logout(kc, user):
    """End every Keycloak session of the user (triggers back-channel logout in the app)."""
    sessions = kc.call("GET", f"/users/{user['id']}/sessions")
    kc.call("POST", f"/users/{user['id']}/logout")
    audit("user_logout", target=user["username"], sessions=len(sessions))


def disable(kc, user):
    """Block the account, then sign it out. A disabled user can't sign in or refresh tokens."""
    kc.call("PUT", f"/users/{user['id']}", json={"enabled": False})
    audit("user_disable", target=user["username"])
    logout(kc, user)


def enable(kc, user):
    kc.call("PUT", f"/users/{user['id']}", json={"enabled": True})
    audit("user_enable", target=user["username"])


def reset(kc, user):
    """Reset all credentials of a possibly compromised account.

    1. The password is replaced with a random value nobody knows, so a stolen
       password stops working immediately.
    2. TOTP and recovery codes are deleted, so a stolen phone or code sheet
       stops working too.
    3. All sessions are ended (back-channel logout).
    4. The user gets an e-mail link to set a new password and enrol MFA again.
    """
    kc.call("PUT", f"/users/{user['id']}/reset-password",
            json={"type": "password", "value": secrets.token_urlsafe(48), "temporary": True})
    removed = []
    for cred in kc.call("GET", f"/users/{user['id']}/credentials"):
        if cred["type"] in MFA_CREDENTIALS:
            kc.call("DELETE", f"/users/{user['id']}/credentials/{cred['id']}")
            removed.append(cred["type"])
    logout(kc, user)
    kc.call("PUT", f"/users/{user['id']}/execute-actions-email",
            params={"lifespan": 900},
            json=["UPDATE_PASSWORD", "CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES"])
    audit("user_reset", target=user["username"], removed=removed, email_sent=True)


def show_sessions(kc, user):
    """List the user's active Keycloak sessions (for evidence before and after revocation)."""
    sessions = kc.call("GET", f"/users/{user['id']}/sessions")
    print(f"{user['username']}: {len(sessions)} active session(s)")
    for s in sessions:
        print(f"  ip={s.get('ipAddress')} started={time.ctime(s['start'] / 1000)} "
              f"last={time.ctime(s['lastAccess'] / 1000)} clients={list(s.get('clients', {}).values())}")


def verify_least_privilege(kc):
    """Show that the tool can't do more than its job.

    It must not read another client's secret (e.g. the webapp's) or the realm's
    login events. Listing clients is not a useful test: Keycloak allows that to
    anyone who manages users, because role mapping needs the client list.
    """
    print(f"admin-tool roles: {', '.join(kc.roles) or '(none)'}")
    extra = set(kc.roles) - {"view-users", "query-users", "query-groups", "manage-users"}
    webapp = kc.call("GET", "/clients", params={"clientId": "webapp"})
    checks = [("read login events", "/events")]
    if webapp:
        checks.insert(0, ("read the webapp client secret", f"/clients/{webapp[0]['id']}/client-secret"))
    failed = bool(extra)
    if extra:
        print(f"FAIL: unexpected roles {sorted(extra)}")
    for name, path in checks:
        try:
            kc.call("GET", path)
            print(f"FAIL: admin-tool can {name}")
            failed = True
        except PermissionError:
            print(f"OK: cannot {name} (403 Forbidden)")
    sys.exit(1 if failed else 0)


USER_ACTIONS = {"logout": logout, "disable": disable, "enable": enable, "reset": reset}


def main():
    parser = argparse.ArgumentParser(description="Central revocation for realm " + REALM)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for action in USER_ACTIONS:
        sub.add_parser(f"user-{action}").add_argument("username")
        sub.add_parser(f"group-{action}").add_argument("group")
    sub.add_parser("sessions").add_argument("username")
    all_p = sub.add_parser("all-logout", help="emergency: sign out every user")
    all_p.add_argument("--yes", action="store_true", help="confirm")
    sub.add_parser("verify-least-privilege")
    args = parser.parse_args()

    kc = Keycloak()
    kind, _, action = args.cmd.partition("-")
    if args.cmd == "sessions":
        show_sessions(kc, kc.user(args.username))
    elif args.cmd == "verify-least-privilege":
        verify_least_privilege(kc)
    elif args.cmd == "all-logout":
        if not args.yes:
            sys.exit("This signs out EVERY user. Run again with --yes to confirm.")
        for user in kc.all_users():
            logout(kc, user)
    elif kind == "user":
        USER_ACTIONS[action](kc, kc.user(args.username))
    elif kind == "group":
        members = kc.group_members(args.group)
        audit(f"group_{action}", target=args.group, members=len(members))
        for user in members:
            USER_ACTIONS[action](kc, user)


if __name__ == "__main__":
    try:
        main()
    except PermissionError as exc:
        audit("denied", reason=str(exc))
        sys.exit(1)
