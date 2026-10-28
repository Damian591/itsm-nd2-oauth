"""Negative tests for the back-channel logout endpoint.

Runs inside the app container (it has requests and PyJWT there):
    Get-Content tests\\scripts\\test_backchannel.py | docker compose exec -T app python -

Every forged or malformed logout token must be rejected with 400, so nobody
except Keycloak can sign users out. Each rejection also appears in the app
audit log as backchannel_logout_rejected.
"""
import os
import time
import uuid

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

URL = "http://localhost:8000/backchannel-logout"
ISSUER = os.environ["OIDC_ISSUER"]
EVENT = {"http://schemas.openid.net/event/backchannel-logout": {}}

real_kid = jwt.PyJWKClient(f"{ISSUER}/protocol/openid-connect/certs").get_signing_keys()[0].key_id
attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def claims(**extra):
    now = int(time.time())
    return {"iss": ISSUER, "aud": "webapp", "iat": now, "exp": now + 60,
            "jti": str(uuid.uuid4()), "sub": "victim", "sid": "victim-session",
            "events": EVENT, "typ": "Logout", **extra}


CASES = {
    "no logout_token": None,
    "not a JWT": "garbage",
    "alg=none (unsigned)": jwt.encode(claims(), None, algorithm="none", headers={"kid": real_kid}),
    "signed with attacker key, real kid": jwt.encode(claims(), attacker_key, algorithm="RS256",
                                                     headers={"kid": real_kid}),
}

failed = 0
for name, token in CASES.items():
    resp = requests.post(URL, data={} if token is None else {"logout_token": token}, timeout=5)
    ok = resp.status_code == 400
    failed += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {resp.status_code}  {name}")

print("All rejected." if not failed else f"{failed} test(s) FAILED")
raise SystemExit(1 if failed else 0)
