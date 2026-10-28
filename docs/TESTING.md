# Security tests

Commands run from the project folder in PowerShell. Screenshots for the report go
to `docs/report/` (blur passwords, secrets and TOTP/recovery codes).

## Central revocation (step 11)

How it works: the infrastructure owner runs `admin-tools/revoke.py` (as the
`admin-tool` service account with only `view-users`, `query-groups` and
`manage-users`). Keycloak ends the user's sessions and calls the app's
`/backchannel-logout` with a signed logout token; the app deletes the matching
Redis sessions at once.

| # | Test | Command / action | Expected result |
|---|------|------------------|-----------------|
| R1 | Sign out one user everywhere | alice signed in at https://app.itsm.test, then `docker compose run --rm admin-tool user-logout alice`, then reload the page as alice | `sessions alice` shows 1 → 0 sessions; app log has `backchannel_logout` for alice's `sub`; reloading redirects alice to the Keycloak login page at once (not after 5 min) |
| R2 | Revoke a whole group | alice and bob signed in (two browsers / private window), `docker compose run --rm admin-tool group-logout staff` | bob is signed out, alice stays signed in |
| R3 | Disable an account | `docker compose run --rm admin-tool user-disable bob`, then bob tries to sign in | bob signed out at once; Keycloak refuses the login ("Account is disabled"). Undo: `user-enable bob` |
| R4 | Reset credentials of a compromised account | `docker compose run --rm admin-tool user-reset alice` | old password no longer works; TOTP and recovery codes deleted; alice signed out; e-mail in Mailpit (http://localhost:8025) with a link to set a new password and enrol MFA again |
| R5 | No silent re-login after revocation | after R1, alice clicks Sign in again | Keycloak asks for password and TOTP again: the SSO session is gone too, and the old refresh token is revoked with it (a refresh would get `invalid_grant`) |
| R6 | Forged logout tokens are rejected | `Get-Content tests\scripts\test_backchannel.py \| docker compose exec -T app python -` | 4× PASS (missing token, garbage, `alg=none`, signed with attacker key) → all 400; app log shows `backchannel_logout_rejected` |
| R7 | Endpoint not reachable from outside | `curl.exe -sS -i --ssl-no-revoke -X POST https://app.itsm.test/backchannel-logout` | `404` from Caddy (only Keycloak inside the Docker network can call it) |
| R8 | Least privilege of the tool | `docker compose run --rm admin-tool verify-least-privilege` | prints its roles (only `manage-users`, `query-groups`, `query-users`, `view-users`); `OK: cannot read the webapp client secret (403)`; `OK: cannot read login events (403)` |
| R9 | Audit trail | `docker compose logs app \| Select-String backchannel`; Keycloak admin console → Events → Admin events | tool prints one JSON line per action (actor, action, target); Keycloak records the admin event; no tokens or passwords in any log |

### Known limitation (for the threat model)

The Notes API validates access tokens locally (signature + expiry), so an access
token that was already issued stays valid until it expires — at most 5 minutes —
even after revocation. Mitigations: the app session holding that token is deleted
at once (R1), the refresh token is dead immediately (R5), and the access token
lifetime is short. Removing the gap entirely would need token introspection on
every API call.

Logout token replay protection (each `jti` accepted once, tokens older than
5 min rejected) is checked in code (`validate_logout_token` in `app/app.py`);
it can't be demonstrated without Keycloak's private key.
