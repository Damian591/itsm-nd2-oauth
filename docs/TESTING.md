# Security tests

Commands run from the project folder in PowerShell. Screenshots for the report go
to `docs/report/` (blur passwords, secrets and TOTP/recovery codes).

Contents: **Security test log (step 12)** for the whole system, then **Central
revocation (step 11)**. Chapter references are OWASP ASVS 5.0 chapters (V1
Encoding and Sanitization, V2 Validation, V3 Web Frontend Security, V6
Authentication, V7 Session Management, V8 Authorization, V9 Self-contained
Tokens, V10 OAuth and OIDC, V12 Secure Communication, V14 Data Protection);
the requirement-level mapping is part of step 13.

## Security test log (step 12)

### Automated tests

`tests/scripts/security_tests.py` runs inside the app container, which reaches
every service through Caddy over HTTPS like a browser.

1. Sign in at https://app.itsm.test as **alice** and as **bob** (normal + private
   window), optionally also as **admin1**.
2. Run:

   ```powershell
   Get-Content tests\scripts\security_tests.py | docker compose exec -T app python -
   ```

3. Screenshot the output for the report. Afterwards alice and bob must sign in
   again (the script signs bob out and uses alice's refresh token on purpose).
   Wait 1 minute before running it again (R1 trips the rate limit).

The API and session tests take tokens and session ids from Redis, i.e. they act
like an attacker who has stolen a token or a cookie. Nothing secret is printed.

| ID | Defence | ASVS | Expected |
| --- | --- | --- | --- |
| T1 | HTTP → HTTPS on app, api, auth | V12 | 308 to `https://` |
| T2 | Modern TLS accepted | V12 | TLS 1.3 and 1.2 handshakes succeed |
| T3, T4 | Old TLS refused | V12 | TLS 1.1 and 1.0 handshakes fail with a protocol alert |
| T5–T7 | Security headers on app, api, auth | V3 | HSTS (1 year), CSP, `nosniff`, Referrer-Policy, Permissions-Policy, no `Server` |
| T8 | No caching of private pages | V14 | `Cache-Control: no-store` |
| S1 | Session cookie flags | V3, V7 | `__Host-session`, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain |
| S2 | Idle timeout | V7 | Cookie expires after 30 min (= Keycloak SSO Session Idle) |
| S3 | Session fixation | V7 | A session id planted by an attacker is replaced by a new one |
| S4 | Open redirect | V3 | `/login?next=` keeps only local paths (`//evil`, `https://evil`, `/\evil` → `/`) |
| S5 | Login CSRF | V10 | `/callback` with a forged `state` → 400 |
| S6 | CSRF on forms | V3 | POST without CSRF token → 400 |
| K1 | Redirect URI allow-list | V10 | Unregistered `redirect_uri` → 400 at Keycloak |
| K2, K3 | PKCE required, S256 only | V10 | No `code_challenge` or `plain` → `invalid_request` |
| K4 | Implicit flow off | V10 | `response_type=token` → error |
| K5 | Password grant off | V10 | `grant_type=password` → `unauthorized_client` |
| K6 | Client authentication | V10 | Wrong client secret → 401 |
| K7 | No user enumeration at login | V6 | Same error text for an existing and an unknown user |
| K8 | No self-registration | V6 | Registration page not available |
| A1 | Valid token works (control) | V9 | 200 |
| A2–A6 | Token validation | V9 | Missing, malformed, `alg=none`, attacker-signed, modified claims → 401 |
| A7, A8 | Token type check | V9 | ID token or refresh token as Bearer → 401 |
| A9 | Object-level access control (IDOR) | V8 | alice reading or deleting bob's note → 404 |
| A10, A11 | Function-level access control | V8 | alice on `/admin/notes` → 403; admin1 → 200 |
| A12, A13 | Input validation | V2 | Bad input → 400; body over 16 KB → 413 |
| A14 | SQL injection | V1 | Injection text stored as plain text, table intact |
| L1 | Logout CSRF | V7 | POST `/logout` without CSRF token → 400 |
| L2 | Logout ends SSO session | V7 | Redirect to Keycloak end-session endpoint |
| L3 | Session destroyed on logout | V7 | Old cookie no longer signs in; Redis key deleted |
| L4 | Refresh token revoked on logout | V7, V10 | Old refresh token → `invalid_grant` |
| L5 | Refresh token rotation | V10 | Every refresh returns a new refresh token |
| L6 | Scope enforcement | V8, V10 | Token without `notes.write` → 403 `insufficient_scope` |
| L7 | Refresh token reuse | V10 | Used refresh token → `invalid_grant` |
| R1 | Rate limit on `/login` | V6 | 429 after 20 requests per minute |

### Manual tests (browser, one screenshot each)

| ID | Defence | ASVS | Steps | Expected |
| --- | --- | --- | --- | --- |
| M1 | Session id changes at login | V7 | DevTools → Network, tick *Preserve log*, click Sign in and log in; compare `set-cookie: __Host-session=` of the `login` response (session before login) and the `callback` response (after login) | Different values: the session id is regenerated at login |
| M2 | Brute force lockout | V6 | Sign in as bob with a wrong password 5×, then with the correct one | Still refused ("Invalid username or password"); works again after ~1 min |
| M3 | Password policy | V6 | Users → bob → Credentials → Reset password, try `Password1234` (blocklist), `bob` + digits (username), 11 characters | Each is rejected with the policy message |
| M4 | MFA is enforced | V6 | Sign in as alice with the correct password, enter a wrong TOTP code | Refused; correct code works |
| M5 | Recovery code is single use | V6 | Sign in with "Try another way" → recovery code; sign out; same code again | Second use refused |
| M6 | Password reset needs 2nd factor | V6 | Forgot Password → link from Mailpit (http://localhost:8025) | Asks for TOTP / recovery code before the new password |
| M7 | Reset link is single use | V6 | Open the same reset link a second time | "Action expired" / link invalid |
| M8 | No enumeration at reset | V6 | Forgot Password with an unknown e-mail | Same message as for alice; no mail in Mailpit |
| M9 | Back button after logout | V7 | Sign out, press Back | Page is not shown from cache, app asks to sign in |
| M10 | Session limits configured | V7 | Keycloak → Realm settings → Sessions | SSO Session Idle 30 min, Max 10 h (same as the app) |

### Results

| Date | Automated | Manual | Notes |
| --- | --- | --- | --- |
| 2026-10-29, run 1 | 41 PASS, 2 FAIL (S4, K8), 1 SKIP (A11, admin1 not signed in) | – | Findings F1, F2 |
| 2026-10-29, run 2 (after fixes) | 43 PASS, 0 FAIL, 1 SKIP (A11, admin1 not signed in) | | F1, F2 confirmed fixed |
| 2026-10-29, run 3 (clean run for the report) | 44 PASS, 0 FAIL, 0 SKIP | M1–M10 all PASS (M1 after fix F4, M3 after fix F5) | alice, bob, admin1 freshly signed in |

### Findings

Findings from the test runs, with fix or decision.

| ID | Test | Finding | Status |
| --- | --- | --- | --- |
| F1 | S4 | **Open redirect.** `/login?next=/\evil.example` was accepted. Browsers treat `/\` as `//`, so after signing in the user would be sent to another site (phishing). Tabs and newlines in the path (`/<TAB>/evil.example`) had the same effect. | Fixed in `app/app.py`: backslashes and control characters are refused; S4 now also checks these cases and that a real local path still works |
| F2 | K8 | **Self-registration was open.** Anyone could create an account in realm `itsm` and get the `user` role, i.e. use the app without being invited. | Fixed: `registrationAllowed: false` in `realm-export.json` |
| F4 | M1 | **Session id was not regenerated at login (session fixation).** The `set-cookie` value of `/login` and `/callback` was the same. `callback()` called `session.clear()` before `regenerate()`, and Flask-Session's `regenerate()` does nothing for an empty session. Risk reduced by the `__Host-` cookie prefix (S3), but the defence itself didn't work. | Fixed in `app/app.py`: `regenerate()` runs before `clear()`; M1 re-tested |
| F5 | M3 | **Password blocklist mostly ineffective.** `keycloak/password-blacklists/blocklist.txt` has 10,010 common passwords, but only 13 are 12 characters or longer. Because the minimum length is 12, the other 99.9 % can never be chosen anyway, so weak 12+ character passwords such as `Password1234` are accepted. `password123456` (in the list) is rejected, so the check itself works. | Fixed: added 72,537 leaked passwords of 12–128 characters (lower-cased, de-duplicated) from the SecLists lists `Pwdb_top-1000000.txt` and `xato-net-10-million-passwords-1000000.txt`, plus project-specific words; the old entries were kept. `Password1234` is now rejected (M3 re-tested) |
| F3 | – | **API did not come back after a Docker restart.** The `api` service had no restart policy, so the app showed "Could not load notes" (availability). | Fixed: `restart: unless-stopped` in `docker-compose.yml` |

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
