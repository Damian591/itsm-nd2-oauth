# ITSM PD2 – OAuth 2.0 (Authorization Code + PKCE) with Keycloak

Homework 2 for Information Technology Security Methods. The project is a small
web app ("Secure Notes") that never sees user passwords. Login is handled by
Keycloak using OAuth 2.0 Authorization Code + PKCE and OpenID Connect.

Everything runs in Docker, so nobody has to install Keycloak, PostgreSQL or
Redis by hand. A first-time setup takes about 15 minutes.

## Progress

The project is built step by step, one branch and one pull request per step.

| # | Step | Status |
| --- | --- | --- |
| 1 | Repository, `.gitignore`, `.gitattributes`, `.env` generator | ✅ Done |
| 2 | Local domains and HTTPS certificates (mkcert) | ✅ Done |
| 3 | Docker Compose: Caddy, Keycloak, PostgreSQL, Redis, Mailpit | ✅ Done |
| 4 | Caddy reverse proxy: TLS 1.2/1.3, HSTS and other security headers | ✅ Done |
| 5 | Keycloak realm `itsm`: client, scopes, roles, groups, realm export | ✅ Done |
| 6 | Web app (BFF): login and logout with Authorization Code + PKCE | ✅ Done |
| 7 | API (resource server) with access token validation | ⏳ Not started |
| 8 | Refresh tokens and session limits | ⏳ Not started |
| 9 | Keycloak security policies: MFA, password policy, brute force protection | ⏳ Not started |
| 10 | Password reset by email | ⏳ Not started |
| 11 | Central revocation (admin tool, back-channel logout) | ⏳ Not started |
| 12 | Security tests and test log | ⏳ Not started |
| 13 | Threat model (STRIDE), ASVS mapping, report | ⏳ Not started |
| 14 | Demo rehearsal | ⏳ Not started |

### What works right now

- All services start with one `docker compose up -d` command.
- `https://auth.itsm.test` and `https://app.itsm.test` are served over HTTPS with
  a locally trusted certificate. HTTP is redirected to HTTPS.
- Caddy adds HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy` and
  `Permissions-Policy` headers and hides the `Server` header.
- The Keycloak realm `itsm` is imported automatically on first start.
- A user can sign in to the web app through Keycloak and sign out again.
  Sign out revokes the refresh token, clears the app session and ends the
  Keycloak session.
- Tokens are stored only on the server (in Redis). The browser gets a
  `__Host-session` cookie (Secure, HttpOnly, SameSite=Lax).
- Logout uses POST with a CSRF token. `/login` and `/callback` are rate limited.

## Architecture

| URL | Component | Purpose |
| --- | --- | --- |
| https://app.itsm.test | Flask app (BFF) | The web app. Keeps tokens on the server side |
| https://auth.itsm.test | Keycloak 26.8.1 | Authorization server (OAuth 2.0 / OpenID Connect) |
| https://api.itsm.test | Flask API | Resource server (step 7, not built yet) |
| http://localhost:8025 | Mailpit | Test mailbox that catches all emails from Keycloak |

Caddy sits in front of everything as a reverse proxy and terminates HTTPS. Only
ports 80/443 (Caddy) and 127.0.0.1:8025 (Mailpit) are open on the host machine.
Keycloak, PostgreSQL, Redis and the app container are reachable only inside the
Docker network.

```
Browser ──HTTPS──> Caddy ──> keycloak:8080 ──> PostgreSQL
                         └─> app:8000 ──> Redis
```

## Requirements

The instructions are written for Windows 10/11. macOS/Linux should work with
the noted differences but have not been tested.

- Docker Desktop (WSL 2 engine), Docker Compose v2
- Git
- Python 3.12+ (only for the `.env` script and the IDE)
- mkcert, jq
- Chrome or Edge (Firefox on Windows does not trust the mkcert CA by default)

Install anything missing from an **administrator** PowerShell:

```powershell
wsl --install
winget install Docker.DockerDesktop Git.Git Python.Python.3.12 FiloSottile.mkcert jqlang.jq
```

In Docker Desktop, check Settings → General → **Use the WSL 2 based engine**.
Docker Desktop must be running whenever the project is used.

## Setup on a new computer

All commands run in a normal PowerShell unless a step says administrator.

### 1. Clone the repository

Use a path without spaces and outside OneDrive (OneDrive sync breaks Docker
mounts).

```powershell
mkdir C:\Projects; cd C:\Projects
git clone https://github.com/Damian591/itsm-nd2-oauth.git
cd itsm-nd2-oauth
```

### 2. Point the domains to 127.0.0.1

The `.test` domains do not exist on the internet, so they are added to the
hosts file. **Administrator** PowerShell:

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`r`n127.0.0.1  app.itsm.test auth.itsm.test api.itsm.test"
```

(macOS/Linux: `echo "127.0.0.1 app.itsm.test auth.itsm.test api.itsm.test" | sudo tee -a /etc/hosts`)

Check: `ping -n 1 auth.itsm.test` should answer from `127.0.0.1`.

Why not `localhost`: tokens contain the issuer URL, and it must be identical
for the browser and for the app inside its container. Inside a container
`localhost` means the container itself, so the same domain names are used
everywhere.

### 3. Create HTTPS certificates

In the project folder:

```powershell
mkcert -install
mkcert -cert-file certs\itsm.test.pem -key-file certs\itsm.test-key.pem app.itsm.test auth.itsm.test api.itsm.test
Copy-Item "$(mkcert -CAROOT)\rootCA.pem" certs\rootCA.pem
```

`mkcert -install` shows a Windows security dialog – click **Yes**. It installs a
local certificate authority that only this computer trusts.

- `certs/` is not in Git. Every team member creates their own certificates.
- **Never copy or share `rootCA-key.pem`** from the `mkcert -CAROOT` folder.
  Whoever has it can issue certificates for any website that this computer will
  trust.
- `rootCA.pem` (without "key") is public. The app container needs it to trust
  Keycloak's certificate. TLS errors must not be "fixed" with `verify=False`.

### 4. Generate the `.env` file

```powershell
python scripts\gen_env.py
```

The script creates `.env` with random passwords and refuses to overwrite an
existing one. `.env` is never committed. `OIDC_CLIENT_SECRET` and
`ADMIN_TOOL_SECRET` stay empty for now and are filled in from Keycloak later.

### 5. Start the services

```powershell
docker compose up -d
docker compose ps
docker compose logs -f keycloak
```

Wait for `Keycloak 26.8.1 ... started`, then press Ctrl+C (this only stops the
log output). The first start takes a minute or two because Keycloak imports the
realm from `keycloak/import/realm-export.json`.

### 6. Finish the Keycloak configuration

The realm export contains no users and no secrets on purpose, so two things are
done by hand.

Sign in at https://auth.itsm.test/admin with `KC_ADMIN_USER` /
`KC_ADMIN_PASSWORD` from `.env`, then switch the realm (top left) from `master`
to **itsm**.

**Client secret**

1. Clients → `webapp` → Credentials → **Regenerate**.
2. Copy the value into `.env` as `OIDC_CLIENT_SECRET=...`.
3. Recreate the app container. A plain `restart` is not enough because
   environment variables are read only when a container is created:

   ```powershell
   docker compose up -d --force-recreate app
   ```

**Test users**

Users → Add user → turn **Email verified** on → join the group → Create. Then
Credentials → Set password with **Temporary** off.

| Username | Email | Group | Purpose |
| --- | --- | --- | --- |
| `alice` | alice@itsm.test | `students` | Main demo user |
| `bob` | bob@itsm.test | `staff` | Second user for access tests between users |
| `admin1` | admin1@itsm.test | `admins` | Gets the `admin` role through the group |

Every new user gets the `user` role automatically (default role of the realm).
Passwords are up to each team member and must not appear in Git or in report
screenshots.

### 7. Try the login

Open https://app.itsm.test, click **Sign in** and log in as `alice`. The app
should show "Signed in as alice". **Sign out** ends both the app session and the
Keycloak session.

## Checks

| What | Expected result |
| --- | --- |
| https://auth.itsm.test | Keycloak page with a padlock, no warnings |
| https://auth.itsm.test/admin | Login with `KC_ADMIN_USER` / `KC_ADMIN_PASSWORD` from `.env` |
| https://app.itsm.test | "Secure Notes" page with a Sign in button |
| http://localhost:8025 | Mailpit inbox |

```powershell
curl.exe -sS --ssl-no-revoke https://auth.itsm.test/realms/itsm/.well-known/openid-configuration | jq .issuer
# -> "https://auth.itsm.test/realms/itsm"
curl.exe -sI http://app.itsm.test
# -> 308 Permanent Redirect, Location: https://app.itsm.test/
curl.exe -sSI --ssl-no-revoke https://app.itsm.test
# -> Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy
```

`--ssl-no-revoke` is needed only for Windows `curl.exe`: mkcert certificates
have no revocation (CRL/OCSP) server. The certificate itself is still verified.

Check that the app container can reach Keycloak (should print `200`):

```powershell
docker compose exec app python -c "import os, requests; print(requests.get(os.environ['OIDC_ISSUER'] + '/.well-known/openid-configuration', timeout=5).status_code)"
```

## Everyday commands

```powershell
docker compose up -d                        # start
docker compose ps                           # status
docker compose logs -f <service>            # logs of one service
docker compose up -d --build app            # after changing app code or requirements.txt
docker compose up -d --force-recreate app   # after changing .env
docker compose restart proxy                # after changing the Caddyfile
docker compose down                         # stop (data is kept)
docker compose down -v                      # stop AND delete the Keycloak database
```

After `down -v` the setup continues from step 5 again: new database, new client
secret, users created again.

## Project layout

```
docker-compose.yml        all services
proxy/Caddyfile           HTTPS, security headers, routing by domain
keycloak/import/          realm export, imported on first start
app/                      Flask app (Dockerfile, app.py, templates, static)
scripts/gen_env.py        creates .env
.env.example              list of environment variables, no values
certs/                    local mkcert certificates (not in Git)
```

## Troubleshooting

| Problem | Solution |
| --- | --- |
| `bind: address already in use` (80/443) | Another program uses the port (IIS, Skype, another web server) – stop it |
| Browser shows "Not secure" | Restart the browser after `mkcert -install`; use Chrome or Edge |
| `curl.exe` prints nothing | Add `-sS --ssl-no-revoke` (`-s` alone hides errors) |
| `/login` returns 500, log shows `redis.exceptions.AuthenticationError` | `REDIS_URL` in `.env` has the wrong password; it must contain the same value as `REDIS_PASSWORD`. Then `docker compose up -d --force-recreate redis app` |
| `/login` returns 500 with `JSONDecodeError` | The app got an empty response for Keycloak metadata. Usually the `auth.itsm.test` block is missing from the Caddyfile (Caddy answers unknown hosts with an empty 200). Fix the Caddyfile, then `docker compose restart proxy` |
| Login fails with `invalid_client` | `OIDC_CLIENT_SECRET` is wrong or outdated – regenerate it, update `.env`, recreate the app |
| Keycloak keeps restarting | `docker compose logs keycloak --tail 50`; usually a broken `.env` or CRLF line endings in it |
| Admin login does not work | Keycloak uses `KC_ADMIN_PASSWORD` only on the very first start; changing `.env` later has no effect without `docker compose down -v` |

## Rules for the repository

- Never commit `.env`, `certs/` or any `*.pem` / `*.key` file.
- One branch and one pull request per step, merged into `main`.
- Passwords and secrets are blurred in report screenshots.
