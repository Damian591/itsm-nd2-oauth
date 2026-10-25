# ITSM PD2 – OAuth 2.0 (Authorization Code + PKCE) su Keycloak

## Architektūra

| Adresas | Komponentas | Paskirtis |
| --- | --- | --- |
| https://auth.itsm.test | Keycloak 26.8.1 | Autorizacijos serveris (OAuth 2.0 / OpenID Connect) |
| https://app.itsm.test | Flask programa (BFF) | Žiniatinklio programa „Saugūs užrašai“ (kuriama) |
| https://api.itsm.test | Flask API | Resursų serveris (kuriama) |
| http://localhost:8025 | Mailpit | Testinis el. paštas (atstatymo laiškai) |

Visi komponentai veikia Docker konteineriuose. HTTPS užtikrina Caddy su vietiniu mkcert sertifikatu. Į kompiuterį atidaryti tik 80/443 (Caddy) ir 8025 (Mailpit, tik `127.0.0.1`); Keycloak, PostgreSQL ir Redis pasiekiami tik vidiniame Docker tinkle.

## Reikalavimai

- **Windows 10/11** su WSL 2 (instrukcijos pateiktos Windows; macOS/Linux – pastabos skliaustuose)
- **Docker Desktop** (WSL 2 backend), Docker Compose v2
- **Git**, **Python 3.12+**, **mkcert**, **jq**
- **Chrome arba Edge** (Firefox Windows sistemoje gali nepasitikėti mkcert CA)

Windows diegimas (PowerShell kaip administratorius):

```powershell
wsl --install
winget install Docker.DockerDesktop Git.Git Python.Python.3.12 FiloSottile.mkcert jqlang.jq
```

Docker Desktop → Settings → General → **Use the WSL 2 based engine**. Docker Desktop turi būti paleistas.

## Pirmas paleidimas naujame kompiuteryje

Visos komandos – **paprastame** PowerShell, nebent nurodyta kitaip.

### 1. Klonuoti repozitoriją

Kelias be tarpų ir ne OneDrive kataloge:

```powershell
mkdir C:\Projects; cd C:\Projects
git clone https://github.com/Damian591/itsm-nd2-oauth.git
cd itsm-nd2-oauth
```

### 2. Domenai → 127.0.0.1

**PowerShell kaip administratorius:**

```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`r`n127.0.0.1  app.itsm.test auth.itsm.test api.itsm.test"
```

(macOS/Linux: `echo "127.0.0.1 app.itsm.test auth.itsm.test api.itsm.test" | sudo tee -a /etc/hosts`)

Patikrinti: `ping -n 1 auth.itsm.test` → `127.0.0.1`.

### 3. HTTPS sertifikatai (mkcert)

Projekto kataloge:

```powershell
mkcert -install
mkcert -cert-file certs\itsm.test.pem -key-file certs\itsm.test-key.pem app.itsm.test auth.itsm.test api.itsm.test
Copy-Item "$(mkcert -CAROOT)\rootCA.pem" certs\rootCA.pem
```

`mkcert -install` parodys Windows saugumo langą – spausti **Yes**.

- `certs/` į Git nekeliamas – kiekvienas kompiuteris turi savo sertifikatus.
- **Niekada nekopijuoti ir nesiųsti `rootCA-key.pem`** iš `mkcert -CAROOT` katalogo: su juo galima sukurti bet kuriai svetainei sertifikatą, kuriuo pasitikės jūsų kompiuteris.

### 4. Aplinkos kintamieji (`.env`)

```powershell
python scripts\gen_env.py
```

Skriptas sukuria `.env` su atsitiktiniais slaptažodžiais. `.env` į Git nekeliamas. `OIDC_CLIENT_SECRET` ir `ADMIN_TOOL_SECRET` užpildomi vėliau, nukopijavus iš Keycloak (žr. „Keycloak konfigūracija“).

### 5. Paleisti

```powershell
docker compose up -d
docker compose ps
docker compose logs -f keycloak     # laukti „Keycloak 26.8.1 ... started“, tada Ctrl+C
```

### 6. Patikrinti

| Kas | Laukiamas rezultatas |
| --- | --- |
| https://auth.itsm.test | Keycloak puslapis su spyna (be įspėjimų) |
| https://auth.itsm.test/admin | Prisijungimas su `KC_ADMIN_USER` / `KC_ADMIN_PASSWORD` iš `.env` |
| http://localhost:8025 | Mailpit pašto dėžutė |

```powershell
curl.exe -sS --ssl-no-revoke https://auth.itsm.test/realms/master/.well-known/openid-configuration | jq .issuer
# -> "https://auth.itsm.test/realms/master"
curl.exe -sI http://auth.itsm.test
# -> 308 Permanent Redirect, Location: https://auth.itsm.test/
curl.exe -sSI --ssl-no-revoke https://auth.itsm.test
# -> Strict-Transport-Security, X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer
```

`--ssl-no-revoke` reikalingas tik Windows `curl.exe`: mkcert sertifikatai neturi atšaukimo (CRL/OCSP) serverio. Pats sertifikatas toliau tikrinamas.

## Kasdienis naudojimas

```powershell
docker compose up -d          # paleisti
docker compose ps             # būsena
docker compose logs -f <servisas>
docker compose down           # sustabdyti (duomenys išlieka)
docker compose down -v        # sustabdyti IR ištrinti Keycloak DB (viskas iš naujo)
```

## Keycloak konfigūracija


## Dažnos problemos

| Problema | Sprendimas |
| --- | --- |
| `bind: address already in use` (80/443) | Prievadą užima kita programa (IIS, Skype ir pan.) – ją sustabdyti |
| Naršyklė rodo „Not secure“ | Po `mkcert -install` iš naujo paleisti naršyklę; naudoti Chrome/Edge |
| `curl.exe` nieko neišveda | Pridėti `-sS --ssl-no-revoke` (žr. aukščiau) |
| Keycloak nuolat persikrauna | `docker compose logs keycloak --tail 50`; dažniausiai – neteisingas `.env` arba CRLF eilučių pabaigos `.env` faile |
| Prisijungimas prie admin nepavyksta | `.env` turi būti su LF eilučių pabaigomis; slaptažodis keičiasi tik su `docker compose down -v` (nauja DB) |

## Dokumentai
