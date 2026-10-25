#!/usr/bin/env python3
"""Sukuria .env iš .env.example su atsitiktiniais slaptažodžiais.
Esamo .env neperrašo. Paleisti iš projekto šakninio katalogo: python scripts/gen_env.py"""
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
example, target = root / ".env.example", root / ".env"

if target.exists():
    sys.exit(".env jau yra.")

GENERATE = {"KC_ADMIN_PASSWORD", "KC_DB_PASSWORD", "REDIS_PASSWORD", "FLASK_SECRET_KEY"}
values, lines = {}, []

for line in example.read_text(encoding="utf-8").splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        key, val = line.split("=", 1)
        key = key.strip()
        if key in GENERATE and not val:
            val = secrets.token_urlsafe(32)
        if key == "KC_ADMIN_USER" and not val:
            val = "kcadmin"
        if key == "REDIS_URL" and not val:
            val = f"redis://:{values['REDIS_PASSWORD']}@redis:6379/0"
        values[key] = val
        line = f"{key}={val}"
    lines.append(line)

target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")   # LF, ne CRLF
print(".env sukurtas. OIDC_CLIENT_SECRET ir ADMIN_TOOL_SECRET užpildykite po Keycloak konfigūravimo.")