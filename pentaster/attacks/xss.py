"""XSS réfléchi (marqueur unique par paramètre découvert, réflexion non
encodée en contenu HTML, contrôle négatif contre une page « propre ») et XSS
stocké (soumission d'un marqueur unique via un formulaire découvert, puis
re-GET de l'origine et de quelques endpoints pour détecter la persistance)."""
from __future__ import annotations

import secrets

from ..scan_models import Finding
from .base import MAX_TARGETS_PER_MODULE
from ._util import ci_header, merged_param_targets, with_query_param

# Repli intégré : endpoints/paramètres courants toujours sondés, même sans
# rien découvert par le crawl (SPA peu explorable).
COMMON_ENDPOINTS = ["/", "/search", "/rest/products/search", "/api/search"]
COMMON_PARAMS = ["q", "search", "query", "name", "redirect"]


def _fresh_payload() -> tuple[str, str]:
    marker = "pxss" + secrets.token_hex(4)
    return marker, f"<script>{marker}()</script>"


def t_reflected_xss(ctx) -> list[Finding]:
    """Sonde CHAQUE (endpoint, paramètre) découvert/repli et confirme toutes
    les réflexions non encodées (pas seulement la première)."""
    out: list[Finding] = []
    _marker, payload = _fresh_payload()
    targets = merged_param_targets(ctx.sitemap, ctx.origin, COMMON_ENDPOINTS, COMMON_PARAMS)
    targets = targets[:MAX_TARGETS_PER_MODULE]
    for base_url, param in targets:
        target = with_query_param(base_url, param, payload)
        st, headers, body = ctx.safe_get(target)
        ct = ci_header(headers, "content-type").lower()
        if st != 200 or "html" not in ct or payload not in (body or ""):
            continue
        base_st, _, base_body = ctx.safe_get(base_url)
        if base_st in (-1,):
            continue
        # Contrôle négatif : le payload ne doit PAS apparaître dans la page
        # « propre » (sans injection) — sinon ce serait du contenu statique.
        if payload not in (base_body or ""):
            out.append(Finding("xss", "reflected-xss", "medium", target,
                               f"Marqueur réfléchi sans encodage (param `{param}`)",
                               request=f"GET {target}"))
    return out


def t_stored_xss(ctx) -> list[Finding]:
    """Soumet le marqueur via chaque formulaire découvert, puis confirme
    TOUTES les pages sur lesquelles il persiste sans encodage (pas
    seulement la première relecture)."""
    out: list[Finding] = []
    _marker, payload = _fresh_payload()
    submitted = False
    for form in ctx.sitemap.forms:
        data = {name: payload for name, ftype in form.fields if ftype.lower() != "password"}
        if not data:
            continue
        st, _, _ = ctx.safe_post(form.action, data=data)
        if st != -1:
            submitted = True
    if not submitted:
        return out

    check_urls = [ctx.origin] + [ep.url for ep in ctx.sitemap.endpoints[:MAX_TARGETS_PER_MODULE]]
    for url in check_urls:
        st, headers, body = ctx.safe_get(url)
        ct = ci_header(headers, "content-type").lower()
        if st == 200 and "html" in ct and payload in (body or ""):
            out.append(Finding("xss", "stored-xss", "high", url,
                               "Marqueur soumis via un formulaire retrouvé persistant "
                               "(sans encodage) sur une page relue",
                               request=f"GET {url}"))
    return out


ATTACKS = [
    ("xss", "Reflected XSS", t_reflected_xss),
    ("xss", "Stored XSS", t_stored_xss),
]
