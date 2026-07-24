"""Contrôle d'accès / IDOR : requête d'un identifiant voisin (id±1) sur les
endpoints découverts qui exposent un segment d'URL numérique, et comparaison
avec la réponse de référence.

Conservateur pour éviter les faux positifs : il faut deux réponses HTTP 200
non vides ET dont le contenu diffère (sinon l'appli protège correctement ou
renvoie la même page pour tous)."""
from __future__ import annotations

import re

from ..scan_models import Finding

NUM_SEG = re.compile(r"/(\d+)(?=$|[/?])")


def _neighbor(url: str, m: re.Match, delta: int) -> str | None:
    n = int(m.group(1)) + delta
    if n < 0:
        return None
    return url[:m.start(1)] + str(n) + url[m.end(1):]


def t_idor(ctx) -> list[Finding]:
    seen = set()
    for ep in list(ctx.sitemap.endpoints) + list(ctx.sitemap.api_endpoints):
        if ep.method.upper() != "GET" or ep.url in seen:
            continue
        matches = list(NUM_SEG.finditer(ep.url))
        if not matches:
            continue
        seen.add(ep.url)
        m = matches[-1]

        base_st, _, base_body = ctx.safe_get(ep.url)
        if base_st != 200 or not (base_body or "").strip():
            continue

        for delta in (1, -1):
            other_url = _neighbor(ep.url, m, delta)
            if not other_url or other_url == ep.url:
                continue
            st, _, body = ctx.safe_get(other_url)
            if st == 200 and (body or "").strip() and body != base_body:
                sign = "+" if delta > 0 else ""
                return [Finding("access-control", "idor-object-id-enumeration", "high",
                                other_url,
                                f"Objet voisin (id {sign}{delta}) accessible avec un contenu "
                                "distinct de la référence authentifiée",
                                request=f"GET {other_url}")]
    return []


ATTACKS = [
    ("access-control", "IDOR (object-id enumeration)", t_idor),
]
