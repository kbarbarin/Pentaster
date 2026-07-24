"""Injection de commande OS — payloads classiques sur les paramètres
découverts par le crawl, confirmée par la signature de sortie de `id`."""
from __future__ import annotations

import re

from ..scan_models import Finding
from ._util import iter_param_targets, with_query_param

CMD_PAYLOADS = ["; id", "| id", "`id`", "$(id)", "& id"]
CMD_MARKER = re.compile(r"uid=\d+\(.*gid=\d+\(")


def t_command_injection(ctx) -> list[Finding]:
    for base_url, param in iter_param_targets(ctx.sitemap):
        for inj in CMD_PAYLOADS:
            target = with_query_param(base_url, param, "x" + inj)
            st, _, body = ctx.safe_get(target)
            if st in (-1, 404):
                continue
            if CMD_MARKER.search(body or ""):
                return [Finding("cmdi", "os-command-injection", "critical", target,
                                f"Sortie de `id` observée (injection `{inj}`)",
                                request=f"GET {target}")]
    return []


ATTACKS = [
    ("cmdi", "OS command injection", t_command_injection),
]
