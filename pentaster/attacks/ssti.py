"""Server-Side Template Injection — évaluation d'une expression mathématique
sur les paramètres découverts, avec contrôle négatif anti-faux-positif et
garde anti-SPA (une SPA renvoie souvent la même coquille HTML pour tout)."""
from __future__ import annotations

from ..scan_models import Finding
from .base import is_spa_shell
from ._util import iter_param_targets, with_query_param

SSTI_PROBES = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49")]


def t_ssti(ctx) -> list[Finding]:
    for base_url, param in iter_param_targets(ctx.sitemap):
        for expr, expect in SSTI_PROBES:
            target = with_query_param(base_url, param, expr)
            st, _, body = ctx.safe_get(target)
            if st in (-1, 404) or is_spa_shell(body or ""):
                continue
            neg_target = with_query_param(base_url, param, "pz" + expr[2:])
            _, _, nbody = ctx.safe_get(neg_target)
            if expect in (body or "") and expr not in (body or "") and expect not in (nbody or ""):
                return [Finding("ssti", "server-side-template-injection", "critical", target,
                                f"Expression `{expr}` évaluée à `{expect}`",
                                request=f"GET {target}")]
    return []


ATTACKS = [
    ("ssti", "SSTI", t_ssti),
]
