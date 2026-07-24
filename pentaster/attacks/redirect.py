"""Redirection non validée (open redirect) sur les paramètres découverts
dont le nom évoque une destination de redirection."""
from __future__ import annotations

from ..scan_models import Finding
from ._util import iter_param_targets, with_query_param

REDIRECT_PARAM_HINTS = ("redirect", "url", "to", "next", "returnurl", "dest",
                        "return", "continue")
EVIL = "https://evil.attacker.example"


def t_open_redirect(ctx) -> list[Finding]:
    for base_url, param in iter_param_targets(ctx.sitemap):
        if param.lower() not in REDIRECT_PARAM_HINTS:
            continue
        target = with_query_param(base_url, param, EVIL)
        st, headers, _ = ctx.safe_get(target)
        loc = {k.lower(): v for k, v in (headers or {}).items()}.get("location", "")
        if EVIL in loc:
            return [Finding("redirect", "open-redirect", "medium", target,
                            f"Redirection (Location) vers une URL externe via `{param}`",
                            request=f"GET {target}")]
    return []


ATTACKS = [
    ("redirect", "Open redirect", t_open_redirect),
]
