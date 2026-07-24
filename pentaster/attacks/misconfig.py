"""Mauvaises configurations : en-têtes de sécurité absents, CORS permissif,
erreurs verboses divulguant une trace interne."""
from __future__ import annotations

import re

from ..scan_models import Finding

VERBOSE_RE = re.compile(
    r"at\s+\w+.*\(.*:\d+:\d+\)|Traceback \(most recent|SequelizeDatabaseError|"
    r"Cannot read propert|stack.*\n.*at ", re.I)


def t_security_headers(ctx) -> list[Finding]:
    st, headers, _ = ctx.safe_get("/")
    if st == -1:
        return []
    lc = {k.lower(): v for k, v in (headers or {}).items()}
    missing = [h for h in ("content-security-policy", "x-frame-options",
                           "strict-transport-security", "x-content-type-options")
               if h not in lc]
    if missing:
        return [Finding("misconfig", "missing-security-headers", "low",
                        ctx.origin.rstrip("/") + "/",
                        "En-têtes absents : " + ", ".join(missing), request="GET /")]
    return []


def t_cors_misconfig(ctx) -> list[Finding]:
    evil = "https://evil.attacker.example"
    st, headers, _ = ctx.safe_get("/", headers={"Origin": evil})
    acao = {k.lower(): v for k, v in (headers or {}).items()}.get("access-control-allow-origin", "")
    if acao in (evil, "*"):
        return [Finding("misconfig", "cors-misconfiguration", "medium",
                        ctx.origin.rstrip("/") + "/",
                        f"Access-Control-Allow-Origin reflète une origine arbitraire ({acao})",
                        request="GET /")]
    return []


def t_verbose_errors(ctx) -> list[Finding]:
    endpoints = [ep.url for ep in list(ctx.sitemap.endpoints) + list(ctx.sitemap.api_endpoints)]
    if not endpoints:
        endpoints = [ctx.origin.rstrip("/") + "/api/not-a-number"]
    for url in endpoints[:20]:
        probe = url.rstrip("/") + "/@@@"
        st, _, body = ctx.safe_get(probe)
        if st >= 400 and VERBOSE_RE.search((body or "")[:4000]):
            return [Finding("misconfig", "verbose-error-disclosure", "low", probe,
                            "Trace/erreur interne divulguée sur entrée invalide",
                            request=f"GET {probe}")]
    return []


ATTACKS = [
    ("misconfig", "Missing security headers", t_security_headers),
    ("misconfig", "CORS misconfiguration", t_cors_misconfig),
    ("misconfig", "Verbose error disclosure", t_verbose_errors),
]
