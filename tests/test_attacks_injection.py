"""SQLi, NoSQL, cmdi, SSTI, path traversal, XXE — un cas vulnérable et un cas
sûr par module, plus un garde-fou de scope. Aucune requête réseau réelle :
tout passe par un faux client HTTP piloté par des règles de correspondance."""
import urllib.parse as up

from pentaster.attacks.base import AttackContext, is_spa_shell
from pentaster.attacks.access_control import t_idor  # noqa: F401 (import sanity)
from pentaster.attacks.cmdi import t_command_injection
from pentaster.attacks.nosql import t_nosql_auth_bypass
from pentaster.attacks.sqli import t_error_based_sqli, t_sqli_auth_bypass
from pentaster.attacks.ssti import t_ssti
from pentaster.attacks.traversal import t_path_traversal
from pentaster.attacks.xxe import t_xxe
from pentaster.scan_models import Endpoint, Form, SiteMap
from pentaster.scope import ScopeGuard

ORIGIN = "http://localhost:3000"


class RoutedHttp:
    """Faux client HTTP : les réponses sont décidées par des prédicats
    (path[, kw]) -> bool, testés dans l'ordre d'ajout."""

    def __init__(self):
        self.get_rules: list = []
        self.post_rules: list = []
        self.calls: list = []

    def when_get(self, predicate, response):
        self.get_rules.append((predicate, response))
        return self

    def when_post(self, predicate, response):
        self.post_rules.append((predicate, response))
        return self

    def get(self, path, **kw):
        self.calls.append(("GET", path, kw))
        for pred, resp in self.get_rules:
            if pred(path, kw):
                return resp
        return (404, {}, "not found")

    def post(self, path, **kw):
        self.calls.append(("POST", path, kw))
        for pred, resp in self.post_rules:
            if pred(path, kw):
                return resp
        return (404, {}, "not found")


def make_ctx(sitemap, http, origin=ORIGIN, allowed=None):
    return AttackContext(http=http, sitemap=sitemap, guard=ScopeGuard(allowed or []), origin=origin)


# --------------------------------------------------------------------- SQLi
def test_error_based_sqli_detects_signature():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/search": {"q"}})
    http = RoutedHttp().when_get(lambda p, kw: "%27" in p,
                                 (200, {}, "SQLITE_ERROR: near \"'\": syntax error"))
    ctx = make_ctx(sitemap, http)
    findings = t_error_based_sqli(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "sqli"
    assert findings[0].severity == "high"


def test_error_based_sqli_no_signature_is_safe():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/search": {"q"}})
    http = RoutedHttp().when_get(lambda p, kw: True, (200, {}, "no results"))
    ctx = make_ctx(sitemap, http)
    assert t_error_based_sqli(ctx) == []


def test_error_based_sqli_builtin_fallback_when_sitemap_empty():
    """SiteMap sans param découvert : le module doit quand même sonder les
    endpoints/paramètres courants intégrés (repli), et détecter la fuite."""
    sitemap = SiteMap(origin=ORIGIN)
    http = RoutedHttp().when_get(
        lambda p, kw: "products/search" in p and "%27" in p,
        (200, {}, "SQLITE_ERROR: near \"'\": syntax error"))
    ctx = make_ctx(sitemap, http)
    findings = t_error_based_sqli(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "sqli"


def test_sqli_auth_bypass_builtin_fallback_when_sitemap_empty():
    """SiteMap sans formulaire découvert : le module doit quand même sonder
    les endpoints de login courants intégrés (repli)."""
    sitemap = SiteMap(origin=ORIGIN)
    http = (RoutedHttp()
            .when_post(_has_or_payload, (200, {}, '{"token":"abc123"}'))
            .when_post(lambda p, kw: True, (401, {}, '{"error":"invalid"}')))
    ctx = make_ctx(sitemap, http)
    findings = t_sqli_auth_bypass(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "sqli"


def _has_or_payload(path, kw):
    data = kw.get("data") or {}
    return any("OR" in str(v) for v in data.values())


def test_sqli_auth_bypass_detects_token_on_payload():
    sitemap = SiteMap(origin=ORIGIN, forms=[
        Form(action=f"{ORIGIN}/login", method="POST",
            fields=(("email", "email"), ("password", "password"))),
    ])
    http = (RoutedHttp()
            .when_post(_has_or_payload, (200, {}, '{"token":"abc123"}'))
            .when_post(lambda p, kw: True, (401, {}, '{"error":"invalid"}')))
    ctx = make_ctx(sitemap, http)
    findings = t_sqli_auth_bypass(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "sqli"
    assert findings[0].severity == "critical"


def test_sqli_auth_bypass_always_rejected_is_safe():
    sitemap = SiteMap(origin=ORIGIN, forms=[
        Form(action=f"{ORIGIN}/login", method="POST",
            fields=(("email", "email"), ("password", "password"))),
    ])
    http = RoutedHttp().when_post(lambda p, kw: True, (401, {}, '{"error":"invalid"}'))
    ctx = make_ctx(sitemap, http)
    assert t_sqli_auth_bypass(ctx) == []


# -------------------------------------------------------------------- NoSQL
def _has_operator_payload(path, kw):
    data = kw.get("data") or {}
    return any(isinstance(v, dict) for v in data.values())


def test_nosql_auth_bypass_detects_token_on_operator():
    sitemap = SiteMap(origin=ORIGIN, forms=[
        Form(action=f"{ORIGIN}/login", method="POST",
            fields=(("email", "email"), ("password", "password"))),
    ])
    http = (RoutedHttp()
            .when_post(_has_operator_payload, (200, {}, '{"token":"xyz"}'))
            .when_post(lambda p, kw: True, (401, {}, "invalid")))
    ctx = make_ctx(sitemap, http)
    findings = t_nosql_auth_bypass(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "nosql"
    assert findings[0].severity == "critical"


def test_nosql_auth_bypass_safe_when_rejected():
    sitemap = SiteMap(origin=ORIGIN, forms=[
        Form(action=f"{ORIGIN}/login", method="POST",
            fields=(("email", "email"), ("password", "password"))),
    ])
    http = RoutedHttp().when_post(lambda p, kw: True, (401, {}, "invalid"))
    ctx = make_ctx(sitemap, http)
    assert t_nosql_auth_bypass(ctx) == []


def test_nosql_auth_bypass_builtin_fallback_when_sitemap_empty():
    """SiteMap sans formulaire découvert : le module doit quand même sonder
    les endpoints de login courants intégrés (repli)."""
    sitemap = SiteMap(origin=ORIGIN)
    http = (RoutedHttp()
            .when_post(_has_operator_payload, (200, {}, '{"token":"xyz"}'))
            .when_post(lambda p, kw: True, (401, {}, "invalid")))
    ctx = make_ctx(sitemap, http)
    findings = t_nosql_auth_bypass(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "nosql"


# --------------------------------------------------------------------- cmdi
def _decoded(path):
    return up.unquote(path)


def test_command_injection_detects_id_output():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/ping": {"host"}})
    http = RoutedHttp().when_get(
        lambda p, kw: any(pl in _decoded(p) for pl in ["; id", "| id", "`id`", "$(id)", "& id"]),
        (200, {}, "uid=0(root) gid=0(root) groups=0(root)"))
    ctx = make_ctx(sitemap, http)
    findings = t_command_injection(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "cmdi"
    assert findings[0].severity == "critical"


def test_command_injection_safe_without_marker():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/ping": {"host"}})
    http = RoutedHttp().when_get(lambda p, kw: True, (200, {}, "pong"))
    ctx = make_ctx(sitemap, http)
    assert t_command_injection(ctx) == []


def test_command_injection_builtin_fallback_when_sitemap_empty():
    """SiteMap sans param découvert : le module doit quand même sonder les
    endpoints/paramètres courants intégrés (repli)."""
    sitemap = SiteMap(origin=ORIGIN)
    http = RoutedHttp().when_get(
        lambda p, kw: any(pl in _decoded(p) for pl in ["; id", "| id", "`id`", "$(id)", "& id"]),
        (200, {}, "uid=0(root) gid=0(root) groups=0(root)"))
    ctx = make_ctx(sitemap, http)
    findings = t_command_injection(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "cmdi"


# --------------------------------------------------------------------- SSTI
def test_ssti_detects_evaluated_expression():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/render": {"tpl"}})

    def handler(path, kw):
        decoded = _decoded(path)
        if "{{7*7}}" in decoded or "${7*7}" in decoded or "#{7*7}" in decoded:
            return (200, {}, "resultat: 49")
        return (200, {}, "resultat: erreur")

    class HandlerHttp:
        def __init__(self):
            self.calls = []

        def get(self, path, **kw):
            self.calls.append(("GET", path, kw))
            return handler(path, kw)

        def post(self, path, **kw):
            self.calls.append(("POST", path, kw))
            return (404, {}, "")

    ctx = make_ctx(sitemap, HandlerHttp())
    findings = t_ssti(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "ssti"
    assert findings[0].severity == "critical"


def test_ssti_negative_control_prevents_false_positive():
    """Le serveur renvoie toujours `49`, y compris pour le contrôle négatif
    (payload inerte) : aucun résultat ne doit être remonté."""
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/render": {"tpl"}})
    http = RoutedHttp().when_get(lambda p, kw: True, (200, {}, "value: 49 always"))
    ctx = make_ctx(sitemap, http)
    assert t_ssti(ctx) == []


def test_ssti_skips_spa_shell():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/render": {"tpl"}})
    shell = '<!DOCTYPE html><html><app-root>49</app-root></html>'
    assert is_spa_shell(shell)
    http = RoutedHttp().when_get(lambda p, kw: True, (200, {}, shell))
    ctx = make_ctx(sitemap, http)
    assert t_ssti(ctx) == []


def test_ssti_builtin_fallback_when_sitemap_empty():
    """SiteMap sans param découvert : le module doit quand même sonder les
    endpoints/paramètres courants intégrés (repli)."""
    sitemap = SiteMap(origin=ORIGIN)

    def handler(path, kw):
        decoded = _decoded(path)
        if "{{7*7}}" in decoded or "${7*7}" in decoded or "#{7*7}" in decoded:
            return (200, {}, "resultat: 49")
        return (200, {}, "resultat: erreur")

    class HandlerHttp:
        def __init__(self):
            self.calls = []

        def get(self, path, **kw):
            self.calls.append(("GET", path, kw))
            return handler(path, kw)

        def post(self, path, **kw):
            self.calls.append(("POST", path, kw))
            return (404, {}, "")

    ctx = make_ctx(sitemap, HandlerHttp())
    findings = t_ssti(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "ssti"


# ---------------------------------------------------------------- traversal
def test_path_traversal_detects_passwd_leak():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/download": {"file"}})
    http = RoutedHttp().when_get(
        lambda p, kw: "etc/passwd" in _decoded(p) or "etc%2fpasswd" in p.lower(),
        (200, {}, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"))
    ctx = make_ctx(sitemap, http)
    findings = t_path_traversal(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "traversal"
    assert findings[0].severity == "critical"


def test_path_traversal_safe_without_signature():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/download": {"file"}},
                      endpoints=[Endpoint(url=f"{ORIGIN}/static/report.pdf", method="GET")])
    http = RoutedHttp().when_get(lambda p, kw: True, (404, {}, "not found"))
    ctx = make_ctx(sitemap, http)
    assert t_path_traversal(ctx) == []


def test_path_traversal_builtin_fallback_when_sitemap_empty():
    """SiteMap sans param découvert : le module doit quand même sonder les
    endpoints/paramètres courants intégrés (repli)."""
    sitemap = SiteMap(origin=ORIGIN)
    http = RoutedHttp().when_get(
        lambda p, kw: "etc/passwd" in _decoded(p) or "etc%2fpasswd" in p.lower(),
        (200, {}, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"))
    ctx = make_ctx(sitemap, http)
    findings = t_path_traversal(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "traversal"


def test_path_traversal_null_byte_variant_on_endpoint():
    sitemap = SiteMap(origin=ORIGIN,
                      endpoints=[Endpoint(url=f"{ORIGIN}/static/report.pdf", method="GET")])
    http = RoutedHttp().when_get(
        lambda p, kw: p.endswith("%2500"),
        (200, {}, "root:x:0:0:root:/root:/bin/bash"))
    ctx = make_ctx(sitemap, http)
    findings = t_path_traversal(ctx)
    assert len(findings) >= 1
    assert findings[0].technique == "path-traversal-null-byte"


# --------------------------------------------------------------------- XXE
def test_xxe_detects_passwd_leak_on_xml_content_type():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/import", method="POST", content_type="application/xml"),
    ])
    http = RoutedHttp().when_post(
        lambda p, kw: "ENTITY" in str(kw.get("data", "")),
        (200, {}, "root:x:0:0:root:/root:/bin/bash"))
    ctx = make_ctx(sitemap, http)
    findings = t_xxe(ctx)
    assert len(findings) >= 1
    assert findings[0].category == "xxe"
    assert findings[0].severity == "critical"


def test_xxe_detects_via_file_upload_endpoint():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/file-upload", method="POST"),
    ])
    http = RoutedHttp().when_post(
        lambda p, kw: "ENTITY" in str(kw.get("data", "")),
        (200, {}, "root:x:0:0:root:/root:/bin/bash"))
    ctx = make_ctx(sitemap, http)
    assert len(t_xxe(ctx)) == 1


def test_xxe_safe_when_not_parsed():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/import", method="POST", content_type="application/xml"),
    ])
    http = RoutedHttp().when_post(lambda p, kw: True, (200, {}, "ok, imported"))
    ctx = make_ctx(sitemap, http)
    assert t_xxe(ctx) == []


# ------------------------------------------------------------- scope guard
def test_safe_get_blocked_out_of_scope_no_request_emitted():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/search": {"q"}})
    http = RoutedHttp().when_get(lambda p, kw: True, (200, {}, "SQLITE_ERROR"))
    ctx = make_ctx(sitemap, http)
    st, headers, body = ctx.safe_get("http://evil.attacker.example/search?q=%27")
    assert (st, headers, body) == (-1, {}, "")
    assert http.calls == []
