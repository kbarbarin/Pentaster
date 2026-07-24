"""access-control (IDOR), auth (creds/JWT), data-exposure, misconfig,
redirect — un cas vulnérable et un cas sûr par module, plus un garde-fou de
scope. Aucune requête réseau réelle."""
from pentaster.attacks.access_control import t_idor
from pentaster.attacks.auth_broken import t_default_credentials, t_jwt_none_alg
from pentaster.attacks.base import AttackContext
from pentaster.attacks.data_exposure import t_null_byte_backup_exposure, t_sensitive_files
from pentaster.attacks.misconfig import t_cors_misconfig, t_security_headers, t_verbose_errors
from pentaster.attacks.redirect import t_open_redirect
from pentaster.scan_models import Endpoint, Form, SiteMap
from pentaster.scope import ScopeGuard

ORIGIN = "http://localhost:3000"


class RoutedHttp:
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


# --------------------------------------------------------------- IDOR/access
def test_idor_detects_distinct_neighbor_object():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/orders/42", method="GET"),
    ])
    http = (RoutedHttp()
            .when_get(lambda p, kw: p.endswith("/api/orders/42"),
                     (200, {}, '{"id":42,"owner":"alice","total":100}'))
            .when_get(lambda p, kw: p.endswith("/api/orders/41"),
                     (200, {}, '{"id":41,"owner":"bob","total":55}')))
    ctx = make_ctx(sitemap, http)
    findings = t_idor(ctx)
    assert len(findings) == 1
    assert findings[0].category == "access-control"
    assert findings[0].severity == "high"


def test_idor_safe_when_neighbor_not_found():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/orders/42", method="GET"),
    ])
    http = RoutedHttp().when_get(lambda p, kw: p.endswith("/api/orders/42"),
                                 (200, {}, '{"id":42,"owner":"alice"}'))
    ctx = make_ctx(sitemap, http)
    assert t_idor(ctx) == []


def test_idor_safe_when_neighbor_identical_content():
    """Même contenu renvoyé pour le voisin (ex. page générique) : pas d'IDOR."""
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/orders/42", method="GET"),
    ])
    http = RoutedHttp().when_get(lambda p, kw: "/api/orders/" in p,
                                 (200, {}, '{"msg":"same for everyone"}'))
    ctx = make_ctx(sitemap, http)
    assert t_idor(ctx) == []


# ---------------------------------------------------------------------- auth
def test_default_credentials_detects_admin_admin():
    sitemap = SiteMap(origin=ORIGIN, forms=[
        Form(action=f"{ORIGIN}/login", method="POST",
            fields=(("email", "email"), ("password", "password"))),
    ])
    http = (RoutedHttp()
            .when_post(lambda p, kw: (kw.get("data") or {}).get("email") == "admin"
                      and (kw.get("data") or {}).get("password") == "admin",
                      (200, {}, '{"token":"abc"}'))
            .when_post(lambda p, kw: True, (401, {}, "invalid")))
    ctx = make_ctx(sitemap, http)
    findings = t_default_credentials(ctx)
    assert len(findings) == 1
    assert findings[0].category == "auth"
    assert findings[0].severity == "high"


def test_default_credentials_safe_when_all_rejected():
    sitemap = SiteMap(origin=ORIGIN, forms=[
        Form(action=f"{ORIGIN}/login", method="POST",
            fields=(("email", "email"), ("password", "password"))),
    ])
    http = RoutedHttp().when_post(lambda p, kw: True, (401, {}, "invalid"))
    ctx = make_ctx(sitemap, http)
    assert t_default_credentials(ctx) == []


def test_jwt_none_alg_accepted_by_protected_endpoint():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/me", method="GET"),
    ])
    http = (RoutedHttp()
            .when_get(lambda p, kw: "Bearer" in str((kw.get("headers") or {}).get("Authorization", "")),
                     (200, {}, '{"email":"pentaster@none.tld"}'))
            .when_get(lambda p, kw: True, (401, {}, "unauthorized")))
    ctx = make_ctx(sitemap, http)
    findings = t_jwt_none_alg(ctx)
    assert len(findings) == 1
    assert findings[0].category == "auth"
    assert findings[0].severity == "high"


def test_jwt_none_alg_safe_when_rejected():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/me", method="GET"),
    ])
    http = RoutedHttp().when_get(lambda p, kw: True, (401, {}, "unauthorized"))
    ctx = make_ctx(sitemap, http)
    assert t_jwt_none_alg(ctx) == []


# ------------------------------------------------------------- data exposure
def test_sensitive_files_detects_dotenv_leak():
    http = RoutedHttp().when_get(lambda p, kw: p == "/.env",
                                 (200, {}, "DB_PASSWORD=secret\nAPI_KEY=xyz\n"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    findings = t_sensitive_files(ctx)
    assert len(findings) == 1
    assert findings[0].category == "data-exposure"
    assert findings[0].severity == "medium"


def test_sensitive_files_safe_when_all_404():
    http = RoutedHttp().when_get(lambda p, kw: True, (404, {}, "not found"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    assert t_sensitive_files(ctx) == []


def test_null_byte_backup_exposure_detects_bypass():
    http = RoutedHttp().when_get(lambda p, kw: p == "/backup.zip%2500.md",
                                 (200, {}, "PK\x03\x04 binary-ish backup contents"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    findings = t_null_byte_backup_exposure(ctx)
    assert len(findings) == 1
    assert findings[0].category == "data-exposure"


def test_null_byte_backup_exposure_safe_when_404():
    http = RoutedHttp().when_get(lambda p, kw: True, (404, {}, ""))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    assert t_null_byte_backup_exposure(ctx) == []


# ----------------------------------------------------------------- misconfig
def test_missing_security_headers_detected():
    http = RoutedHttp().when_get(lambda p, kw: p == "/", (200, {}, "<html></html>"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    findings = t_security_headers(ctx)
    assert len(findings) == 1
    assert findings[0].category == "misconfig"
    assert findings[0].severity == "low"


def test_security_headers_safe_when_all_present():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
    }
    http = RoutedHttp().when_get(lambda p, kw: p == "/", (200, headers, "<html></html>"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    assert t_security_headers(ctx) == []


def test_cors_misconfig_detects_reflected_origin():
    evil = "https://evil.attacker.example"
    http = RoutedHttp().when_get(
        lambda p, kw: (kw.get("headers") or {}).get("Origin") == evil,
        (200, {"Access-Control-Allow-Origin": evil}, "<html></html>"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    findings = t_cors_misconfig(ctx)
    assert len(findings) == 1
    assert findings[0].category == "misconfig"
    assert findings[0].severity == "medium"


def test_cors_misconfig_safe_when_not_reflected():
    http = RoutedHttp().when_get(lambda p, kw: True, (200, {}, "<html></html>"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    assert t_cors_misconfig(ctx) == []


def test_verbose_errors_detects_stack_trace():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[Endpoint(url=f"{ORIGIN}/api/products/1", method="GET")])
    http = RoutedHttp().when_get(
        lambda p, kw: p.endswith("/@@@"),
        (500, {}, "Traceback (most recent call last):\n  File x, line 1"))
    ctx = make_ctx(sitemap, http)
    findings = t_verbose_errors(ctx)
    assert len(findings) == 1
    assert findings[0].category == "misconfig"
    assert findings[0].severity == "low"


def test_verbose_errors_safe_when_generic_500():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[Endpoint(url=f"{ORIGIN}/api/products/1", method="GET")])
    http = RoutedHttp().when_get(lambda p, kw: True, (500, {}, "internal server error"))
    ctx = make_ctx(sitemap, http)
    assert t_verbose_errors(ctx) == []


# ------------------------------------------------------------------ redirect
def test_open_redirect_detects_external_location():
    evil = "https://evil.attacker.example"
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/go": {"redirect"}})
    http = RoutedHttp().when_get(lambda p, kw: "redirect=" in p,
                                 (302, {"Location": evil + "/"}, ""))
    ctx = make_ctx(sitemap, http)
    findings = t_open_redirect(ctx)
    assert len(findings) == 1
    assert findings[0].category == "redirect"
    assert findings[0].severity == "medium"


def test_open_redirect_safe_when_location_internal():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/go": {"redirect"}})
    http = RoutedHttp().when_get(lambda p, kw: True, (302, {"Location": "/home"}, ""))
    ctx = make_ctx(sitemap, http)
    assert t_open_redirect(ctx) == []


def test_open_redirect_ignores_unrelated_param_names():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/search": {"q"}})
    http = RoutedHttp().when_get(lambda p, kw: True,
                                 (302, {"Location": "https://evil.attacker.example/"}, ""))
    ctx = make_ctx(sitemap, http)
    assert t_open_redirect(ctx) == []


# --------------------------------------------------------------- scope guard
def test_safe_get_blocked_out_of_scope_no_request_emitted():
    http = RoutedHttp().when_get(lambda p, kw: True, (200, {}, "DB_PASSWORD=secret"))
    ctx = make_ctx(SiteMap(origin=ORIGIN), http)
    st, headers, body = ctx.safe_get("http://evil.attacker.example/.env")
    assert (st, headers, body) == (-1, {}, "")
    assert http.calls == []
