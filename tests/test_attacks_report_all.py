"""Fix C — les modules d'attaque ne s'arrêtent plus à la première instance
confirmée : ils sondent TOUTES les cibles découvertes/repli et remontent
TOUTES les instances vulnérables, dédupliquées par (category, technique,
url). Aucune requête réseau réelle."""
from pentaster.attacks.access_control import t_idor
from pentaster.attacks.base import AttackContext, dedup_findings
from pentaster.attacks.sqli import t_error_based_sqli
from pentaster.attacks.xxe import t_xxe
from pentaster.scan_models import Endpoint, Finding, SiteMap
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


# ---------------------------------------------------------- dedup_findings
def test_dedup_findings_removes_exact_duplicates_keeps_distinct_technique():
    a = Finding("exploit", "Login Admin", "high", ORIGIN, "x")
    b = Finding("exploit", "Login Admin", "high", ORIGIN, "x")  # doublon exact
    c = Finding("exploit", "CSRF", "high", ORIGIN, "y")         # même URL, technique distincte
    out = dedup_findings([a, b, c])
    assert len(out) == 2
    assert {f.technique for f in out} == {"Login Admin", "CSRF"}


def test_dedup_findings_keeps_same_technique_on_different_urls():
    a = Finding("sqli", "sqli-error-based", "high", f"{ORIGIN}/a?q=%27")
    b = Finding("sqli", "sqli-error-based", "high", f"{ORIGIN}/b?q=%27")
    out = dedup_findings([a, b])
    assert len(out) == 2


# ------------------------------------------------------- report-all: sqli
def test_error_based_sqli_reports_every_vulnerable_endpoint():
    """Trois endpoints de recherche DISTINCTS, tous vulnérables : le module
    doit confirmer les TROIS instances, pas seulement la première."""
    sitemap = SiteMap(origin=ORIGIN, params={
        f"{ORIGIN}/search-a": {"q"},
        f"{ORIGIN}/search-b": {"q"},
        f"{ORIGIN}/search-c": {"q"},
    })
    http = RoutedHttp().when_get(
        lambda p, kw: "%27" in p,
        (200, {}, "SQLITE_ERROR: near \"'\": syntax error"))
    ctx = make_ctx(sitemap, http)
    findings = t_error_based_sqli(ctx)

    vulnerable_urls = {f"{ORIGIN}/search-a", f"{ORIGIN}/search-b", f"{ORIGIN}/search-c"}
    hit_urls = {f.url.split("?")[0] for f in findings}
    assert vulnerable_urls <= hit_urls
    assert all(f.category == "sqli" for f in findings)
    # Dédupliqué : aucune URL rapportée deux fois.
    assert len(findings) == len({f.url for f in findings})


# --------------------------------------------------------- report-all: xxe
def test_xxe_reports_every_vulnerable_endpoint():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/import1", method="POST", content_type="application/xml"),
        Endpoint(url=f"{ORIGIN}/api/import2", method="POST", content_type="application/xml"),
    ])
    http = RoutedHttp().when_post(
        lambda p, kw: "ENTITY" in str(kw.get("data", "")),
        (200, {}, "root:x:0:0:root:/root:/bin/bash"))
    ctx = make_ctx(sitemap, http)
    findings = t_xxe(ctx)
    assert len(findings) == 2
    assert {f.url for f in findings} == {f"{ORIGIN}/api/import1", f"{ORIGIN}/api/import2"}
    assert all(f.category == "xxe" for f in findings)


# ------------------------------------------------- report-all: access-control
def test_idor_reports_every_vulnerable_endpoint():
    sitemap = SiteMap(origin=ORIGIN, endpoints=[
        Endpoint(url=f"{ORIGIN}/api/orders/42", method="GET"),
        Endpoint(url=f"{ORIGIN}/api/invoices/10", method="GET"),
    ])
    http = (RoutedHttp()
            .when_get(lambda p, kw: p.endswith("/api/orders/42"),
                     (200, {}, '{"id":42,"owner":"alice"}'))
            .when_get(lambda p, kw: p.endswith("/api/orders/41"),
                     (200, {}, '{"id":41,"owner":"bob"}'))
            .when_get(lambda p, kw: p.endswith("/api/invoices/10"),
                     (200, {}, '{"id":10,"total":42}'))
            .when_get(lambda p, kw: p.endswith("/api/invoices/9"),
                     (200, {}, '{"id":9,"total":7}')))
    ctx = make_ctx(sitemap, http)
    findings = t_idor(ctx)
    assert len(findings) == 2
    assert all(f.category == "access-control" for f in findings)
    reported_bases = {f.url.rsplit("/", 1)[0] for f in findings}
    assert reported_bases == {f"{ORIGIN}/api/orders", f"{ORIGIN}/api/invoices"}
