"""XSS réfléchi + stocké : réflexion/persistance non encodée = vulnérable ;
échappement HTML = sûr (contrôle négatif/anti-faux-positif exercé). Aucune
requête réseau réelle."""
import urllib.parse as up

from pentaster.attacks.base import AttackContext
from pentaster.attacks.xss import t_reflected_xss, t_stored_xss
from pentaster.scan_models import Endpoint, Form, SiteMap
from pentaster.scope import ScopeGuard

ORIGIN = "http://localhost:3000"


class ReflectHttp:
    """Simule une appli qui reflète (GET) et/ou stocke (POST) l'entrée
    utilisateur, avec ou sans échappement HTML selon `escape`."""

    def __init__(self, escape: bool):
        self.escape = escape
        self.stored = None
        self.calls: list = []

    def _render(self, value: str) -> str:
        return value.replace("<", "&lt;").replace(">", "&gt;") if self.escape else value

    def get(self, path, **kw):
        self.calls.append(("GET", path, kw))
        parts = up.urlsplit(path)
        qs = up.parse_qs(parts.query)
        reflected = ""
        if qs:
            last_param = list(qs)[-1]
            reflected = up.unquote(qs[last_param][-1])
        body = "<html><body>"
        if reflected:
            body += self._render(reflected)
        if self.stored:
            body += self.stored
        body += "</body></html>"
        return (200, {"Content-Type": "text/html"}, body)

    def post(self, path, **kw):
        self.calls.append(("POST", path, kw))
        data = kw.get("data") or {}
        for v in data.values():
            if isinstance(v, str) and "<script>" in v:
                self.stored = self._render(v)
        return (200, {}, "submitted")


def make_ctx(sitemap, http, origin=ORIGIN, allowed=None):
    return AttackContext(http=http, sitemap=sitemap, guard=ScopeGuard(allowed or []), origin=origin)


# ------------------------------------------------------------- reflected XSS
def test_reflected_xss_detects_unencoded_reflection():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/search": {"q"}})
    ctx = make_ctx(sitemap, ReflectHttp(escape=False))
    findings = t_reflected_xss(ctx)
    assert len(findings) == 1
    assert findings[0].category == "xss"
    assert findings[0].severity == "medium"


def test_reflected_xss_safe_when_html_escaped():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/search": {"q"}})
    ctx = make_ctx(sitemap, ReflectHttp(escape=True))
    assert t_reflected_xss(ctx) == []


# ----------------------------------------------------------------- stored XSS
def test_stored_xss_detects_persistent_marker():
    sitemap = SiteMap(
        origin=ORIGIN,
        forms=[Form(action=f"{ORIGIN}/comments", method="POST", fields=(("body", "text"),))],
        endpoints=[Endpoint(url=f"{ORIGIN}/comments", method="GET")],
    )
    ctx = make_ctx(sitemap, ReflectHttp(escape=False))
    findings = t_stored_xss(ctx)
    assert len(findings) == 1
    assert findings[0].category == "xss"
    assert findings[0].severity == "high"


def test_stored_xss_safe_when_escaped_on_replay():
    sitemap = SiteMap(
        origin=ORIGIN,
        forms=[Form(action=f"{ORIGIN}/comments", method="POST", fields=(("body", "text"),))],
        endpoints=[Endpoint(url=f"{ORIGIN}/comments", method="GET")],
    )
    ctx = make_ctx(sitemap, ReflectHttp(escape=True))
    assert t_stored_xss(ctx) == []


def test_stored_xss_no_forms_is_safe():
    sitemap = SiteMap(origin=ORIGIN)
    ctx = make_ctx(sitemap, ReflectHttp(escape=False))
    assert t_stored_xss(ctx) == []


# --------------------------------------------------------------- scope guard
def test_safe_get_blocked_out_of_scope_no_request_emitted():
    sitemap = SiteMap(origin=ORIGIN, params={f"{ORIGIN}/search": {"q"}})
    http = ReflectHttp(escape=False)
    ctx = make_ctx(sitemap, http)
    st, headers, body = ctx.safe_get("http://evil.attacker.example/search?q=x")
    assert (st, headers, body) == (-1, {}, "")
    assert http.calls == []
