from pentaster.attacks.base import (
    AttackContext, is_spa_shell, negative_control_confirms,
)
from pentaster.scan_models import SiteMap
from pentaster.scope import ScopeGuard


class FakeHttp:
    def __init__(self):
        self.calls = []

    def get(self, path, **kw):
        self.calls.append(("GET", path, kw))
        return (200, {}, "OK")

    def post(self, path, **kw):
        self.calls.append(("POST", path, kw))
        return (200, {}, "OK")


def make_ctx(origin="http://localhost:3000", extra=None):
    return AttackContext(http=FakeHttp(), sitemap=SiteMap(origin=origin),
                         guard=ScopeGuard([]), origin=origin,
                         extra_headers=extra or {})


def test_safe_get_allows_in_scope():
    ctx = make_ctx()
    st, _, body = ctx.safe_get("/api/x")
    assert st == 200 and body == "OK"
    assert ctx.http.calls == [("GET", "/api/x", {})]


def test_safe_get_blocks_out_of_scope_absolute_url():
    ctx = make_ctx()
    st, _, body = ctx.safe_get("http://evil.attacker.example/x")
    assert st == -1 and body == ""
    assert ctx.http.calls == []          # aucune requête émise hors scope


def test_safe_post_merges_auth_headers():
    ctx = make_ctx(extra={"Authorization": "Bearer tok"})
    ctx.safe_post("/api/x", data={"a": 1})
    method, path, kw = ctx.http.calls[0]
    assert method == "POST"
    assert kw["headers"]["Authorization"] == "Bearer tok"


def test_is_spa_shell():
    assert is_spa_shell("<!DOCTYPE html><html><app-root></app-root></html>")
    assert not is_spa_shell('{"key":"value"}')


def test_negative_control_confirms():
    assert negative_control_confirms("MARK", "x MARK y", "no marker here")
    assert not negative_control_confirms("MARK", "x MARK y", "also MARK present")
    assert not negative_control_confirms("MARK", "clean", "clean")
