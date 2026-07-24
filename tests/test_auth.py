from pentaster.auth import AuthSession, authenticate
from pentaster.scope import ScopeGuard


class FakeHttp:
    """Http factice scriptée par chemin : path -> (status, headers, body)."""

    def __init__(self, base, script):
        self.base = base.rstrip("/")
        self.script = script
        self.calls = []

    def request(self, method, path, *, headers=None, data=None, raw=False):
        self.calls.append((method, path, headers, data))
        key = path
        if key in self.script:
            return self.script[key]
        return (404, {}, "not found")

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


def test_authenticate_success_via_bearer_token_from_login():
    script = {
        "/api/Users": (404, {}, ""),
        "/api/register": (404, {}, ""),
        "/register": (404, {}, ""),
        "/api/auth/register": (404, {}, ""),
        "/rest/user/login": (200, {}, '{"authentication": {"token": "abc.def.ghi"}}'),
    }
    http = FakeHttp("http://localhost:3000", script)
    guard = ScopeGuard(["localhost"])

    session = authenticate(http, "http://localhost:3000", guard=guard)

    assert isinstance(session, AuthSession)
    assert session.authenticated is True
    assert session.token == "abc.def.ghi"
    assert session.headers.get("Authorization") == "Bearer abc.def.ghi"
    assert session.email is not None and "@" in session.email


def test_authenticate_success_via_top_level_token_field():
    script = {
        "/api/login": (200, {}, '{"token": "xyz123"}'),
    }
    http = FakeHttp("http://t", script)
    guard = ScopeGuard(["t"])

    session = authenticate(http, "http://t", guard=guard)

    assert session.authenticated is True
    assert session.token == "xyz123"
    assert session.headers.get("Authorization") == "Bearer xyz123"


def test_authenticate_success_via_set_cookie():
    script = {
        "/login": (200, {"Set-Cookie": "session=deadbeef; Path=/; HttpOnly"}, "{}"),
    }
    http = FakeHttp("http://t", script)
    guard = ScopeGuard(["t"])

    session = authenticate(http, "http://t", guard=guard)

    assert session.authenticated is True
    assert "session=deadbeef" in session.headers.get("Cookie", "")


def test_authenticate_all_endpoints_fail_returns_unauthenticated_no_raise():
    http = FakeHttp("http://t", {})  # everything 404s
    guard = ScopeGuard(["t"])

    session = authenticate(http, "http://t", guard=guard)

    assert session.authenticated is False
    assert session.headers == {}
    assert session.token is None


def test_authenticate_never_raises_even_if_http_errors():
    class BoomHttp:
        base = "http://t"

        def request(self, *a, **kw):
            raise RuntimeError("boom")

        def get(self, path, **kw):
            return self.request("GET", path, **kw)

        def post(self, path, **kw):
            return self.request("POST", path, **kw)

    guard = ScopeGuard(["t"])
    session = authenticate(BoomHttp(), "http://t", guard=guard)
    assert session.authenticated is False


def test_authenticate_gates_out_of_scope_requests():
    """If the origin is not authorized by guard, authenticate must not call http at all."""
    http = FakeHttp("http://evil.example", {
        "/rest/user/login": (200, {}, '{"authentication": {"token": "should-not-happen"}}'),
    })
    guard = ScopeGuard(["localhost"])  # evil.example is NOT in scope

    session = authenticate(http, "http://evil.example", guard=guard)

    assert session.authenticated is False
    assert session.headers == {}
    assert http.calls == []  # never actually issued a request out of scope


def test_authenticate_emits_progress_events():
    events = []

    def progress(phase, event, detail):
        events.append((phase, event, detail))

    script = {
        "/rest/user/login": (200, {}, '{"authentication": {"token": "tok"}}'),
    }
    http = FakeHttp("http://t", script)
    guard = ScopeGuard(["t"])

    authenticate(http, "http://t", guard=guard, progress=progress)

    kinds = {(p, e) for p, e, _ in events}
    assert ("auth", "start") in kinds
    assert ("auth", "login-ok") in kinds


def test_authenticate_progress_login_fail_when_no_endpoint_works():
    events = []

    def progress(phase, event, detail):
        events.append((phase, event, detail))

    http = FakeHttp("http://t", {})
    guard = ScopeGuard(["t"])

    authenticate(http, "http://t", guard=guard, progress=progress)

    kinds = {(p, e) for p, e, _ in events}
    assert ("auth", "login-fail") in kinds


def test_authenticate_deterministic_email_for_same_origin():
    http1 = FakeHttp("http://t", {"/rest/user/login": (200, {}, '{"authentication": {"token": "a"}}')})
    http2 = FakeHttp("http://t", {"/rest/user/login": (200, {}, '{"authentication": {"token": "a"}}')})
    guard = ScopeGuard(["t"])

    s1 = authenticate(http1, "http://t", guard=guard)
    s2 = authenticate(http2, "http://t", guard=guard)

    assert s1.email == s2.email
