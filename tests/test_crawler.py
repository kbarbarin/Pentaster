from pentaster.crawler import run_crawl
from pentaster.auth import AuthSession
from pentaster.scope import ScopeGuard


HTML_HEADERS = {"content-type": "text/html; charset=utf-8"}
JSON_HEADERS = {"content-type": "application/json"}

ORIGIN = "http://localhost:3000"


class FakeHttp:
    """Http factice : URL absolue -> (status, headers, body)."""

    def __init__(self, script):
        self.script = script
        self.calls = []

    def request(self, method, path, *, headers=None, data=None, raw=False):
        self.calls.append((method, path, headers))
        if path in self.script:
            return self.script[path]
        return (404, {}, "not found")

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


INDEX_HTML = """
<html><body>
<a href="/about">About</a>
<a href="/search?q=test&sort=asc">Search</a>
<a href="http://other-host.example/evil">Evil offsite</a>
<form action="/login" method="POST">
  <input name="email" type="email">
  <input name="password" type="password">
  <select name="remember"></select>
</form>
<p>API used: /api/products fetches data, also /rest/user/whoami</p>
</body></html>
"""

ABOUT_HTML = """<html><body><p>About page, no links here.</p></body></html>"""

SEARCH_HTML = """<html><body><a href="/about">back</a></body></html>"""


def make_script():
    return {
        f"{ORIGIN}/": (200, HTML_HEADERS, INDEX_HTML),
        f"{ORIGIN}/about": (200, HTML_HEADERS, ABOUT_HTML),
        f"{ORIGIN}/search?q=test&sort=asc": (200, HTML_HEADERS, SEARCH_HTML),
        f"{ORIGIN}/login": (200, HTML_HEADERS, "<html><body>login form page</body></html>"),
    }


def test_crawl_extracts_endpoints_forms_and_api_fragments():
    http = FakeHttp(make_script())
    guard = ScopeGuard(["localhost"])

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    urls = {e.url for e in sitemap.endpoints}
    assert any("about" in u for u in urls)
    assert any("search" in u for u in urls)

    assert len(sitemap.forms) == 1
    form = sitemap.forms[0]
    assert form.action.endswith("/login")
    assert form.method == "POST"
    field_names = {name for name, _typ in form.fields}
    assert {"email", "password", "remember"} <= field_names

    api_paths = {e.url for e in sitemap.api_endpoints}
    assert any("/api/products" in u for u in api_paths)
    assert any("/rest/user/whoami" in u for u in api_paths)


def test_crawl_records_query_params_in_sitemap_params():
    http = FakeHttp(make_script())
    guard = ScopeGuard(["localhost"])

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    search_key = next((k for k in sitemap.params if "search" in k), None)
    assert search_key is not None
    assert sitemap.params[search_key] == {"q", "sort"}


def test_crawl_same_origin_filter_rejects_other_host():
    http = FakeHttp(make_script())
    guard = ScopeGuard(["localhost"])

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    all_urls = [e.url for e in sitemap.endpoints] + [e.url for e in sitemap.api_endpoints]
    assert not any("other-host.example" in u for u in all_urls)
    # never even requested
    requested = {path for _, path, _ in http.calls}
    assert not any("other-host.example" in p for p in requested)


def test_crawl_respects_max_pages():
    http = FakeHttp(make_script())
    guard = ScopeGuard(["localhost"])

    run_crawl(ORIGIN, http=http, guard=guard, max_pages=1)

    # only the seed page fetched
    assert len(http.calls) <= 1


def test_crawl_respects_max_depth_on_a_deep_chain():
    # Build a chain: /d0 -> /d1 -> /d2 -> /d3 -> /d4 (each page links only to next)
    script = {}
    for i in range(5):
        nxt = f"/d{i+1}"
        html = f'<html><body><a href="{nxt}">next</a></body></html>'
        script[f"{ORIGIN}/d{i}"] = (200, HTML_HEADERS, html)

    http = FakeHttp(script)
    guard = ScopeGuard(["localhost"])

    run_crawl(
        ORIGIN, http=http, guard=guard,
        seeds=[f"{ORIGIN}/d0"], max_depth=2, max_pages=100,
    )

    fetched_paths = {p for _, p, _ in http.calls}
    # depth 0 = d0 (seed), depth 1 = d1, depth 2 = d2 -> d3 should NOT be fetched
    assert not any("d3" in p for p in fetched_paths)


def test_crawl_stub_scope_guard_rejects_host_blocks_crawl():
    class RejectAllGuard:
        def is_authorized(self, url):
            return False

        def host_of(self, url):
            return None

    http = FakeHttp(make_script())
    guard = RejectAllGuard()

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    assert sitemap.endpoints == []
    assert sitemap.forms == []
    assert http.calls == []


def test_crawl_sitemap_authenticated_reflects_session():
    http = FakeHttp(make_script())
    guard = ScopeGuard(["localhost"])
    session = AuthSession(headers={"Authorization": "Bearer tok"}, token="tok",
                          authenticated=True, email="pentaster_1@probe.tld")

    sitemap = run_crawl(ORIGIN, http=http, guard=guard, session=session)

    assert sitemap.authenticated is True
    # auth headers were actually forwarded on at least one request
    assert any(h and h.get("Authorization") == "Bearer tok" for _, _, h in http.calls)


def test_crawl_sitemap_authenticated_false_without_session():
    http = FakeHttp(make_script())
    guard = ScopeGuard(["localhost"])

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    assert sitemap.authenticated is False


def test_crawl_progress_callback_fires_for_endpoint_and_form():
    events = []

    def progress(phase, event, payload):
        events.append((phase, event, payload))

    http = FakeHttp(make_script())
    guard = ScopeGuard(["localhost"])

    run_crawl(ORIGIN, http=http, guard=guard, progress=progress)

    kinds = {(p, e) for p, e, _ in events}
    assert ("crawl", "endpoint") in kinds
    assert ("crawl", "form") in kinds


def test_crawl_skips_network_error_status_minus_one():
    script = make_script()
    script[f"{ORIGIN}/about"] = (-1, {}, "connection reset")
    http = FakeHttp(script)
    guard = ScopeGuard(["localhost"])

    # must not raise
    sitemap = run_crawl(ORIGIN, http=http, guard=guard)
    assert isinstance(sitemap.endpoints, list)


def test_crawl_discovers_api_endpoints_from_js_bundle():
    script = {
        f"{ORIGIN}/": (200, HTML_HEADERS,
                       '<html><body><script src="/main.js"></script></body></html>'),
        f"{ORIGIN}/main.js": (200, {"content-type": "application/javascript"},
                              'const routes=["/api/Users","/rest/user/login",'
                              '"/assets/logo.png"];fetch("/api/Users");'),
    }
    http = FakeHttp(script)
    guard = ScopeGuard(["localhost"])

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    api_urls = {e.url for e in sitemap.api_endpoints}
    assert any(u.endswith("/api/Users") for u in api_urls)
    assert any(u.endswith("/rest/user/login") for u in api_urls)
    # asset-like path should not be treated as an API endpoint
    assert not any("logo.png" in u for u in api_urls)


def test_crawl_js_bundle_fetch_is_bounded():
    scripts_html = "".join(f'<script src="/bundle{i}.js"></script>' for i in range(20))
    script = {f"{ORIGIN}/": (200, HTML_HEADERS, f"<html><body>{scripts_html}</body></html>")}
    for i in range(20):
        script[f"{ORIGIN}/bundle{i}.js"] = (
            200, {"content-type": "application/javascript"}, f'"/api/thing{i}"')
    http = FakeHttp(script)
    guard = ScopeGuard(["localhost"])

    run_crawl(ORIGIN, http=http, guard=guard)

    js_calls = [p for _, p, _ in http.calls if p.endswith(".js")]
    assert len(js_calls) <= 10


def test_crawl_seeds_common_endpoints_even_on_trivial_crawl():
    script = {f"{ORIGIN}/": (200, HTML_HEADERS, "<html><body>nothing here</body></html>")}
    http = FakeHttp(script)
    guard = ScopeGuard(["localhost"])

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    api_urls = {e.url for e in sitemap.api_endpoints}
    assert any(u.endswith("/rest/user/login") for u in api_urls)
    assert any(u.endswith("/api/Users") for u in api_urls)
    seed_sources = {e.source for e in sitemap.api_endpoints if e.url.endswith("/rest/user/login")}
    assert "seed" in seed_sources


def test_crawl_seed_endpoints_respect_scope_guard():
    class RejectAllGuard:
        def is_authorized(self, url):
            return False

        def host_of(self, url):
            return None

    http = FakeHttp(make_script())
    guard = RejectAllGuard()

    sitemap = run_crawl(ORIGIN, http=http, guard=guard)

    assert sitemap.api_endpoints == []


def test_crawl_does_not_follow_links_from_json_endpoints():
    script = {
        f"{ORIGIN}/": (200, HTML_HEADERS, '<html><body><a href="/data.json">data</a></body></html>'),
        f"{ORIGIN}/data.json": (200, JSON_HEADERS, '{"link": "<a href=\\"/should-not-be-parsed\\">x</a>"}'),
    }
    http = FakeHttp(script)
    guard = ScopeGuard(["localhost"])

    run_crawl(ORIGIN, http=http, guard=guard)

    fetched = {p for _, p, _ in http.calls}
    assert not any("should-not-be-parsed" in p for p in fetched)
