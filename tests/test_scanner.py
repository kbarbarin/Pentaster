"""Stage 4 — Orchestrateur : `run_full_scan` enchaîne recon/auth/crawl/attaques
sans jamais toucher au réseau ni à Docker (tout est injecté)."""
import pytest

from pentaster.scanner import run_full_scan
from pentaster.scope import ScopeError, ScopeGuard


@pytest.fixture(autouse=True)
def _no_real_tcp(monkeypatch):
    # Neutralise le scan TCP natif (sinon il tenterait de vraies connexions).
    monkeypatch.setattr("pentaster.recon._socket_connect",
                        lambda h, p, timeout=0.6: False)


ORIGIN = "http://localhost:3000"

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
        <service name="http-alt" product="Node.js" version=""/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

HTTPX_JSON = '{"url": "http://localhost:3000", "status_code": 200, "tech": ["Express"]}\n'

INDEX_HTML = """
<html><body>
<a href="/about">About</a>
<form action="/login" method="POST">
  <input name="email" type="email">
  <input name="password" type="password">
</form>
</body></html>
"""

ABOUT_HTML = "<html><body><p>About page.</p></body></html>"

# Note : pas d'en-têtes de sécurité (CSP/XFO/HSTS/nosniff) -> déclenche
# `t_security_headers` (misconfig) de façon déterministe.
HTML_HEADERS = {"content-type": "text/html; charset=utf-8"}


def fake_docker_dispatch(argv):
    if any("nmap" in a for a in argv):
        return (NMAP_XML, "", 0)
    if any("httpx" in a for a in argv):
        return (HTTPX_JSON, "", 0)
    return ("", "unknown image", 1)


class FakeHttp:
    """Http factice : chemins relatifs préfixés par `base`, script en URL absolue."""

    def __init__(self, base, script=None):
        self.base = base.rstrip("/")
        self.script = dict(script or {})
        self.calls = []

    def request(self, method, path, *, headers=None, data=None, raw=False):
        url = path if path.startswith("http") else self.base + path
        self.calls.append((method, url, headers))
        if url in self.script:
            return self.script[url]
        return (404, {}, "not found")

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)


def make_script():
    return {
        f"{ORIGIN}/": (200, HTML_HEADERS, INDEX_HTML),
        f"{ORIGIN}/about": (200, HTML_HEADERS, ABOUT_HTML),
        f"{ORIGIN}/login": (200, HTML_HEADERS, "<html><body>login</body></html>"),
    }


def make_http_factory(script=None):
    def factory(base):
        return FakeHttp(base, script or make_script())
    return factory


def test_run_full_scan_assembles_full_report():
    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        now=lambda: "t",
    )

    assert report.target == ORIGIN
    assert report.started_at == "t"
    assert report.finished_at == "t"

    assert report.recon is not None
    assert {s.port for s in report.recon.services} == {3000}
    assert "Express" in report.recon.tech

    assert report.sitemap is not None
    assert any("about" in e.url for e in report.sitemap.endpoints)
    assert len(report.sitemap.forms) == 1

    assert report.findings, "at least one attack module should have fired (missing headers)"
    assert any(f.category == "misconfig" for f in report.findings)

    assert report.timeline
    phases = {ev.phase for ev in report.timeline}
    assert {"recon", "auth", "crawl", "attack"} <= phases
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("recon", "start") in events
    assert ("recon", "done") in events
    assert ("crawl", "done") in events
    assert ("attack", "done") in events


def test_run_full_scan_findings_are_severity_sorted():
    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        now=lambda: "t",
    )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranks = [order.get(f.severity, 5) for f in report.findings]
    assert ranks == sorted(ranks)


def test_run_full_scan_out_of_scope_raises_scope_error():
    guard = ScopeGuard(["localhost"])
    with pytest.raises(ScopeError):
        run_full_scan(
            "http://example.com",
            guard=guard,
            wordlists_dir="/w",
            docker_fn=fake_docker_dispatch,
            http_factory=make_http_factory(),
            now=lambda: "t",
        )


def test_run_full_scan_no_auth_flag_skips_auth_phase():
    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        now=lambda: "t",
        do_auth=False,
    )
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("auth", "skipped") in events
    assert report.sitemap.authenticated is False


def test_run_full_scan_forwards_progress_events():
    events = []

    def progress(phase, event, payload):
        events.append((phase, event))

    guard = ScopeGuard(["localhost"])
    run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        now=lambda: "t",
        progress=progress,
    )
    # Les sous-modules émettent bien leur propre progression, relayée telle quelle.
    assert ("recon", "port") in events
    assert ("crawl", "endpoint") in events
    assert any(p == "attack" and e == "start" for p, e in events)


def test_run_full_scan_recon_failure_does_not_abort_scan(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("nmap docker exploded")

    monkeypatch.setattr("pentaster.scanner.run_recon", boom)

    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        now=lambda: "t",
    )
    assert report.recon.services == []
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("recon", "error") in events
    # Le reste du pipeline continue.
    assert ("crawl", "done") in events
    assert ("attack", "done") in events


def test_run_full_scan_crawl_failure_does_not_abort_scan(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("crawl exploded")

    monkeypatch.setattr("pentaster.scanner.run_crawl", boom)

    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        now=lambda: "t",
    )
    assert report.sitemap.endpoints == []
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("crawl", "error") in events
    # Le reste du pipeline continue et un ScanReport complet est bien rendu.
    assert ("attack", "done") in events
    assert report.finished_at == "t"


NUCLEI_JSONL = (
    '{"template-id":"exposed-panel","info":{"name":"Admin panel exposed","severity":"medium"},'
    '"matched-at":"http://localhost:3000/admin"}\n'
)

CHALLENGES_BODY = (
    '{"status":"success","data":[{"name":"Login Admin","solved":false},'
    '{"name":"CSRF","solved":false}]}'
)


def fake_docker_dispatch_with_nuclei(argv):
    if any("nmap" in a for a in argv):
        return (NMAP_XML, "", 0)
    if any("httpx" in a for a in argv):
        return (HTTPX_JSON, "", 0)
    if any("nuclei" in a for a in argv):
        return (NUCLEI_JSONL, "", 0)
    return ("", "unknown image", 1)


def test_run_full_scan_nuclei_phase_adds_findings():
    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch_with_nuclei,
        http_factory=make_http_factory(),
        now=lambda: "t",
    )
    nuclei_findings = [f for f in report.findings if f.category == "nuclei"]
    assert len(nuclei_findings) == 1
    assert nuclei_findings[0].technique == "Admin panel exposed"
    assert nuclei_findings[0].severity == "medium"
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("nuclei", "start") in events
    assert ("nuclei", "done") in events


def test_run_full_scan_exploit_phase_confirms_challenges_when_detected():
    script = make_script()
    script[f"{ORIGIN}/api/Challenges/"] = (200, {}, CHALLENGES_BODY)

    calls = []

    def fake_solve_fn(base_url, progress=None):
        calls.append(base_url)
        return {
            "before": 0, "after": 2, "total": 2,
            "newly_solved": ["Login Admin", "CSRF"],
            "ran": [("Login Admin", True), ("CSRF", True)],
        }

    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(script),
        solve_fn=fake_solve_fn,
        now=lambda: "t",
    )
    assert calls == [ORIGIN]
    exploit_findings = [f for f in report.findings if f.category == "exploit"]
    assert len(exploit_findings) == 2
    assert {f.technique for f in exploit_findings} == {"Login Admin", "CSRF"}
    assert all(f.confirmed and f.severity == "high" for f in exploit_findings)
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("exploit", "start") in events
    assert ("exploit", "done") in events


def test_run_full_scan_exploit_phase_skipped_when_not_juice_shop_like():
    """Cible générique (pas d'API /api/Challenges/) : le solveur d'exploit
    n'est JAMAIS invoqué et aucun finding 'exploit' n'apparaît."""
    called = []

    def fake_solve_fn(base_url, progress=None):
        called.append(base_url)
        return {"newly_solved": ["should-not-appear"], "ran": []}

    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        solve_fn=fake_solve_fn,
        now=lambda: "t",
    )
    assert called == []
    assert [f for f in report.findings if f.category == "exploit"] == []


def test_run_full_scan_deep_false_skips_nuclei_and_exploit_phases():
    called = []

    def fake_solve_fn(base_url, progress=None):
        called.append(base_url)
        return {"newly_solved": [], "ran": []}

    script = make_script()
    script[f"{ORIGIN}/api/Challenges/"] = (200, {}, CHALLENGES_BODY)

    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch_with_nuclei,
        http_factory=make_http_factory(script),
        solve_fn=fake_solve_fn,
        now=lambda: "t",
        deep=False,
    )
    assert called == []
    assert [f for f in report.findings if f.category == "nuclei"] == []
    assert [f for f in report.findings if f.category == "exploit"] == []
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("nuclei", "skipped") in events
    assert ("exploit", "skipped") in events


def test_run_full_scan_attack_failure_does_not_abort_scan(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("attacks exploded")

    monkeypatch.setattr("pentaster.scanner.run_attacks", boom)

    guard = ScopeGuard(["localhost"])
    report = run_full_scan(
        ORIGIN,
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        http_factory=make_http_factory(),
        now=lambda: "t",
    )
    assert report.findings == []
    events = {(ev.phase, ev.event) for ev in report.timeline}
    assert ("attack", "error") in events
    assert report.finished_at == "t"
