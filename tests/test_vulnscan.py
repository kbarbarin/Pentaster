"""Stage 5 — nuclei (Docker) + détection auto Juice-Shop-like + confirmation
par exploit réel (solveurs). Aucune requête réseau/Docker réelle : tout est
injecté (`docker_fn`, faux client HTTP, `solve_fn`)."""
from pentaster.scan_models import Finding
from pentaster.vulnscan import looks_like_juice_shop, run_exploit_phase, run_nuclei

TARGET = "http://localhost:3000"

NUCLEI_JSONL = (
    '{"template-id":"exposed-panel","info":{"name":"Admin panel exposed","severity":"medium"},'
    '"matched-at":"http://localhost:3000/admin"}\n'
    '{"template-id":"tech-detect","info":{"name":"Angular detected","severity":"info"},'
    '"matched-at":"http://localhost:3000/"}\n'
)


# --------------------------------------------------------------------- nuclei
def test_run_nuclei_converts_jsonl_to_findings():
    def fake_docker(argv):
        assert any("nuclei" in a for a in argv)
        return (NUCLEI_JSONL, "", 0)

    findings = run_nuclei(TARGET, wordlists_dir="/w", docker_fn=fake_docker)
    assert len(findings) == 2
    assert all(f.category == "nuclei" for f in findings)
    by_name = {f.technique: f for f in findings}
    assert by_name["Admin panel exposed"].severity == "medium"
    assert by_name["Admin panel exposed"].url == "http://localhost:3000/admin"
    assert "exposed-panel" in by_name["Admin panel exposed"].evidence
    assert by_name["Angular detected"].severity == "info"


def test_run_nuclei_returns_empty_on_docker_failure():
    def fake_docker(argv):
        return ("", "docker: command not found", 1)

    assert run_nuclei(TARGET, wordlists_dir="/w", docker_fn=fake_docker) == []


def test_run_nuclei_returns_empty_when_docker_raises():
    def boom(argv):
        raise RuntimeError("docker daemon unreachable")

    assert run_nuclei(TARGET, wordlists_dir="/w", docker_fn=boom) == []


def test_run_nuclei_emits_progress_events():
    events = []

    def progress(phase, event, payload):
        events.append((phase, event))

    def fake_docker(argv):
        return (NUCLEI_JSONL, "", 0)

    run_nuclei(TARGET, wordlists_dir="/w", docker_fn=fake_docker, progress=progress)
    assert ("nuclei", "start") in events
    assert ("nuclei", "done") in events
    assert events.count(("nuclei", "finding")) == 2


# -------------------------------------------------------------- juice shop
class FakeHttp:
    def __init__(self, script):
        self.script = script
        self.calls = []

    def get(self, path, **kw):
        self.calls.append(path)
        return self.script.get(path, (404, {}, "not found"))


CHALLENGES_BODY = (
    '{"status":"success","data":[{"name":"Login Admin","solved":false},'
    '{"name":"CSRF","solved":false}]}'
)


def test_looks_like_juice_shop_detects_challenges_api():
    http = FakeHttp({"/api/Challenges/": (200, {}, CHALLENGES_BODY)})
    assert looks_like_juice_shop(http) is True


def test_looks_like_juice_shop_false_when_missing():
    http = FakeHttp({})
    assert looks_like_juice_shop(http) is False


def test_looks_like_juice_shop_false_on_garbage_body():
    http = FakeHttp({"/api/Challenges/": (200, {}, "<html>not json</html>")})
    assert looks_like_juice_shop(http) is False


# -------------------------------------------------------------- exploit phase
def test_run_exploit_phase_confirms_newly_solved_and_ran_ok():
    http = FakeHttp({"/api/Challenges/": (200, {}, CHALLENGES_BODY)})

    calls = []

    def fake_solve_fn(base_url, progress=None):
        calls.append(base_url)
        return {
            "before": 0, "after": 2, "total": 2,
            "newly_solved": ["Login Admin", "CSRF"],
            "ran": [("Login Admin", True), ("CSRF", True), ("Other", False)],
        }

    findings = run_exploit_phase(TARGET, http, solve_fn=fake_solve_fn)
    assert calls == [TARGET]
    assert len(findings) == 2
    assert {f.technique for f in findings} == {"Login Admin", "CSRF"}
    assert all(f.category == "exploit" and f.confirmed and f.severity == "high"
              for f in findings)
    assert all(f.url == TARGET for f in findings)


def test_run_exploit_phase_dedups_newly_solved_and_ran():
    http = FakeHttp({"/api/Challenges/": (200, {}, CHALLENGES_BODY)})

    def fake_solve_fn(base_url, progress=None):
        return {
            "before": 0, "after": 1, "total": 2,
            "newly_solved": ["Login Admin"],
            "ran": [("Login Admin", True), ("CSRF", False)],
        }

    findings = run_exploit_phase(TARGET, http, solve_fn=fake_solve_fn)
    assert len(findings) == 1
    assert findings[0].technique == "Login Admin"


def test_run_exploit_phase_skips_when_not_juice_shop_and_never_calls_solve_fn():
    http = FakeHttp({})  # /api/Challenges/ -> 404
    called = []

    def fake_solve_fn(base_url, progress=None):
        called.append(base_url)
        return {"newly_solved": ["should-not-appear"], "ran": []}

    findings = run_exploit_phase(TARGET, http, solve_fn=fake_solve_fn)
    assert findings == []
    assert called == []


def test_run_exploit_phase_never_raises_on_solve_fn_error():
    http = FakeHttp({"/api/Challenges/": (200, {}, CHALLENGES_BODY)})

    def boom(base_url, progress=None):
        raise RuntimeError("network unreachable")

    assert run_exploit_phase(TARGET, http, solve_fn=boom) == []


def test_run_exploit_phase_emits_progress_events():
    http = FakeHttp({"/api/Challenges/": (200, {}, CHALLENGES_BODY)})
    events = []

    def progress(phase, event, payload):
        events.append((phase, event))

    def fake_solve_fn(base_url, progress=None):
        return {"newly_solved": ["Login Admin"], "ran": [("Login Admin", True)]}

    run_exploit_phase(TARGET, http, solve_fn=fake_solve_fn, progress=progress)
    assert ("exploit", "start") in events
    assert ("exploit", "solved") in events
    assert ("exploit", "done") in events
