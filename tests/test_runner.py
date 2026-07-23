from pentaster.runner import DockerRunner, RunResult
from pentaster.workflow import Step


def step(**kw):
    base = {"id": "probe", "tool": "httpx", "image": "projectdiscovery/httpx:latest",
            "args": ["-u", "{{target}}", "-json"], "parser": "httpx"}
    base.update(kw)
    return Step(**base)


def test_rewrite_localhost():
    r = DockerRunner("/w")
    assert r.rewrite_target("http://localhost:3000") == "http://host.docker.internal:3000"
    assert r.rewrite_target("http://127.0.0.1:3000/x") == "http://host.docker.internal:3000/x"
    assert r.rewrite_target("http://example.com") == "http://example.com"


def test_build_command_structure():
    r = DockerRunner("/word/lists")
    cmd = r.build_command(step(), "http://localhost:3000")
    assert cmd[:5] == ["docker", "run", "--rm", "-v", "/word/lists:/wordlists"]
    assert "projectdiscovery/httpx:latest" in cmd
    assert "http://host.docker.internal:3000" in cmd
    assert "{{target}}" not in cmd


def test_run_uses_injected_docker_and_returns_result():
    calls = {}

    def fake_docker(argv):
        calls["argv"] = argv
        return ("STDOUT", "STDERR", 0)

    r = DockerRunner("/w", run_docker=fake_docker)
    res = r.run(step(), "http://localhost:3000")
    assert isinstance(res, RunResult)
    assert res.step_id == "probe"
    assert res.stdout == "STDOUT"
    assert res.exit_code == 0
    assert calls["argv"][0] == "docker"


def test_rewrite_does_not_corrupt_similar_hosts():
    r = DockerRunner("/w")
    assert r.rewrite_target("http://127.0.0.100:8080") == "http://127.0.0.100:8080"
    assert r.rewrite_target("http://notlocalhost.example.com") == "http://notlocalhost.example.com"
    assert r.rewrite_target("http://mylocalhost.internal") == "http://mylocalhost.internal"


def test_rewrite_still_maps_exact_local_hosts():
    r = DockerRunner("/w")
    assert r.rewrite_target("http://localhost:3000") == "http://host.docker.internal:3000"
    assert r.rewrite_target("http://127.0.0.1:3000/x") == "http://host.docker.internal:3000/x"
