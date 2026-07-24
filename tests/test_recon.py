import pytest

from pentaster.recon import parse_nmap_xml, run_recon, tcp_port_scan
from pentaster.scope import ScopeGuard


@pytest.fixture(autouse=True)
def _no_real_tcp(monkeypatch):
    # Par défaut, aucun port TCP réel ne répond (tests hermétiques). Les tests
    # qui veulent exercer le scan TCP passent leur propre `connect`.
    monkeypatch.setattr("pentaster.recon._socket_connect",
                        lambda h, p, timeout=0.6: False)


def test_tcp_port_scan_finds_open_ports():
    # `connect` factice : seul le port 3000 est "ouvert".
    services = tcp_port_scan("localhost", [22, 80, 3000],
                             connect=lambda h, p: p == 3000)
    assert [s.port for s in services] == [3000]
    assert services[0].name == "http-dev" and services[0].state == "open"


def test_run_recon_merges_tcp_scan(monkeypatch):
    # nmap ne renvoie rien ; le scan TCP (injecté) trouve le port 3000.
    monkeypatch.setattr("pentaster.recon._socket_connect",
                        lambda h, p, timeout=0.6: p == 3000)

    def fake_docker(argv):
        return ("", "", 1)   # nmap + httpx échouent → seul le TCP scan trouve

    r = run_recon("http://localhost:3000", guard=ScopeGuard([]),
                  wordlists_dir="/tmp", docker_fn=fake_docker)
    assert 3000 in [s.port for s in r.services]


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
        <service name="http-alt" product="Node.js" version=""/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

HTTPX_JSON = (
    '{"url": "http://localhost:3000", "status_code": 200, '
    '"tech": ["Angular", "Express"]}\n'
)


def test_parse_nmap_xml_returns_only_open_ports():
    services = parse_nmap_xml(NMAP_XML)
    assert len(services) == 2
    assert services[0].port == 80
    assert services[0].proto == "tcp"
    assert services[0].state == "open"
    assert services[0].name == "http"
    assert services[0].product == "nginx"
    assert services[0].version == "1.18.0"
    assert services[1].port == 3000
    assert services[1].name == "http-alt"
    assert services[1].product == "Node.js"


def test_parse_nmap_xml_empty_or_garbage_returns_empty_list():
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml("not xml at all <<<") == []
    assert parse_nmap_xml("<nmaprun></nmaprun>") == []


def fake_docker_dispatch(argv):
    if any("nmap" in a for a in argv):
        return (NMAP_XML, "", 0)
    if any("httpx" in a for a in argv):
        return (HTTPX_JSON, "", 0)
    return ("", "unknown image", 1)


def test_run_recon_returns_services_and_tech():
    guard = ScopeGuard(["localhost"])
    result = run_recon(
        "http://localhost:3000",
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
    )
    ports = {s.port for s in result.services}
    assert ports == {80, 3000}
    assert "Angular" in result.tech
    assert "Express" in result.tech


def test_run_recon_docker_vm_caveat_note_for_localhost():
    guard = ScopeGuard(["localhost"])
    result = run_recon(
        "http://localhost:3000",
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
    )
    assert result.docker_target == "host.docker.internal"
    assert any("host.docker.internal" in n for n in result.notes)


def test_run_recon_passes_bare_host_to_nmap_not_full_url():
    captured = {}

    def capturing_docker(argv):
        if any("nmap" in a for a in argv):
            captured["argv"] = argv
            return (NMAP_XML, "", 0)
        return (HTTPX_JSON, "", 0)

    guard = ScopeGuard(["localhost"])
    run_recon(
        "http://localhost:3000",
        guard=guard,
        wordlists_dir="/w",
        docker_fn=capturing_docker,
    )
    argv = captured["argv"]
    # bare rewritten host must be present, but not the full original URL
    assert "host.docker.internal" in argv
    assert "http://localhost:3000" not in argv
    assert not any("http://localhost:3000" in a for a in argv)


def test_run_recon_never_raises_on_tool_failure():
    def failing_docker(argv):
        return ("", "boom", 1)

    guard = ScopeGuard(["localhost"])
    result = run_recon(
        "http://localhost:3000",
        guard=guard,
        wordlists_dir="/w",
        docker_fn=failing_docker,
    )
    assert result.services == []
    assert result.tech == []
    assert result.notes  # some note recorded


def test_run_recon_progress_callback_fires_for_ports_and_brackets():
    events = []

    def progress(phase, event, payload):
        events.append((phase, event, payload))

    guard = ScopeGuard(["localhost"])
    run_recon(
        "http://localhost:3000",
        guard=guard,
        wordlists_dir="/w",
        docker_fn=fake_docker_dispatch,
        progress=progress,
    )
    kinds = {(p, e) for p, e, _ in events}
    assert ("recon", "start") in kinds
    assert ("recon", "done") in kinds
    port_events = [ev for ev in events if ev[0] == "recon" and ev[1] == "port"]
    assert len(port_events) >= 1
    tech_events = [ev for ev in events if ev[0] == "recon" and ev[1] == "tech"]
    assert len(tech_events) >= 1
