from pentaster.parsers import parse_httpx, parse_ffuf, parse_nuclei, get_parser, Finding

HTTPX = '{"url":"http://host.docker.internal:3000","status_code":200,"title":"OWASP Juice Shop","tech":["Angular","Express"]}\n'
FFUF = '{"results":[{"url":"http://host.docker.internal:3000/admin","status":200,"length":1234},{"url":"http://host.docker.internal:3000/ftp","status":200,"length":99}],"config":{}}'
NUCLEI = (
    '{"template-id":"tech-detect","info":{"name":"Angular detected","severity":"info"},"matched-at":"http://host.docker.internal:3000/"}\n'
    '{"template-id":"exposed-panel","info":{"name":"Admin panel exposed","severity":"medium"},"matched-at":"http://host.docker.internal:3000/admin"}\n'
)

def test_parse_httpx_returns_tech_finding():
    out = parse_httpx(HTTPX, "http://host.docker.internal:3000")
    assert len(out) == 1
    f = out[0]
    assert isinstance(f, Finding)
    assert f.tool == "httpx"
    assert f.type == "tech"
    assert f.severity == "info"
    assert "Angular" in f.evidence
    assert "200" in f.evidence

def test_parse_httpx_ignores_blank_lines():
    assert parse_httpx("\n  \n", "t") == []

def test_parse_ffuf_returns_endpoint_per_result():
    out = parse_ffuf(FFUF, "http://host.docker.internal:3000")
    assert len(out) == 2
    assert {f.name for f in out} == {
        "http://host.docker.internal:3000/admin",
        "http://host.docker.internal:3000/ftp",
    }
    assert all(f.type == "endpoint" and f.tool == "ffuf" for f in out)

def test_parse_ffuf_handles_empty():
    assert parse_ffuf('{"results":[],"config":{}}', "t") == []

def test_parse_nuclei_maps_severity_and_name():
    out = parse_nuclei(NUCLEI, "http://host.docker.internal:3000")
    assert len(out) == 2
    sev = {f.name: f.severity for f in out}
    assert sev["Admin panel exposed"] == "medium"
    assert sev["Angular detected"] == "info"
    assert all(f.type == "vulnerability" and f.tool == "nuclei" for f in out)

def test_parse_nuclei_ignores_malformed_lines():
    out = parse_nuclei("not json\n" + NUCLEI, "t")
    assert len(out) == 2

def test_get_parser_returns_callable():
    assert get_parser("nuclei") is parse_nuclei

def test_get_parser_unknown_raises():
    import pytest
    with pytest.raises(KeyError):
        get_parser("does-not-exist")
