"""Tests du moteur générique `pentaster.techniques` — AUCUN accès réseau.

`run_techniques` fait des vraies requêtes HTTP : on ne l'appelle jamais ici.
"""
from pentaster.techniques import TECHNIQUES, run_techniques, Finding, Http


def test_imports_work():
    assert TECHNIQUES is not None
    assert callable(run_techniques)
    assert Finding is not None
    assert Http is not None


def test_at_least_eight_techniques_registered():
    assert len(TECHNIQUES) >= 8


def test_every_technique_entry_is_name_and_callable():
    for entry in TECHNIQUES:
        assert isinstance(entry, tuple)
        assert len(entry) == 2
        name, fn = entry
        assert isinstance(name, str) and name
        assert callable(fn)


def test_http_base_strips_trailing_slash():
    http = Http("http://x/")
    assert http.base == "http://x"
    http2 = Http("http://x")
    assert http2.base == "http://x"


def test_finding_defaults():
    f = Finding("some-technique", "high", "http://x/path")
    assert f.evidence == ""
    assert f.confirmed is True
    assert f.raw == {}
    assert f.technique == "some-technique"
    assert f.severity == "high"
    assert f.url == "http://x/path"
