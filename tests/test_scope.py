import pytest
from pentaster.scope import ScopeGuard, ScopeError

def test_localhost_authorized_by_default():
    g = ScopeGuard([])
    assert g.is_authorized("http://localhost:3000")
    assert g.is_authorized("http://127.0.0.1:3000/path")

def test_host_of_extracts_hostname():
    g = ScopeGuard([])
    assert g.host_of("http://example.com:8080/x") == "example.com"
    assert g.host_of("not a url") is None

def test_exact_host_in_allowlist():
    g = ScopeGuard(["example.com"])
    assert g.is_authorized("https://example.com/anything")

def test_subdomain_of_allowed_entry():
    g = ScopeGuard(["example.com"])
    assert g.is_authorized("https://app.example.com")

def test_unlisted_host_refused():
    g = ScopeGuard(["example.com"])
    assert not g.is_authorized("https://evil.org")

def test_from_file_reads_entries(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("example.com\n# commentaire\n\nfoo.test\n")
    g = ScopeGuard.from_file(str(p))
    assert g.is_authorized("http://example.com")
    assert g.is_authorized("http://foo.test")
    assert not g.is_authorized("http://bar.test")

def test_scope_error_is_exception():
    assert issubclass(ScopeError, Exception)
