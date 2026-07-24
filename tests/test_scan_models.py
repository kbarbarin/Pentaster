from pentaster.scan_models import (
    Finding, Endpoint, Form, SiteMap, Service, ReconResult,
    TimelineEvent, ScanReport, scan_to_dict,
)


def make_report():
    sm = SiteMap(origin="http://t", authenticated=True,
                 endpoints=[Endpoint(url="http://t/x", method="GET", params=("id",))],
                 forms=[Form(action="/login", method="POST", fields=(("email", "email"),))],
                 params={"http://t/x": {"id", "q"}})
    recon = ReconResult(host="t", services=[Service(port=80, name="http")],
                        tech=["Angular"], notes=["caveat docker-vm"])
    f = Finding(category="sqli", technique="auth-bypass", severity="critical",
                url="http://t/login", evidence="401→200")
    return ScanReport(target="http://t", started_at="s", finished_at="f",
                      recon=recon, sitemap=sm, findings=[f],
                      timeline=[TimelineEvent(phase="recon", event="start")])


def test_scan_to_dict_serializes_sets():
    d = scan_to_dict(make_report())
    # SiteMap.params contient un set → doit devenir une liste triée
    assert d["sitemap"]["params"]["http://t/x"] == ["id", "q"]


def test_scan_to_dict_is_json_serializable():
    import json
    d = scan_to_dict(make_report())
    txt = json.dumps(d)               # ne doit pas lever
    assert "sqli" in txt and "Angular" in txt


def test_finding_defaults():
    f = Finding(category="xss", technique="reflected", severity="high", url="u")
    assert f.confirmed is True and f.evidence == "" and f.raw == {}


def test_scan_report_shape():
    r = make_report()
    assert r.recon.services[0].port == 80
    assert r.sitemap.authenticated is True
    assert r.findings[0].category == "sqli"
