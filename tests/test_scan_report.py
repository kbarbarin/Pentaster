"""Stage 4 — Rapport riche : groupage par catégorie, rendu HTML (autoescape),
et écriture disque (`scan.json` / `scan.html`)."""
import json

from pentaster.scan_models import (
    Endpoint,
    Finding,
    Form,
    ReconResult,
    ScanReport,
    Service,
    SiteMap,
    TimelineEvent,
    scan_to_dict,
)
from pentaster.scan_report import group_by_category, render_scan_html, save_scan

TARGET = "http://localhost:3000"


def make_report(evidence_xss="Marqueur réfléchi") -> ScanReport:
    recon = ReconResult(
        host="localhost",
        docker_target="host.docker.internal",
        services=[Service(port=3000, proto="tcp", state="open", name="http-alt",
                          product="Node.js", version="")],
        tech=["Angular", "Express"],
        notes=["nmap s'exécute dans la VM Docker (host.docker.internal) — ports indicatifs."],
    )
    sitemap = SiteMap(
        origin=TARGET,
        endpoints=[
            Endpoint(url=f"{TARGET}/about", method="GET", source="link"),
            Endpoint(url=f"{TARGET}/search?q=x", method="GET", params=("q",), source="link"),
        ],
        forms=[Form(action=f"{TARGET}/login", method="POST",
                    fields=(("email", "email"), ("password", "password")))],
        api_endpoints=[Endpoint(url=f"{TARGET}/api/products", method="GET", source="api")],
        authenticated=True,
    )
    findings = [
        Finding("xss", "reflected-xss", "medium", f"{TARGET}/search?q=<script>1</script>",
                evidence=evidence_xss, request=f"GET {TARGET}/search"),
        Finding("misconfig", "missing-security-headers", "low", f"{TARGET}/",
                evidence="En-têtes absents : content-security-policy"),
        Finding("sqli", "error-based-sqli", "high", f"{TARGET}/search?q=%27",
                evidence="SQLITE_ERROR near ..."),
    ]
    timeline = [
        TimelineEvent(phase="recon", event="start", ts="t1"),
        TimelineEvent(phase="recon", event="done", detail="1 service(s)", ts="t2"),
        TimelineEvent(phase="auth", event="done", detail="authentifié", ts="t3"),
        TimelineEvent(phase="crawl", event="done", detail="2 endpoint(s)", ts="t4"),
        TimelineEvent(phase="attack", event="done", detail="3 finding(s)", ts="t5"),
    ]
    return ScanReport(target=TARGET, started_at="t0", finished_at="t5",
                      recon=recon, sitemap=sitemap, findings=findings, timeline=timeline)


def test_group_by_category_preserves_severity_order_within_group():
    report = make_report()
    grouped = group_by_category(report.findings)
    assert set(grouped) == {"xss", "misconfig", "sqli"}
    assert all(f.category == "xss" for f in grouped["xss"])
    assert len(grouped["sqli"]) == 1
    assert grouped["sqli"][0].severity == "high"


def test_render_scan_html_contains_all_section_headers():
    report = make_report()
    html = render_scan_html(report)
    assert "Recon" in html
    assert "Cartographie" in html
    assert "Vulnérabilités par catégorie" in html
    assert "Journal d'exécution" in html
    assert report.target in html


def test_render_scan_html_groups_findings_by_category():
    report = make_report()
    html = render_scan_html(report)
    assert "xss" in html
    assert "misconfig" in html
    assert "sqli" in html
    assert "reflected-xss" in html
    assert "missing-security-headers" in html
    assert "error-based-sqli" in html


def test_render_scan_html_shows_recon_services_and_tech_and_notes():
    report = make_report()
    html = render_scan_html(report)
    assert "3000" in html
    assert "Node.js" in html
    assert "Angular" in html
    assert "host.docker.internal" in html


def test_render_scan_html_shows_sitemap_endpoints_and_forms():
    report = make_report()
    html = render_scan_html(report)
    assert "/about" in html
    assert "/login" in html
    assert "/api/products" in html


def test_render_scan_html_shows_authenticated_status():
    report = make_report()
    html = render_scan_html(report)
    assert "oui" in html


def test_render_scan_html_escapes_script_in_evidence():
    report = make_report(evidence_xss="<script>alert(1)</script>")
    html = render_scan_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_scan_html_shows_timeline_events():
    report = make_report()
    html = render_scan_html(report)
    assert "t1" in html
    assert "t5" in html


def test_save_scan_writes_json_and_html(tmp_path):
    report = make_report()
    json_path, html_path = save_scan(report, str(tmp_path))

    assert json_path.endswith("scan.json")
    assert html_path.endswith("scan.html")

    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["target"] == TARGET
    assert len(data["findings"]) == 3

    with open(html_path, encoding="utf-8") as fh:
        html = fh.read()
    assert "Cartographie" in html


def test_scan_to_dict_round_trips_through_json_dumps():
    report = make_report()
    data = scan_to_dict(report)
    dumped = json.dumps(data)
    reloaded = json.loads(dumped)
    assert reloaded["target"] == TARGET
    assert reloaded["sitemap"]["authenticated"] is True
    assert len(reloaded["findings"]) == 3
