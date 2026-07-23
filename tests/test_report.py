import os

from pentaster.engine import RunReport, StepOutcome
from pentaster.parsers import Finding
from pentaster.report import DEFAULT_TEMPLATE, render_report, save_report, _severity_rank


def _report():
    findings = [
        Finding("nuclei", "http://localhost:3000", "vulnerability", "high", "XSS réfléchi", "matched-at"),
        Finding("nuclei", "http://localhost:3000", "vulnerability", "low", "Header manquant", ""),
        Finding("httpx", "http://localhost:3000", "tech", "info", "Angular", "status 200"),
    ]
    outcomes = [
        StepOutcome("probe", "httpx", 0, [findings[2]]),
        StepOutcome("vulns", "nuclei", 0, [findings[0], findings[1]]),
    ]
    return RunReport("web-basic", "http://localhost:3000",
                     "2026-07-23T10:00:00", "2026-07-23T10:00:12", outcomes)


def test_default_template_exists():
    assert os.path.exists(DEFAULT_TEMPLATE)


def test_severity_rank_orders_critical_first():
    assert _severity_rank("critical") < _severity_rank("high") < _severity_rank("low")
    assert _severity_rank("n'importe") == 5


def test_render_contains_findings_and_target():
    html = render_report(_report())
    assert "XSS réfléchi" in html
    assert "http://localhost:3000" in html
    assert "web-basic" in html
    # tech listée dans la section technologies
    assert "Angular" in html


def test_render_sorts_high_before_low():
    html = render_report(_report())
    assert html.index("XSS réfléchi") < html.index("Header manquant")


def test_save_report_writes_file(tmp_path):
    path = save_report(_report(), str(tmp_path))
    assert path.endswith("report.html")
    content = open(path, encoding="utf-8").read()
    assert "Rapport Pentaster" in content
    assert "12 s" in content  # durée calculée
