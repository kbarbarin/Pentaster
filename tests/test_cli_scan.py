"""Stage 5 — commande CLI `scan` : double garde-fou identique à `audit`, puis
happy path avec `run_full_scan` patché (jamais de réseau/Docker réel)."""
import os

from typer.testing import CliRunner

import pentaster.cli as cli
from pentaster.cli import app
from pentaster.scan_models import Finding, ReconResult, ScanReport, SiteMap, TimelineEvent

runner = CliRunner()

TARGET = "http://localhost:3000"


def make_fake_report() -> ScanReport:
    recon = ReconResult(host="localhost", services=[], tech=[])
    sitemap = SiteMap(origin=TARGET)
    findings = [
        Finding("misconfig", "missing-security-headers", "low", f"{TARGET}/",
                evidence="En-têtes absents : content-security-policy"),
    ]
    timeline = [
        TimelineEvent(phase="recon", event="start", ts="t1"),
        TimelineEvent(phase="attack", event="done", ts="t2"),
    ]
    return ScanReport(
        target=TARGET,
        started_at="t1",
        finished_at="t2",
        recon=recon,
        sitemap=sitemap,
        findings=findings,
        timeline=timeline,
    )


def test_scan_refuses_without_authorized_flag():
    res = runner.invoke(app, ["scan", "--target", TARGET])
    assert res.exit_code == 2
    assert "authorized" in res.stdout.lower()


def test_scan_refuses_out_of_scope_target():
    res = runner.invoke(app, ["scan", "--target", "http://example.com", "--authorized"])
    assert res.exit_code == 3
    assert "périmètre" in res.stdout


def test_scan_happy_path_writes_report(tmp_path, monkeypatch):
    def fake_run_full_scan(target, *, guard, wordlists_dir, max_pages, max_depth,
                            do_auth, progress=None):
        # Exerce la closure de log en direct pour chaque type d'événement.
        if progress is not None:
            from pentaster.scan_models import Endpoint, Form, Service
            progress("recon", "start", "localhost")
            progress("recon", "port", Service(port=3000, proto="tcp", name="http-alt", product="Node.js"))
            progress("recon", "tech", "Express")
            progress("auth", "start", target)
            progress("auth", "login-ok", "/rest/user/login")
            progress("crawl", "endpoint", Endpoint(url=f"{target}/about", method="GET"))
            progress("crawl", "form", Form(action=f"{target}/login", method="POST"))
            progress("attack", "start", ("misconfig", "security-headers"))
            progress("attack", "done", ("security-headers", 1))
        return make_fake_report()

    monkeypatch.setattr(cli, "run_full_scan", fake_run_full_scan)

    out_dir = str(tmp_path / "out")
    res = runner.invoke(
        app, ["scan", "--target", TARGET, "--authorized", "--out", out_dir])

    assert res.exit_code == 0, res.stdout
    json_path = os.path.join(out_dir, "scan.json")
    html_path = os.path.join(out_dir, "scan.html")
    assert os.path.exists(json_path)
    assert os.path.exists(html_path)
    assert "login OK" in res.stdout
    assert "vuln" in res.stdout


def test_scan_login_fail_is_logged(tmp_path, monkeypatch):
    def fake_run_full_scan(target, *, guard, wordlists_dir, max_pages, max_depth,
                            do_auth, progress=None):
        if progress is not None:
            progress("auth", "start", target)
            progress("auth", "login-fail", "aucun endpoint")
        return make_fake_report()

    monkeypatch.setattr(cli, "run_full_scan", fake_run_full_scan)

    out_dir = str(tmp_path / "out2")
    res = runner.invoke(
        app, ["scan", "--target", TARGET, "--authorized", "--out", out_dir])

    assert res.exit_code == 0, res.stdout
    assert "login échec" in res.stdout


def test_app_registers_scan_and_existing_commands():
    from typer.main import get_command
    names = set(get_command(app).commands.keys())
    assert "scan" in names
    for existing in ("run", "audit", "solve", "scope-check", "list-workflows"):
        assert existing in names
