from typer.testing import CliRunner
from pentaster.cli import app

runner = CliRunner()


def test_run_refuses_without_authorized_flag():
    res = runner.invoke(app, ["run", "web-basic", "--target", "http://localhost:3000"])
    assert res.exit_code == 2
    assert "authorized" in res.stdout.lower()


def test_run_refuses_out_of_scope_target():
    res = runner.invoke(app, ["run", "web-basic", "--target", "http://evil.example", "--authorized"])
    assert res.exit_code == 2
    assert "hors périmètre" in res.stdout or "périmètre" in res.stdout


def test_scope_check_authorized():
    res = runner.invoke(app, ["scope-check", "http://localhost:3000"])
    assert res.exit_code == 0
    assert "AUTORIS" in res.stdout.upper()


def test_scope_check_refused():
    res = runner.invoke(app, ["scope-check", "http://evil.example"])
    assert res.exit_code == 2


def test_run_unknown_workflow_is_error():
    res = runner.invoke(app, ["run", "does-not-exist", "--target", "http://localhost:3000", "--authorized"])
    assert res.exit_code != 0
