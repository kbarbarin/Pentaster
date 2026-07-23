import os

from typer.testing import CliRunner

from pentaster.cli import app, run_scan
from pentaster.engine import Engine
from pentaster.runner import DockerRunner, RunResult

runner = CliRunner()

WF_YAML = (
    "name: web-basic\n"
    "steps:\n"
    "  - id: probe\n"
    "    tool: httpx\n"
    "    image: img\n"
    "    args: ['-u', '{{target}}']\n"
    "    parser: httpx\n"
)


def _write_wf(tmp_path):
    p = tmp_path / "wf.yaml"
    p.write_text(WF_YAML)
    return str(p)


def test_run_refuses_without_authorized_flag():
    res = runner.invoke(app, ["run", "web-basic", "--target", "http://localhost:3000"])
    assert res.exit_code == 2
    assert "authorized" in res.stdout.lower()


def test_run_refuses_out_of_scope_target():
    res = runner.invoke(app, ["run", "web-basic", "--target", "http://evil.example", "--authorized"])
    assert res.exit_code == 3
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


def test_run_unknown_workflow_exits_with_code_1_not_2():
    res = runner.invoke(app, ["run", "does-not-exist", "--target", "http://localhost:3000", "--authorized"])
    assert res.exit_code == 1


def test_run_scan_produces_outputs(tmp_path):
    """run_scan orchestre un scan complet sans jamais invoquer Docker (runner factice injecté)."""

    class FakeRunner(DockerRunner):
        def __init__(self):
            super().__init__("/w", run_docker=lambda argv: ("", "", 0))

        def run(self, step, target):
            return RunResult(
                step.id, '{"url":"u","status_code":200,"tech":["Angular"]}', "", 0
            )

    def engine_factory(wordlists_dir, scope):
        return Engine(FakeRunner(), scope)

    out_dir = str(tmp_path / "runs" / "20260723-100000")
    result = run_scan(
        workflow_path=_write_wf(tmp_path),
        target="http://localhost:3000",
        scope_path=None,
        wordlists_dir="/w",
        out_root=out_dir,
        now=lambda: "2026-07-23T10:00:00",
        engine_factory=engine_factory,
    )

    assert result == out_dir
    assert os.path.exists(os.path.join(result, "results.json"))
    assert os.path.exists(os.path.join(result, "report.html"))
