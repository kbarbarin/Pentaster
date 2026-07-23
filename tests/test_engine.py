import time
import pytest
from pentaster.engine import Engine, RunReport, StepOutcome
from pentaster.runner import DockerRunner, RunResult
from pentaster.scope import ScopeGuard, ScopeError
from pentaster.workflow import Workflow, Step

def make_wf():
    return Workflow(name="web-basic", steps=[
        Step(id="probe", tool="httpx", image="img", args=["-u", "{{target}}"], parser="httpx"),
        Step(id="vulns", tool="nuclei", image="img", args=[], parser="nuclei", depends_on=["probe"]),
    ])

# Runner factice : renvoie une sortie JSON selon l'outil de l'étape
class FakeRunner(DockerRunner):
    def __init__(self):
        super().__init__("/w", run_docker=lambda argv: ("", "", 0))
    def run(self, step, target):
        outputs = {
            "httpx": '{"url":"http://host.docker.internal:3000","status_code":200,"tech":["Angular"]}',
            "nuclei": '{"template-id":"x","info":{"name":"Bug","severity":"high"},"matched-at":"u"}',
        }
        return RunResult(step_id=step.id, stdout=outputs[step.tool], stderr="", exit_code=0)

FIXED_NOW = iter(["2026-07-23T10:00:00", "2026-07-23T10:00:05"])

def test_execute_refuses_unauthorized_target():
    eng = Engine(FakeRunner(), ScopeGuard(["example.com"]))
    with pytest.raises(ScopeError):
        eng.execute(make_wf(), "http://evil.org")

def test_execute_returns_report_with_findings():
    eng = Engine(FakeRunner(), ScopeGuard([]))
    report = eng.execute(make_wf(), "http://localhost:3000", now=lambda: next(FIXED_NOW))
    assert isinstance(report, RunReport)
    assert report.workflow == "web-basic"
    assert report.target == "http://localhost:3000"
    assert report.started_at == "2026-07-23T10:00:00"
    assert report.finished_at == "2026-07-23T10:00:05"
    # une étape probe (1 finding tech) + une étape vulns (1 finding)
    names = {f.name for f in report.findings}
    assert "Bug" in names
    assert any(f.severity == "high" for f in report.findings)

def test_outcomes_ordered_by_declaration():
    eng = Engine(FakeRunner(), ScopeGuard([]))
    report = eng.execute(make_wf(), "http://localhost:3000", now=lambda: "t")
    assert [o.step_id for o in report.outcomes] == ["probe", "vulns"]

def test_outcomes_ordered_despite_out_of_order_completion():
    # Two INDEPENDENT steps (no depends_on) => one wave, run concurrently.
    wf = Workflow(name="w", steps=[
        Step(id="slow", tool="httpx", image="img", args=[], parser="httpx"),
        Step(id="fast", tool="nuclei", image="img", args=[], parser="nuclei"),
    ])
    class DelayRunner(DockerRunner):
        def __init__(self):
            super().__init__("/w", run_docker=lambda a: ("", "", 0))
        def run(self, step, target):
            if step.id == "slow":
                time.sleep(0.1)  # first-declared finishes LAST
            outputs = {
                "httpx": '{"url":"u","status_code":200,"tech":[]}',
                "nuclei": '{"template-id":"x","info":{"name":"B","severity":"low"},"matched-at":"u"}',
            }
            return RunResult(step.id, outputs[step.tool], "", 0)
    eng = Engine(DelayRunner(), ScopeGuard([]))
    report = eng.execute(wf, "http://localhost:3000", now=lambda: "t")
    assert [o.step_id for o in report.outcomes] == ["slow", "fast"]
