"""Moteur : ordonne les étapes, exécute, parse et agrège les findings."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .parsers import Finding, get_parser
from .runner import DockerRunner
from .scope import ScopeError, ScopeGuard
from .workflow import Step, Workflow, execution_order


@dataclass
class StepOutcome:
    step_id: str
    tool: str
    exit_code: int
    findings: list[Finding]


@dataclass
class RunReport:
    workflow: str
    target: str
    started_at: str
    finished_at: str
    outcomes: list[StepOutcome]

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for o in self.outcomes:
            out.extend(o.findings)
        return out


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Engine:
    def __init__(self, runner: DockerRunner, scope: ScopeGuard):
        self.runner = runner
        self.scope = scope

    def _run_step(self, step: Step, target: str) -> StepOutcome:
        result = self.runner.run(step, target)
        parser = get_parser(step.parser)
        findings = parser(result.stdout, self.runner.rewrite_target(target))
        return StepOutcome(step.id, step.tool, result.exit_code, findings)

    def _safe_run_step(self, step: Step, target: str) -> StepOutcome:
        try:
            return self._run_step(step, target)
        except Exception:
            return StepOutcome(step_id=step.id, tool=step.tool, exit_code=-1, findings=[])

    def execute(self, workflow: Workflow, target: str, now: Callable[[], str] = _now_iso) -> RunReport:
        if not self.scope.is_authorized(target):
            raise ScopeError(f"Cible non autorisée par le scope : {target}")
        started = now()
        outcomes: list[StepOutcome] = []
        for wave in execution_order(workflow):
            with ThreadPoolExecutor(max_workers=len(wave)) as ex:
                outcomes.extend(ex.map(lambda s: self._safe_run_step(s, target), wave))
        finished = now()
        order = [s.id for s in workflow.steps]
        outcomes.sort(key=lambda o: order.index(o.step_id))
        return RunReport(workflow.name, target, started, finished, outcomes)
