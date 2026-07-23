"""Runner Docker : exécute une étape dans un conteneur éphémère."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Callable

from .workflow import Step

DockerFn = Callable[[list[str]], tuple[str, str, int]]

# Regex to match localhost or 127.0.0.1 only when bounded by non-host characters
_LOCAL_HOST_RE = re.compile(r"(?<![\w.-])(localhost|127\.0\.0\.1)(?![\w.-])")


@dataclass
class RunResult:
    step_id: str
    stdout: str
    stderr: str
    exit_code: int


def _default_docker(argv: list[str]) -> tuple[str, str, int]:
    proc = subprocess.run(argv, capture_output=True, text=True)
    return proc.stdout, proc.stderr, proc.returncode


class DockerRunner:
    def __init__(self, wordlists_dir: str, run_docker: DockerFn | None = None):
        self.wordlists_dir = wordlists_dir
        self._run_docker = run_docker or _default_docker

    def rewrite_target(self, target: str) -> str:
        return _LOCAL_HOST_RE.sub("host.docker.internal", target)

    def build_command(self, step: Step, target: str) -> list[str]:
        rewritten = self.rewrite_target(target)
        args = [a.replace("{{target}}", rewritten) for a in step.args]
        return [
            "docker", "run", "--rm",
            "-v", f"{self.wordlists_dir}:/wordlists",
            step.image,
            *args,
        ]

    def run(self, step: Step, target: str) -> RunResult:
        argv = self.build_command(step, target)
        stdout, stderr, code = self._run_docker(argv)
        return RunResult(step_id=step.id, stdout=stdout, stderr=stderr, exit_code=code)
