# Pentaster Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construire le MVP de Pentaster : un framework Python qui orchestre des outils de pentest web (httpx, ffuf, nuclei) dans des conteneurs Docker éphémères, pilotés par des workflows YAML déclaratifs, avec garde-fou d'autorisation, résultats JSON et rapport HTML.

**Architecture:** Un moteur Python générique lit un workflow YAML, construit un graphe d'étapes (`depends_on`), exécute chaque étape via `docker run`, parse la sortie de chaque outil en *findings* normalisés, agrège le tout puis produit `results.json` + `report.html`. Le moteur ne connaît aucun outil en dur.

**Tech Stack:** Python 3.13, typer (CLI), rich (sortie), pydantic v2 (validation YAML), PyYAML, jinja2 (rapport), pytest (tests). Docker pour l'exécution des outils.

## Global Constraints

- Python **3.13** (déjà installé).
- Package Python nommé **`pentaster`**.
- Aucun outil pentest installé nativement : tout outil s'exécute via **`docker run --rm`** (images officielles).
- **Garde-fou obligatoire** : aucun scan sans cible dans l'allowlist **et** flag `--authorized`.
- `localhost` / `127.0.0.1` autorisés par défaut dans le scope (lab local).
- Cible locale : `localhost` réécrit en `host.docker.internal` avant exécution dans un conteneur.
- Aucun test ne doit nécessiter Docker ni réseau : le runner est injectable/mockable.
- TDD strict : test qui échoue → implémentation minimale → test qui passe → commit.
- Répertoire de travail du projet : `~/dev/Pentaster`. Tous les chemins ci-dessous sont relatifs à cette racine.

---

### Task 1: Scaffold du projet & outillage

**Files:**
- Create: `pyproject.toml`
- Create: `pentaster/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/test_sanity.py`

**Interfaces:**
- Consumes: rien.
- Produces: package importable `pentaster` (expose `__version__: str`), environnement pytest fonctionnel.

- [ ] **Step 1: Écrire le test qui échoue**

`tests/test_sanity.py` :
```python
import pentaster

def test_package_has_version():
    assert isinstance(pentaster.__version__, str)
    assert pentaster.__version__
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_sanity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster'`

- [ ] **Step 3: Créer le scaffold**

`pyproject.toml` :
```toml
[project]
name = "pentaster"
version = "0.1.0"
description = "Framework d'orchestration pour pentest web automatisé"
requires-python = ">=3.13"
dependencies = [
    "typer>=0.12",
    "rich>=13.7",
    "pydantic>=2.7",
    "pyyaml>=6.0",
    "jinja2>=3.1",
]

[project.scripts]
pentaster = "pentaster.cli:app"

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["pentaster*"]

[tool.pytest.ini_options]
pythonpath = ["."]
```

`pentaster/__init__.py` :
```python
__version__ = "0.1.0"
```

`tests/__init__.py` : fichier vide.

- [ ] **Step 4: Installer les dépendances**

Run: `cd ~/dev/Pentaster && python3 -m pip install -e ".[dev]"`
Expected: installation réussie de typer, rich, pydantic, pyyaml, jinja2, pytest.

- [ ] **Step 5: Lancer le test pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_sanity.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd ~/dev/Pentaster
git add pyproject.toml pentaster/__init__.py tests/__init__.py tests/test_sanity.py
git commit -m "feat: scaffold pentaster package and test tooling"
```

---

### Task 2: Modèle Finding & parsers d'outils

**Files:**
- Create: `pentaster/parsers.py`
- Create: `tests/test_parsers.py`

**Interfaces:**
- Consumes: rien.
- Produces:
  - `Finding` (dataclass) champs : `tool:str, target:str, type:str, severity:str, name:str, evidence:str="", raw:dict={}`.
  - `parse_httpx(stdout:str, target:str) -> list[Finding]`
  - `parse_ffuf(stdout:str, target:str) -> list[Finding]`
  - `parse_nuclei(stdout:str, target:str) -> list[Finding]`
  - `get_parser(name:str) -> Callable[[str,str], list[Finding]]` (lève `KeyError` si inconnu).

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_parsers.py` :
```python
from pentaster.parsers import parse_httpx, parse_ffuf, parse_nuclei, get_parser, Finding

HTTPX = '{"url":"http://host.docker.internal:3000","status_code":200,"title":"OWASP Juice Shop","tech":["Angular","Express"]}\n'
FFUF = '{"results":[{"url":"http://host.docker.internal:3000/admin","status":200,"length":1234},{"url":"http://host.docker.internal:3000/ftp","status":200,"length":99}],"config":{}}'
NUCLEI = (
    '{"template-id":"tech-detect","info":{"name":"Angular detected","severity":"info"},"matched-at":"http://host.docker.internal:3000/"}\n'
    '{"template-id":"exposed-panel","info":{"name":"Admin panel exposed","severity":"medium"},"matched-at":"http://host.docker.internal:3000/admin"}\n'
)

def test_parse_httpx_returns_tech_finding():
    out = parse_httpx(HTTPX, "http://host.docker.internal:3000")
    assert len(out) == 1
    f = out[0]
    assert isinstance(f, Finding)
    assert f.tool == "httpx"
    assert f.type == "tech"
    assert f.severity == "info"
    assert "Angular" in f.evidence
    assert "200" in f.evidence

def test_parse_httpx_ignores_blank_lines():
    assert parse_httpx("\n  \n", "t") == []

def test_parse_ffuf_returns_endpoint_per_result():
    out = parse_ffuf(FFUF, "http://host.docker.internal:3000")
    assert len(out) == 2
    assert {f.name for f in out} == {
        "http://host.docker.internal:3000/admin",
        "http://host.docker.internal:3000/ftp",
    }
    assert all(f.type == "endpoint" and f.tool == "ffuf" for f in out)

def test_parse_ffuf_handles_empty():
    assert parse_ffuf('{"results":[],"config":{}}', "t") == []

def test_parse_nuclei_maps_severity_and_name():
    out = parse_nuclei(NUCLEI, "http://host.docker.internal:3000")
    assert len(out) == 2
    sev = {f.name: f.severity for f in out}
    assert sev["Admin panel exposed"] == "medium"
    assert sev["Angular detected"] == "info"
    assert all(f.type == "vulnerability" and f.tool == "nuclei" for f in out)

def test_parse_nuclei_ignores_malformed_lines():
    out = parse_nuclei("not json\n" + NUCLEI, "t")
    assert len(out) == 2

def test_get_parser_returns_callable():
    assert get_parser("nuclei") is parse_nuclei

def test_get_parser_unknown_raises():
    import pytest
    with pytest.raises(KeyError):
        get_parser("does-not-exist")
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_parsers.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.parsers'`

- [ ] **Step 3: Écrire l'implémentation minimale**

`pentaster/parsers.py` :
```python
"""Parsers : convertissent la sortie brute de chaque outil en Findings normalisés."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Finding:
    tool: str
    target: str
    type: str
    severity: str
    name: str
    evidence: str = ""
    raw: dict = field(default_factory=dict)


def _iter_json_lines(stdout: str):
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def parse_httpx(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for obj in _iter_json_lines(stdout):
        techs = obj.get("tech") or obj.get("technologies") or []
        status = obj.get("status_code", "")
        url = obj.get("url", target)
        evidence = f"status {status}; tech: {', '.join(techs)}".strip()
        findings.append(
            Finding(
                tool="httpx",
                target=target,
                type="tech",
                severity="info",
                name=obj.get("title") or url,
                evidence=evidence,
                raw=obj,
            )
        )
    return findings


def parse_ffuf(stdout: str, target: str) -> list[Finding]:
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for res in data.get("results", []):
        url = res.get("url", "")
        findings.append(
            Finding(
                tool="ffuf",
                target=target,
                type="endpoint",
                severity="info",
                name=url,
                evidence=f"status {res.get('status', '')}; len {res.get('length', '')}",
                raw=res,
            )
        )
    return findings


def parse_nuclei(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for obj in _iter_json_lines(stdout):
        info = obj.get("info", {})
        findings.append(
            Finding(
                tool="nuclei",
                target=target,
                type="vulnerability",
                severity=info.get("severity", "info"),
                name=info.get("name", obj.get("template-id", "unknown")),
                evidence=obj.get("matched-at", ""),
                raw=obj,
            )
        )
    return findings


PARSERS: dict[str, Callable[[str, str], list[Finding]]] = {
    "httpx": parse_httpx,
    "ffuf": parse_ffuf,
    "nuclei": parse_nuclei,
}


def get_parser(name: str) -> Callable[[str, str], list[Finding]]:
    return PARSERS[name]
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_parsers.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add pentaster/parsers.py tests/test_parsers.py
git commit -m "feat: Finding model and httpx/ffuf/nuclei parsers"
```

---

### Task 3: Garde-fou d'autorisation (ScopeGuard)

**Files:**
- Create: `pentaster/scope.py`
- Create: `tests/test_scope.py`

**Interfaces:**
- Consumes: rien.
- Produces:
  - `ScopeError(Exception)`
  - `ScopeGuard(allowed: list[str])` avec `DEFAULT_ALLOWED = ["localhost", "127.0.0.1"]` toujours inclus.
  - `ScopeGuard.from_file(path: str) -> ScopeGuard`
  - `ScopeGuard.host_of(target: str) -> str | None`
  - `ScopeGuard.is_authorized(target: str) -> bool`

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_scope.py` :
```python
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
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_scope.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.scope'`

- [ ] **Step 3: Écrire l'implémentation minimale**

`pentaster/scope.py` :
```python
"""Garde-fou d'autorisation : refuse toute cible hors allowlist."""
from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(Exception):
    """Levée quand une cible n'est pas autorisée par le scope."""


class ScopeGuard:
    DEFAULT_ALLOWED = ["localhost", "127.0.0.1"]

    def __init__(self, allowed: list[str]):
        entries = [a.strip().lower() for a in allowed if a.strip() and not a.strip().startswith("#")]
        self.allowed = list(dict.fromkeys(self.DEFAULT_ALLOWED + entries))

    @classmethod
    def from_file(cls, path: str) -> "ScopeGuard":
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        return cls(lines)

    def host_of(self, target: str) -> str | None:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.hostname

    def is_authorized(self, target: str) -> bool:
        host = self.host_of(target)
        if host is None:
            return False
        host = host.lower()
        for entry in self.allowed:
            if host == entry or host.endswith("." + entry):
                return True
        return False
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_scope.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add pentaster/scope.py tests/test_scope.py
git commit -m "feat: authorization scope guard with allowlist"
```

---

### Task 4: Modèles de workflow & ordonnancement DAG

**Files:**
- Create: `pentaster/workflow.py`
- Create: `tests/test_workflow.py`

**Interfaces:**
- Consumes: rien.
- Produces:
  - `Step(BaseModel)` : `id:str, tool:str, image:str, args:list[str], parser:str, depends_on:list[str]=[]`
  - `Workflow(BaseModel)` : `name:str, description:str="", target_type:str="url", steps:list[Step]`
  - `load_workflow(path:str) -> Workflow` (YAML → validation pydantic)
  - `validate_dag(wf:Workflow) -> None` (lève `ValueError` si `depends_on` référence un id inexistant)
  - `execution_order(wf:Workflow) -> list[list[Step]]` (vagues d'étapes parallélisables ; lève `ValueError` sur cycle)

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_workflow.py` :
```python
import pytest
from pentaster.workflow import Workflow, Step, load_workflow, validate_dag, execution_order

def make_wf(steps):
    return Workflow(name="t", steps=[Step(**s) for s in steps])

BASE = [
    {"id": "probe", "tool": "httpx", "image": "img", "args": ["-u", "{{target}}"], "parser": "httpx"},
    {"id": "content", "tool": "ffuf", "image": "img", "args": [], "parser": "ffuf", "depends_on": ["probe"]},
    {"id": "vulns", "tool": "nuclei", "image": "img", "args": [], "parser": "nuclei", "depends_on": ["probe"]},
]

def test_load_workflow_from_yaml(tmp_path):
    p = tmp_path / "wf.yaml"
    p.write_text(
        "name: web-basic\n"
        "steps:\n"
        "  - id: probe\n"
        "    tool: httpx\n"
        "    image: img\n"
        "    args: ['-u', '{{target}}']\n"
        "    parser: httpx\n"
    )
    wf = load_workflow(str(p))
    assert wf.name == "web-basic"
    assert wf.steps[0].id == "probe"
    assert wf.steps[0].depends_on == []

def test_validate_dag_missing_dependency_raises():
    wf = make_wf([
        {"id": "a", "tool": "x", "image": "img", "args": [], "parser": "httpx", "depends_on": ["ghost"]},
    ])
    with pytest.raises(ValueError, match="ghost"):
        validate_dag(wf)

def test_execution_order_layers():
    wf = make_wf(BASE)
    waves = execution_order(wf)
    assert [s.id for s in waves[0]] == ["probe"]
    assert {s.id for s in waves[1]} == {"content", "vulns"}

def test_execution_order_detects_cycle():
    wf = make_wf([
        {"id": "a", "tool": "x", "image": "img", "args": [], "parser": "httpx", "depends_on": ["b"]},
        {"id": "b", "tool": "x", "image": "img", "args": [], "parser": "httpx", "depends_on": ["a"]},
    ])
    with pytest.raises(ValueError, match="cycle"):
        execution_order(wf)

def test_execution_order_preserves_declared_order_in_wave():
    wf = make_wf(BASE)
    waves = execution_order(wf)
    # content déclaré avant vulns → même ordre dans la vague
    assert [s.id for s in waves[1]] == ["content", "vulns"]
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_workflow.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.workflow'`

- [ ] **Step 3: Écrire l'implémentation minimale**

`pentaster/workflow.py` :
```python
"""Modèles de workflow (pydantic) + chargement YAML + ordonnancement DAG."""
from __future__ import annotations

import yaml
from pydantic import BaseModel, Field


class Step(BaseModel):
    id: str
    tool: str
    image: str
    args: list[str] = Field(default_factory=list)
    parser: str
    depends_on: list[str] = Field(default_factory=list)


class Workflow(BaseModel):
    name: str
    description: str = ""
    target_type: str = "url"
    steps: list[Step]


def load_workflow(path: str) -> Workflow:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return Workflow.model_validate(data)


def validate_dag(wf: Workflow) -> None:
    ids = {s.id for s in wf.steps}
    for step in wf.steps:
        for dep in step.depends_on:
            if dep not in ids:
                raise ValueError(f"Étape '{step.id}' dépend d'un id inexistant : '{dep}'")


def execution_order(wf: Workflow) -> list[list[Step]]:
    validate_dag(wf)
    by_id = {s.id: s for s in wf.steps}
    done: set[str] = set()
    remaining = [s.id for s in wf.steps]
    waves: list[list[Step]] = []
    while remaining:
        ready = [sid for sid in remaining if all(d in done for d in by_id[sid].depends_on)]
        if not ready:
            raise ValueError(f"cycle détecté dans le workflow (étapes restantes : {remaining})")
        waves.append([by_id[sid] for sid in ready])
        done.update(ready)
        remaining = [sid for sid in remaining if sid not in done]
    return waves
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_workflow.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add pentaster/workflow.py tests/test_workflow.py
git commit -m "feat: workflow models, YAML loader and DAG scheduling"
```

---

### Task 5: Runner Docker

**Files:**
- Create: `pentaster/runner.py`
- Create: `tests/test_runner.py`

**Interfaces:**
- Consumes: `Step` (de `pentaster.workflow`).
- Produces:
  - `RunResult` (dataclass) : `step_id:str, stdout:str, stderr:str, exit_code:int`
  - `DockerRunner(wordlists_dir:str, run_docker:Callable[[list[str]], tuple[str,str,int]] | None = None)`
  - `DockerRunner.rewrite_target(target:str) -> str` (`localhost`/`127.0.0.1` → `host.docker.internal`)
  - `DockerRunner.build_command(step:Step, target:str) -> list[str]` (argv complet de `docker run`)
  - `DockerRunner.run(step:Step, target:str) -> RunResult`

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_runner.py` :
```python
from pentaster.runner import DockerRunner, RunResult
from pentaster.workflow import Step

def step(**kw):
    base = {"id": "probe", "tool": "httpx", "image": "projectdiscovery/httpx:latest",
            "args": ["-u", "{{target}}", "-json"], "parser": "httpx"}
    base.update(kw)
    return Step(**base)

def test_rewrite_localhost():
    r = DockerRunner("/w")
    assert r.rewrite_target("http://localhost:3000") == "http://host.docker.internal:3000"
    assert r.rewrite_target("http://127.0.0.1:3000/x") == "http://host.docker.internal:3000/x"
    assert r.rewrite_target("http://example.com") == "http://example.com"

def test_build_command_structure():
    r = DockerRunner("/word/lists")
    cmd = r.build_command(step(), "http://localhost:3000")
    assert cmd[:5] == ["docker", "run", "--rm", "-v", "/word/lists:/wordlists"]
    assert "projectdiscovery/httpx:latest" in cmd
    # {{target}} substitué et réécrit
    assert "http://host.docker.internal:3000" in cmd
    assert "{{target}}" not in cmd

def test_run_uses_injected_docker_and_returns_result():
    calls = {}
    def fake_docker(argv):
        calls["argv"] = argv
        return ("STDOUT", "STDERR", 0)
    r = DockerRunner("/w", run_docker=fake_docker)
    res = r.run(step(), "http://localhost:3000")
    assert isinstance(res, RunResult)
    assert res.step_id == "probe"
    assert res.stdout == "STDOUT"
    assert res.exit_code == 0
    assert calls["argv"][0] == "docker"
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_runner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.runner'`

- [ ] **Step 3: Écrire l'implémentation minimale**

`pentaster/runner.py` :
```python
"""Runner Docker : exécute une étape dans un conteneur éphémère."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable

from .workflow import Step

DockerFn = Callable[[list[str]], tuple[str, str, int]]


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
        return target.replace("localhost", "host.docker.internal").replace(
            "127.0.0.1", "host.docker.internal"
        )

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
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_runner.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add pentaster/runner.py tests/test_runner.py
git commit -m "feat: docker runner with target rewriting and injectable exec"
```

---

### Task 6: Moteur d'orchestration

**Files:**
- Create: `pentaster/engine.py`
- Create: `tests/test_engine.py`

**Interfaces:**
- Consumes: `Workflow`/`Step` (workflow.py), `execution_order` (workflow.py), `DockerRunner`/`RunResult` (runner.py), `ScopeGuard`/`ScopeError` (scope.py), `get_parser`/`Finding` (parsers.py).
- Produces:
  - `StepOutcome` (dataclass) : `step_id:str, tool:str, exit_code:int, findings:list[Finding]`
  - `RunReport` (dataclass) : `workflow:str, target:str, started_at:str, finished_at:str, outcomes:list[StepOutcome]` + propriété `findings -> list[Finding]`
  - `Engine(runner:DockerRunner, scope:ScopeGuard)` avec `execute(workflow:Workflow, target:str, now:Callable[[], str]=...) -> RunReport`. Lève `ScopeError` si cible non autorisée.

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_engine.py` :
```python
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
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_engine.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.engine'`

- [ ] **Step 3: Écrire l'implémentation minimale**

`pentaster/engine.py` :
```python
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

    def execute(self, workflow: Workflow, target: str, now: Callable[[], str] = _now_iso) -> RunReport:
        if not self.scope.is_authorized(target):
            raise ScopeError(f"Cible non autorisée par le scope : {target}")
        started = now()
        outcomes: list[StepOutcome] = []
        for wave in execution_order(workflow):
            with ThreadPoolExecutor(max_workers=len(wave)) as ex:
                outcomes.extend(ex.map(lambda s: self._run_step(s, target), wave))
        finished = now()
        order = [s.id for s in workflow.steps]
        outcomes.sort(key=lambda o: order.index(o.step_id))
        return RunReport(workflow.name, target, started, finished, outcomes)
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_engine.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add pentaster/engine.py tests/test_engine.py
git commit -m "feat: orchestration engine with scope check and DAG execution"
```

---

### Task 7: Persistance JSON des résultats

**Files:**
- Create: `pentaster/results.py`
- Create: `tests/test_results.py`

**Interfaces:**
- Consumes: `RunReport` (engine.py).
- Produces:
  - `report_to_dict(report:RunReport) -> dict`
  - `save_results(report:RunReport, out_dir:str) -> str` (écrit `<out_dir>/results.json`, crée le dossier, renvoie le chemin)

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_results.py` :
```python
import json
from pentaster.results import save_results, report_to_dict
from pentaster.engine import RunReport, StepOutcome
from pentaster.parsers import Finding

def make_report():
    f = Finding(tool="nuclei", target="t", type="vulnerability", severity="high", name="Bug", evidence="e", raw={"k": 1})
    return RunReport("web-basic", "http://localhost:3000", "s", "f", [StepOutcome("vulns", "nuclei", 0, [f])])

def test_report_to_dict_shape():
    d = report_to_dict(make_report())
    assert d["workflow"] == "web-basic"
    assert d["findings_count"] == 1
    assert d["outcomes"][0]["findings"][0]["name"] == "Bug"

def test_save_results_writes_file(tmp_path):
    path = save_results(make_report(), str(tmp_path / "run1"))
    assert path.endswith("results.json")
    data = json.loads(open(path).read())
    assert data["target"] == "http://localhost:3000"
    assert data["outcomes"][0]["findings"][0]["severity"] == "high"
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_results.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.results'`

- [ ] **Step 3: Écrire l'implémentation minimale**

`pentaster/results.py` :
```python
"""Sérialisation JSON d'un RunReport."""
from __future__ import annotations

import json
import os
from dataclasses import asdict

from .engine import RunReport


def report_to_dict(report: RunReport) -> dict:
    return {
        "workflow": report.workflow,
        "target": report.target,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "findings_count": len(report.findings),
        "outcomes": [asdict(o) for o in report.outcomes],
    }


def save_results(report: RunReport, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "results.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report_to_dict(report), fh, indent=2, ensure_ascii=False)
    return path
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_results.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add pentaster/results.py tests/test_results.py
git commit -m "feat: JSON results persistence"
```

---

### Task 8: Rapport HTML

**Files:**
- Create: `templates/report.html.j2`
- Create: `pentaster/report.py`
- Create: `tests/test_report.py`

**Interfaces:**
- Consumes: `RunReport` (engine.py).
- Produces:
  - `render_report(report:RunReport, template_path:str) -> str`
  - `save_report(report:RunReport, out_dir:str, template_path:str) -> str` (écrit `<out_dir>/report.html`, renvoie le chemin)
  - `DEFAULT_TEMPLATE` : chemin par défaut `templates/report.html.j2` (résolu relativement à la racine du package).

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_report.py` :
```python
import os
from pentaster.report import render_report, save_report, DEFAULT_TEMPLATE
from pentaster.engine import RunReport, StepOutcome
from pentaster.parsers import Finding

def make_report():
    f = Finding(tool="nuclei", target="t", type="vulnerability", severity="high", name="SQL Injection", evidence="/x")
    return RunReport("web-basic", "http://localhost:3000", "s", "f", [StepOutcome("vulns", "nuclei", 0, [f])])

def test_default_template_exists():
    assert os.path.exists(DEFAULT_TEMPLATE)

def test_render_contains_findings():
    html = render_report(make_report(), DEFAULT_TEMPLATE)
    assert "SQL Injection" in html
    assert "web-basic" in html
    assert "http://localhost:3000" in html
    assert "high" in html

def test_save_report_writes_html(tmp_path):
    path = save_report(make_report(), str(tmp_path / "run1"), DEFAULT_TEMPLATE)
    assert path.endswith("report.html")
    assert "SQL Injection" in open(path).read()
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_report.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.report'`

- [ ] **Step 3: Écrire le gabarit et l'implémentation**

`templates/report.html.j2` :
```html
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Pentaster — Rapport {{ report.workflow }}</title>
<style>
  body { font-family: -apple-system, Arial, sans-serif; margin: 2rem; color: #1f2430; }
  h1 { color: #0e7490; }
  .meta { color: #64748b; font-size: .9rem; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-size: .9rem; }
  th { background: #f1f5f9; }
  .sev-critical { color: #b91c1c; font-weight: 700; }
  .sev-high { color: #dc2626; font-weight: 600; }
  .sev-medium { color: #b45309; }
  .sev-low { color: #0891b2; }
  .sev-info { color: #64748b; }
</style>
</head>
<body>
  <h1>🛡️ Pentaster — {{ report.workflow }}</h1>
  <div class="meta">
    Cible : <b>{{ report.target }}</b> · Début : {{ report.started_at }} · Fin : {{ report.finished_at }}
    · {{ report.findings|length }} finding(s)
  </div>

  <h2>Findings</h2>
  <table>
    <tr><th>Sévérité</th><th>Outil</th><th>Type</th><th>Nom</th><th>Preuve</th></tr>
    {% for f in report.findings %}
    <tr>
      <td class="sev-{{ f.severity }}">{{ f.severity }}</td>
      <td>{{ f.tool }}</td>
      <td>{{ f.type }}</td>
      <td>{{ f.name }}</td>
      <td>{{ f.evidence }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Étapes</h2>
  <table>
    <tr><th>Étape</th><th>Outil</th><th>Code sortie</th><th>Findings</th></tr>
    {% for o in report.outcomes %}
    <tr><td>{{ o.step_id }}</td><td>{{ o.tool }}</td><td>{{ o.exit_code }}</td><td>{{ o.findings|length }}</td></tr>
    {% endfor %}
  </table>
</body>
</html>
```

`pentaster/report.py` :
```python
"""Génération du rapport HTML via jinja2."""
from __future__ import annotations

import os

from jinja2 import Template

from .engine import RunReport

DEFAULT_TEMPLATE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "templates", "report.html.j2"
)


def render_report(report: RunReport, template_path: str) -> str:
    with open(template_path, "r", encoding="utf-8") as fh:
        template = Template(fh.read())
    return template.render(report=report)


def save_report(report: RunReport, out_dir: str, template_path: str = DEFAULT_TEMPLATE) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_report(report, template_path))
    return path
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_report.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add templates/report.html.j2 pentaster/report.py tests/test_report.py
git commit -m "feat: HTML report generation"
```

---

### Task 9: CLI (typer)

**Files:**
- Create: `pentaster/cli.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `load_workflow` (workflow.py), `ScopeGuard`/`ScopeError` (scope.py), `DockerRunner` (runner.py), `Engine` (engine.py), `save_results` (results.py), `save_report`/`DEFAULT_TEMPLATE` (report.py).
- Produces:
  - `app` : `typer.Typer`
  - commande `run(workflow_path, target, authorized:bool, scope:str, wordlists:str, outdir:str)` — refuse sans `--authorized` (exit code 2) et sans cible dans le scope (exit code 3).
  - fonction `run_scan(workflow_path, target, scope_path, wordlists_dir, out_root, now=...) -> str` (logique testable sans Docker via runner injecté n'est pas requise ici : la commande construit un vrai `DockerRunner`, mais `run_scan` prend un `engine_factory` optionnel pour les tests).

- [ ] **Step 1: Écrire les tests qui échouent**

`tests/test_cli.py` :
```python
import os
import pytest
from typer.testing import CliRunner
from pentaster.cli import app, run_scan
from pentaster.engine import Engine, RunReport, StepOutcome
from pentaster.parsers import Finding
from pentaster.runner import DockerRunner, RunResult
from pentaster.scope import ScopeGuard

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

def write_wf(tmp_path):
    p = tmp_path / "wf.yaml"
    p.write_text(WF_YAML)
    return str(p)

def test_run_requires_authorized_flag(tmp_path):
    result = runner.invoke(app, ["run", write_wf(tmp_path), "--target", "http://localhost:3000"])
    assert result.exit_code == 2
    assert "authoris" in result.output.lower()

def test_run_scan_produces_outputs(tmp_path):
    # engine_factory injecte un runner factice → pas de Docker
    class FakeRunner(DockerRunner):
        def __init__(self):
            super().__init__("/w", run_docker=lambda a: ("", "", 0))
        def run(self, step, target):
            return RunResult(step.id, '{"url":"u","status_code":200,"tech":["Angular"]}', "", 0)
    def engine_factory(wordlists_dir, scope):
        return Engine(FakeRunner(), scope)

    out = run_scan(
        workflow_path=write_wf(tmp_path),
        target="http://localhost:3000",
        scope_path=None,
        wordlists_dir="/w",
        out_root=str(tmp_path / "runs"),
        now=lambda: "2026-07-23T10:00:00",
        engine_factory=engine_factory,
    )
    assert os.path.exists(os.path.join(out, "results.json"))
    assert os.path.exists(os.path.join(out, "report.html"))
```

- [ ] **Step 2: Lancer les tests pour vérifier l'échec**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pentaster.cli'`

- [ ] **Step 3: Écrire l'implémentation minimale**

`pentaster/cli.py` :
```python
"""Interface en ligne de commande."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Callable, Optional

import typer
from rich.console import Console

from .engine import Engine
from .report import save_report
from .results import save_results
from .runner import DockerRunner
from .scope import ScopeError, ScopeGuard
from .workflow import load_workflow

app = typer.Typer(help="Pentaster — orchestration de pentest web automatisé.")
console = Console()


def _default_engine_factory(wordlists_dir: str, scope: ScopeGuard) -> Engine:
    return Engine(DockerRunner(wordlists_dir), scope)


def run_scan(
    workflow_path: str,
    target: str,
    scope_path: Optional[str],
    wordlists_dir: str,
    out_root: str,
    now: Callable[[], str] = lambda: datetime.now().isoformat(timespec="seconds"),
    engine_factory: Callable[[str, ScopeGuard], Engine] = _default_engine_factory,
) -> str:
    workflow = load_workflow(workflow_path)
    scope = ScopeGuard.from_file(scope_path) if scope_path and os.path.exists(scope_path) else ScopeGuard([])
    engine = engine_factory(wordlists_dir, scope)
    report = engine.execute(workflow, target, now=now)
    out_dir = os.path.join(out_root, now().replace(":", "-"))
    save_results(report, out_dir)
    save_report(report, out_dir)
    return out_dir


@app.command()
def run(
    workflow_path: str = typer.Argument(..., help="Chemin du workflow YAML."),
    target: str = typer.Option(..., "--target", "-t", help="URL cible (ex. http://localhost:3000)."),
    authorized: bool = typer.Option(False, "--authorized", help="Confirme que tu es autorisé à scanner la cible."),
    scope: str = typer.Option("scope.txt", "--scope", help="Fichier d'allowlist."),
    wordlists: str = typer.Option("wordlists", "--wordlists", help="Dossier de wordlists monté dans les conteneurs."),
    outdir: str = typer.Option("runs", "--outdir", help="Dossier racine des résultats."),
):
    if not authorized:
        console.print("[red]Refus : passe --authorized pour confirmer que tu es autorisé à scanner cette cible.[/red]")
        raise typer.Exit(code=2)
    try:
        out = run_scan(
            workflow_path=workflow_path,
            target=target,
            scope_path=scope,
            wordlists_dir=os.path.abspath(wordlists),
            out_root=outdir,
        )
    except ScopeError as exc:
        console.print(f"[red]Refus : {exc}[/red]")
        raise typer.Exit(code=3)
    console.print(f"[green]Scan terminé.[/green] Résultats : [bold]{out}[/bold]")


@app.command("list-workflows")
def list_workflows(directory: str = typer.Option("workflows", "--dir")):
    for name in sorted(os.listdir(directory)):
        if name.endswith((".yaml", ".yml")):
            console.print(f"• {name}")


if __name__ == "__main__":
    app()
```

- [ ] **Step 4: Lancer les tests pour vérifier le succès**

Run: `cd ~/dev/Pentaster && python3 -m pytest tests/test_cli.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/dev/Pentaster
git add pentaster/cli.py tests/test_cli.py
git commit -m "feat: typer CLI with authorization gate and scan orchestration"
```

---

### Task 10: Workflow par défaut, wordlist, scope, README & smoke test

**Files:**
- Create: `workflows/web-basic.yaml`
- Create: `wordlists/common.txt`
- Create: `scope.txt`
- Modify: `README.md`

**Interfaces:**
- Consumes: toute la stack précédente.
- Produces: un workflow exécutable de bout en bout + doc d'usage.

- [ ] **Step 1: Créer le workflow par défaut**

`workflows/web-basic.yaml` :
```yaml
name: web-basic
description: Évaluation web de base (probe → découverte de contenu → vulns)
target_type: url
steps:
  - id: probe
    tool: httpx
    image: projectdiscovery/httpx:latest
    args: ["-u", "{{target}}", "-json", "-tech-detect", "-sc", "-title", "-silent"]
    parser: httpx

  - id: content
    tool: ffuf
    image: ghcr.io/ffuf/ffuf:latest
    depends_on: [probe]
    args: ["-u", "{{target}}/FUZZ", "-w", "/wordlists/common.txt", "-s", "-o", "/dev/stdout", "-of", "json"]
    parser: ffuf

  - id: vulns
    tool: nuclei
    image: projectdiscovery/nuclei:latest
    depends_on: [probe]
    args: ["-u", "{{target}}", "-jsonl", "-silent", "-severity", "low,medium,high,critical"]
    parser: nuclei
```

- [ ] **Step 2: Créer la wordlist courte et le scope**

`wordlists/common.txt` :
```
admin
login
ftp
robots.txt
api
backup
.git
rest
```

`scope.txt` :
```
# Une entrée par ligne (hôte ou domaine). localhost et 127.0.0.1 sont autorisés par défaut.
# Ajoute ici uniquement des cibles que tu as le droit de scanner.
```

- [ ] **Step 3: Rédiger le README**

`README.md` :
```markdown
# Pentaster

Framework d'orchestration pour **pentest web automatisé**. Enchaîne des outils
(httpx, ffuf, nuclei) dans des conteneurs Docker éphémères, pilotés par des
workflows YAML, avec garde-fou d'autorisation, résultats JSON et rapport HTML.

## Prérequis
- Python 3.13, Docker.
- Installation : `python3 -m pip install -e ".[dev]"`

## Usage
```bash
# Lister les workflows
pentaster list-workflows

# Lancer un scan (nécessite --authorized ET une cible dans scope.txt)
pentaster run workflows/web-basic.yaml --target http://localhost:3000 --authorized
```
Les résultats (`results.json` + `report.html`) sont écrits dans `runs/<horodatage>/`.

## Garde-fou
Aucun scan sans le flag `--authorized` et sans que l'hôte cible figure dans
l'allowlist (`scope.txt`). `localhost` et `127.0.0.1` sont autorisés par défaut
pour les labs locaux.

## Ajouter un outil
Édite un workflow YAML : ajoute un bloc `step` (`image`, `args`, `parser`).
Si le format de sortie est nouveau, ajoute un parser dans `pentaster/parsers.py`.

## ⚠️ Usage légal
À n'utiliser que sur des cibles que tu possèdes ou pour lesquelles tu as une
autorisation écrite (lab, mission, bug bounty).
```

- [ ] **Step 4: Lancer toute la suite de tests**

Run: `cd ~/dev/Pentaster && python3 -m pytest -v`
Expected: PASS (tous les tests des tâches 1 à 9)

- [ ] **Step 5: Smoke test manuel de bout en bout (Docker requis)**

Le lab Juice Shop doit tourner sur `localhost:3000`.
Run:
```bash
cd ~/dev/Pentaster
docker pull projectdiscovery/httpx:latest
docker pull projectdiscovery/nuclei:latest
docker pull ghcr.io/ffuf/ffuf:latest
pentaster run workflows/web-basic.yaml --target http://localhost:3000 --authorized
```
Expected: message « Scan terminé », un dossier `runs/<horodatage>/` contenant
`results.json` (findings non vides) et `report.html` (ouvrable dans un navigateur,
avec les technos et vulns détectées sur Juice Shop).

Vérification du refus :
```bash
pentaster run workflows/web-basic.yaml --target http://example.com --authorized
```
Expected: `Refus : Cible non autorisée par le scope` (exit code 3).

- [ ] **Step 6: Commit**

```bash
cd ~/dev/Pentaster
git add workflows/web-basic.yaml wordlists/common.txt scope.txt README.md
git commit -m "feat: default web-basic workflow, wordlist, scope and docs"
```

---

## Notes de fin

- **Parallélisme** : les étapes d'une même vague (`content`, `vulns`) tournent en threads ; l'I/O est un `docker run` bloquant, donc le threading est adapté.
- **Images Docker** : les tags exacts (`ghcr.io/ffuf/ffuf`) et options (`-o /dev/stdout -of json` pour ffuf) sont à confirmer au smoke test. Si ffuf n'émet pas de JSON sur stdout, ajuster les `args` du workflow (le parser attend `{"results":[...]}`) — aucune modif du moteur nécessaire.
- **Évolutions hors MVP** (rappel spec) : sqlmap/dalfox, workflow infra (subfinder/naabu), notifications, dashboard web, reprise de scan.
