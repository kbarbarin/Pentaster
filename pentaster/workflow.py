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
    seen: set[str] = set()
    for step in wf.steps:
        if step.id in seen:
            raise ValueError(f"Id d'étape dupliqué : '{step.id}'")
        seen.add(step.id)
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
