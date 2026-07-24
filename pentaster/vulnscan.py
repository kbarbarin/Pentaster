"""Stage 5 — Couverture élargie du pipeline `scan` :

* `run_nuclei` — scan de vulnérabilités générique via nuclei (Docker),
  converti en `scan_models.Finding` (category="nuclei").
* `looks_like_juice_shop` / `run_exploit_phase` — détection AUTOMATIQUE
  d'une cible exposant l'API de challenges OWASP Juice Shop
  (`GET /api/Challenges/`) et confirmation des vulnérabilités RÉELLES via
  les solveurs d'exploit (`pentaster.solvers.run_solvers`), qui exécutent
  l'attaque HTTP réelle plutôt qu'une simple heuristique.

Entièrement injectable (Docker via `docker_fn`, HTTP via `http`, solveurs
via `solve_fn`) : jamais de réseau/Docker réel dans les tests. Une phase qui
échoue ne lève jamais — elle dégrade proprement vers une liste vide.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

from .parsers import parse_nuclei
from .runner import DockerFn, DockerRunner
from .scan_models import Finding
from .solvers import run_solvers as _default_run_solvers
from .workflow import Step

Progress = Callable[[str, str, object], None]

_NUCLEI_STEP = Step(
    id="nuclei",
    tool="nuclei",
    image="projectdiscovery/nuclei:latest",
    args=["-u", "{{target}}", "-jsonl", "-silent",
          "-severity", "info,low,medium,high,critical", "-timeout", "5"],
    parser="nuclei",
)


def run_nuclei(
    target: str,
    *,
    wordlists_dir: str,
    docker_fn: Optional[DockerFn] = None,
    progress: Optional[Progress] = None,
) -> list[Finding]:
    """Exécute nuclei (Docker) contre `target` et convertit chaque résultat
    en `scan_models.Finding` (category="nuclei"). Ne lève jamais : Docker
    down, image inconnue ou sortie vide -> []."""

    def emit(event: str, payload: object = None) -> None:
        if progress is not None:
            progress("nuclei", event, payload)

    emit("start", target)
    out: list[Finding] = []
    try:
        runner = DockerRunner(wordlists_dir, run_docker=docker_fn)
        res = runner.run(_NUCLEI_STEP, target)
        if res.exit_code == 0 and res.stdout.strip():
            for raw_finding in parse_nuclei(res.stdout, target):
                info = raw_finding.raw.get("info", {}) if isinstance(raw_finding.raw, dict) else {}
                template_id = (raw_finding.raw or {}).get("template-id", "unknown")
                finding = Finding(
                    category="nuclei",
                    technique=info.get("name") or template_id,
                    severity=raw_finding.severity,
                    url=raw_finding.evidence or target,
                    evidence=f"{template_id} ({raw_finding.type})",
                    raw=raw_finding.raw,
                )
                out.append(finding)
                emit("finding", finding)
    except Exception as exc:  # noqa: BLE001 - une phase ne doit jamais avorter le scan
        emit("error", str(exc))
        return []
    emit("done", len(out))
    return out


def looks_like_juice_shop(http) -> bool:
    """Sonde `GET /api/Challenges/` : vrai si la réponse ressemble à l'API
    de challenges OWASP Juice Shop (`{"data":[...]}` avec des entrées
    nommées). Ne lève jamais."""
    try:
        st, _, body = http.get("/api/Challenges/")
    except Exception:  # noqa: BLE001
        return False
    if st != 200:
        return False
    try:
        data = json.loads(body or "")
    except (json.JSONDecodeError, TypeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    entries = data.get("data")
    if not isinstance(entries, list) or not entries:
        return False
    return all(isinstance(e, dict) and "name" in e for e in entries[:5])


def run_exploit_phase(
    target: str,
    http,
    *,
    solve_fn: Callable[..., dict] = _default_run_solvers,
    progress: Optional[Progress] = None,
) -> list[Finding]:
    """Si `target` expose l'API de challenges Juice Shop, exécute les
    solveurs d'exploit RÉELS (`solve_fn`, par défaut `solvers.run_solvers`)
    pour CONFIRMER les vulnérabilités effectivement présentes, et renvoie un
    `Finding` (category="exploit") par challenge confirmé — dédupliqué par
    technique (nom du challenge). Priorité à `newly_solved` (fraîchement
    confirmés par CETTE exécution) puis aux entrées `ran` déjà réussies.

    Si la cible n'est PAS détectée comme Juice-Shop-like, `solve_fn` n'est
    JAMAIS appelé (générique : aucun effet sur une cible non Juice Shop).
    Ne lève jamais."""

    def emit(event: str, payload: object = None) -> None:
        if progress is not None:
            progress("exploit", event, payload)

    emit("start", target)

    if not looks_like_juice_shop(http):
        emit("done", 0)
        return []

    def solver_progress(event, label, ok):
        if progress is not None:
            progress("exploit", event, (label, ok))

    try:
        result = solve_fn(target, progress=solver_progress) or {}
    except Exception as exc:  # noqa: BLE001
        emit("error", str(exc))
        return []

    newly_solved = list(result.get("newly_solved") or [])
    ran_ok = [name for name, ok in (result.get("ran") or []) if ok]

    out: list[Finding] = []
    seen: set[str] = set()
    for name in newly_solved + ran_ok:
        if name in seen:
            continue
        seen.add(name)
        finding = Finding(
            category="exploit",
            technique=name,
            severity="high",
            url=target,
            evidence=f"Exploit confirmé — challenge '{name}' résolu",
            confirmed=True,
        )
        out.append(finding)
        emit("solved", finding)

    emit("done", len(out))
    return out
