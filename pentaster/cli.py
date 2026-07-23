"""Point d'entrée CLI (typer + rich) : `pentaster run <workflow> --target <url>`."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Callable

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .engine import Engine
from .report import save_report
from .results import save_results
from .runner import DockerRunner
from .scope import ScopeError, ScopeGuard
from .solvers import run_solvers
from .workflow import load_workflow

app = typer.Typer(add_completion=False, help="Pentaster — orchestrateur de pentest web.")
console = Console()

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOWS_DIR = _ROOT / "workflows"
_WORDLISTS_DIR = _ROOT / "wordlists"
_TEMPLATES_DIR = _ROOT / "templates"

_SEV_STYLE = {"critical": "bold white on red", "high": "red", "medium": "yellow",
              "low": "cyan", "info": "dim"}


def _resolve_workflow(name_or_path: str) -> Path:
    """Accepte un nom court ('web-basic') ou un chemin vers un .yaml."""
    p = Path(name_or_path)
    if p.exists():
        return p
    candidate = _WORKFLOWS_DIR / (name_or_path if name_or_path.endswith((".yaml", ".yml"))
                                  else f"{name_or_path}.yaml")
    if candidate.exists():
        return candidate
    raise typer.BadParameter(f"Workflow introuvable : {name_or_path} (ni {candidate})")


def _load_scope(scope_path: str | None) -> ScopeGuard:
    if scope_path:
        p = Path(scope_path)
        if not p.exists():
            raise typer.BadParameter(f"Fichier de scope introuvable : {scope_path}")
        return ScopeGuard.from_file(str(p))
    default = _ROOT / "scope.txt"
    if default.exists():
        return ScopeGuard.from_file(str(default))
    # Sans fichier : seuls localhost / 127.0.0.1 (DEFAULT_ALLOWED) sont autorisés.
    return ScopeGuard([])


def _default_engine_factory(wordlists_dir: str, guard: ScopeGuard) -> Engine:
    return Engine(DockerRunner(wordlists_dir), guard)


def run_scan(
    workflow_path: str,
    target: str,
    scope_path: str | None,
    wordlists_dir: str,
    out_root: str,
    now: Callable[[], str] = lambda: datetime.now().isoformat(timespec="seconds"),
    engine_factory: Callable[[str, ScopeGuard], Engine] = _default_engine_factory,
    template_dir: str | None = None,
) -> str:
    """Orchestration pure d'un scan : charge le workflow, exécute, écrit JSON + HTML.

    Ne touche pas à la console — c'est la commande `run` qui affiche. Le
    `engine_factory` permet d'injecter un `Engine` (avec un runner factice)
    dans les tests, sans jamais invoquer Docker.

    `out_root` est le dossier de sortie final (déjà résolu par l'appelant) :
    la fonction y écrit `results.json` et `report.html` puis renvoie ce chemin.
    """
    wf_path = _resolve_workflow(workflow_path)
    wf = load_workflow(str(wf_path))
    guard = _load_scope(scope_path)
    engine = engine_factory(wordlists_dir, guard)
    report = engine.execute(wf, target, now=now)
    save_results(report, out_root)
    save_report(report, out_root, template_dir=template_dir)
    return out_root


@app.command()
def run(
    workflow: str = typer.Argument(..., help="Nom ('web-basic') ou chemin d'un workflow YAML."),
    target: str = typer.Option(..., "--target", "-t", help="URL/hôte cible (lab autorisé)."),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirme explicitement l'autorisation de tester la cible."),
    scope: str = typer.Option(None, "--scope", "-s", help="Fichier d'allowlist (défaut : scope.txt)."),
    wordlists: str = typer.Option(None, "--wordlists", "-w", help="Dossier de wordlists monté dans les conteneurs."),
    out: str = typer.Option(None, "--out", "-o", help="Dossier de sortie (défaut : runs/<timestamp>)."),
    templates: str = typer.Option(None, "--templates", help="Dossier des templates de rapport."),
):
    """Exécute un workflow contre une cible autorisée, puis produit JSON + rapport HTML."""
    try:
        guard = _load_scope(scope)
    except typer.BadParameter as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1)

    # Double garde-fou : flag explicite ET appartenance au scope.
    if not authorized:
        console.print(Panel.fit(
            "[bold red]Refus :[/bold red] ajoute le flag [b]--authorized[/b] pour confirmer "
            "que tu es autorisé à tester cette cible.", border_style="red"))
        raise typer.Exit(code=2)
    if not guard.is_authorized(target):
        console.print(Panel.fit(
            f"[bold red]Refus :[/bold red] cible hors périmètre → [b]{target}[/b]\n"
            f"Hôtes autorisés : {', '.join(guard.allowed)}\n"
            "Ajoute l'hôte à scope.txt si tu y es autorisé.", border_style="red"))
        raise typer.Exit(code=3)

    try:
        wf_path = _resolve_workflow(workflow)
    except typer.BadParameter as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1)
    wf = load_workflow(str(wf_path))

    wl_dir = str(Path(wordlists).resolve()) if wordlists else str(_WORDLISTS_DIR)
    tpl_dir = templates or str(_TEMPLATES_DIR)
    out_dir = out or str(_ROOT / "runs" / datetime.now().strftime("%Y%m%d-%H%M%S"))

    console.print(Panel.fit(
        f"[b]Workflow[/b] : {wf.name} ({wf_path.name})\n"
        f"[b]Cible[/b] : {target}\n"
        f"[b]Scope OK[/b] : {guard.host_of(target)}\n"
        f"[b]Sortie[/b] : {out_dir}", title="Pentaster", border_style="green"))

    try:
        with console.status("[bold green]Exécution du workflow (conteneurs Docker)…", spinner="dots"):
            out_dir = run_scan(
                workflow_path=str(wf_path),
                target=target,
                scope_path=scope,
                wordlists_dir=wl_dir,
                out_root=out_dir,
                template_dir=tpl_dir,
            )
    except ScopeError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=3)

    with open(os.path.join(out_dir, "results.json"), encoding="utf-8") as fh:
        results = json.load(fh)
    _print_summary(results)
    console.print(f"\n[green]→[/green] JSON  : {os.path.join(out_dir, 'results.json')}")
    console.print(f"[green]→[/green] Rapport HTML : {os.path.join(out_dir, 'report.html')}")


def _print_summary(results: dict) -> None:
    """Affiche le tableau des findings à partir du `results.json` fraîchement écrit."""
    findings = [f for o in results.get("outcomes", []) for f in o.get("findings", [])]
    table = Table(title=f"Findings — {results.get('target')} ({len(findings)})")
    table.add_column("Sév"); table.add_column("Type"); table.add_column("Nom", max_width=50)
    table.add_column("Outil")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: order.get((x.get("severity") or "").lower(), 5)):
        sev = f.get("severity", "")
        style = _SEV_STYLE.get(sev.lower(), "white")
        table.add_row(f"[{style}]{sev}[/]", f.get("type", ""), f.get("name", ""), f.get("tool", ""))
    console.print(table)
    for o in results.get("outcomes", []):
        if o.get("exit_code", 0) != 0:
            console.print(f"[yellow]⚠ étape {o.get('step_id')} ({o.get('tool')}) code {o.get('exit_code')}[/yellow]")


@app.command()
def solve(
    target: str = typer.Option(..., "--target", "-t", help="URL/hôte cible (lab autorisé)."),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirme explicitement l'autorisation de tester la cible."),
    scope: str = typer.Option(None, "--scope", "-s", help="Fichier d'allowlist (défaut : scope.txt)."),
    out: str = typer.Option(None, "--out", "-o", help="Dossier de sortie (défaut : runs/<timestamp>)."),
):
    """Exécute les solveurs de challenges OWASP Juice Shop contre une cible autorisée."""
    try:
        guard = _load_scope(scope)
    except typer.BadParameter as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1)

    # Même double garde-fou que `run` : flag explicite ET appartenance au scope.
    if not authorized:
        console.print(Panel.fit(
            "[bold red]Refus :[/bold red] ajoute le flag [b]--authorized[/b] pour confirmer "
            "que tu es autorisé à tester cette cible.", border_style="red"))
        raise typer.Exit(code=2)
    if not guard.is_authorized(target):
        console.print(Panel.fit(
            f"[bold red]Refus :[/bold red] cible hors périmètre → [b]{target}[/b]\n"
            f"Hôtes autorisés : {', '.join(guard.allowed)}\n"
            "Ajoute l'hôte à scope.txt si tu y es autorisé.", border_style="red"))
        raise typer.Exit(code=3)

    out_dir = out or str(_ROOT / "runs" / datetime.now().strftime("%Y%m%d-%H%M%S"))
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        f"[b]Cible[/b] : {target}\n"
        f"[b]Scope OK[/b] : {guard.host_of(target)}\n"
        f"[b]Sortie[/b] : {out_dir}", title="Pentaster — Solve", border_style="green"))

    with console.status("[bold green]Exécution des solveurs de challenges…", spinner="dots"):
        result = run_solvers(target)

    delta = result["after"] - result["before"]
    console.print(
        f"\n[b]Résultat[/b] : {result['before']} → {result['after']} / {result['total']} "
        f"résolus ([green]+{delta}[/green])")
    if result["newly_solved"]:
        table = Table(title=f"Nouvellement résolus ({len(result['newly_solved'])})")
        table.add_column("Challenge")
        for name in result["newly_solved"]:
            table.add_row(name)
        console.print(table)
    else:
        console.print("[yellow]Aucun nouveau challenge résolu.[/yellow]")

    out_path = os.path.join(out_dir, "challenges.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    console.print(f"\n[green]→[/green] JSON : {out_path}")


@app.command()
def scope_check(
    target: str = typer.Argument(..., help="Cible à tester."),
    scope: str = typer.Option(None, "--scope", "-s"),
):
    """Teste seulement le garde-fou de périmètre sur une cible."""
    guard = _load_scope(scope)
    if guard.is_authorized(target):
        console.print(f"[green]✔ AUTORISÉE[/green] — hôte {guard.host_of(target)}")
    else:
        console.print(f"[red]✘ REFUSÉE[/red] — {target} (autorisés : {', '.join(guard.allowed)})")
        raise typer.Exit(code=2)


@app.command("list-workflows")
def list_workflows(
    directory: str = typer.Option(None, "--dir", "-d", help="Dossier des workflows (défaut : workflows/)."),
):
    """Liste les workflows YAML disponibles."""
    d = Path(directory) if directory else _WORKFLOWS_DIR
    if not d.exists():
        console.print(f"[red]Dossier introuvable : {d}[/red]")
        raise typer.Exit(code=1)
    names = sorted(p.name for p in d.iterdir() if p.suffix in (".yaml", ".yml"))
    if not names:
        console.print(f"[yellow]Aucun workflow trouvé dans {d}[/yellow]")
        return
    for name in names:
        console.print(f"• {name}")


if __name__ == "__main__":
    app()
