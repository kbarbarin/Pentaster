"""Point d'entrée CLI (typer + rich) : `pentaster run <workflow> --target <url>`."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .engine import Engine
from .report import save_report
from .results import save_results
from .runner import DockerRunner
from .scope import ScopeError, ScopeGuard
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
    guard = _load_scope(scope)

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
        raise typer.Exit(code=2)

    wf_path = _resolve_workflow(workflow)
    wf = load_workflow(str(wf_path))

    wl_dir = str(Path(wordlists).resolve()) if wordlists else str(_WORDLISTS_DIR)
    tpl_dir = templates or str(_TEMPLATES_DIR)
    out_dir = out or str(_ROOT / "runs" / datetime.now().strftime("%Y%m%d-%H%M%S"))

    console.print(Panel.fit(
        f"[b]Workflow[/b] : {wf.name} ({wf_path.name})\n"
        f"[b]Cible[/b] : {target}\n"
        f"[b]Scope OK[/b] : {guard.host_of(target)}\n"
        f"[b]Sortie[/b] : {out_dir}", title="Pentaster", border_style="green"))

    runner = DockerRunner(wl_dir)
    engine = Engine(runner, guard)

    try:
        with console.status("[bold green]Exécution du workflow (conteneurs Docker)…", spinner="dots"):
            report = engine.execute(wf, target)
    except ScopeError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2)

    _print_summary(report)

    json_path = save_results(report, out_dir)
    html_path = save_report(report, out_dir, template_dir=tpl_dir)
    console.print(f"\n[green]→[/green] JSON  : {json_path}")
    console.print(f"[green]→[/green] Rapport HTML : {html_path}")


def _print_summary(report) -> None:
    table = Table(title=f"Findings — {report.target} ({len(report.findings)})")
    table.add_column("Sév"); table.add_column("Type"); table.add_column("Nom", max_width=50)
    table.add_column("Outil")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(report.findings, key=lambda x: order.get(x.severity.lower(), 5)):
        style = _SEV_STYLE.get(f.severity.lower(), "white")
        table.add_row(f"[{style}]{f.severity}[/]", f.type, f.name, f.tool)
    console.print(table)
    for o in report.outcomes:
        if o.exit_code != 0:
            console.print(f"[yellow]⚠ étape {o.step_id} ({o.tool}) code {o.exit_code}[/yellow]")


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


if __name__ == "__main__":
    app()
