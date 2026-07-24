"""Point d'entrée CLI (typer + rich) : `pentaster run <workflow> --target <url>`."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Callable

import dataclasses

import typer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .engine import Engine
from .report import SEVERITY_COLOR
from .report import save_report
from .results import save_results
from .runner import DockerRunner
from .scan_report import group_by_category, save_scan
from .scanner import run_full_scan
from .scope import ScopeError, ScopeGuard
from .solvers import run_solvers
from .techniques import run_techniques
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

    console.print("\n[bold cyan]💥 Exploits exécutés[/bold cyan]")

    def _on_solve(event, label, ok):
        if event == "start":
            console.print(f"  [cyan]⚙[/cyan]  [dim]exploit :[/dim] {label}…")
        elif ok:
            console.print(f"     [green][bold]✓ exploit OK[/bold] ({label})[/green]")

    result = run_solvers(target, progress=_on_solve)

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


def _render_audit_html(result: dict, template_dir: str | None = None) -> str:
    """Rend le rapport HTML autonome de `pentaster audit` (jinja2, autoescape)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(result["findings"], key=lambda f: order.get((f.severity or "").lower(), 5))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
    env = Environment(
        loader=FileSystemLoader(template_dir or str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    env.filters["sev_color"] = lambda s: SEVERITY_COLOR.get((s or "unknown").lower(), "#6b7280")
    template = env.get_template("audit.html.j2")
    return template.render(
        target=result["target"],
        findings=findings,
        counts=counts,
        generated_at=datetime.now().isoformat(timespec="seconds"),
    )


@app.command()
def audit(
    target: str = typer.Option(..., "--target", "-t", help="URL/hôte cible (lab autorisé)."),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirme explicitement l'autorisation de tester la cible."),
    scope: str = typer.Option(None, "--scope", "-s", help="Fichier d'allowlist (défaut : scope.txt)."),
    out: str = typer.Option(None, "--out", "-o", help="Dossier de sortie (défaut : runs/<timestamp>)."),
):
    """Exécute le moteur d'exploitation web générique contre une cible autorisée."""
    try:
        guard = _load_scope(scope)
    except typer.BadParameter as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1)

    # Même double garde-fou que `run`/`solve` : flag explicite ET appartenance au scope.
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
        f"[b]Sortie[/b] : {out_dir}", title="Pentaster — Audit", border_style="green"))

    console.print("\n[bold cyan]🔎 Techniques testées[/bold cyan]")

    def _on_tech(event, name, count):
        if event == "start":
            console.print(f"  [cyan]⚙[/cyan]  [dim]test :[/dim] {name}…")
        elif count:
            console.print(f"     [green on default][bold]✓ {count} vulnérabilité(s)[/bold][/] "
                          f"[green]({name})[/green]")

    result = run_techniques(target, progress=_on_tech)
    findings = result["findings"]

    from collections import Counter
    counts = Counter(f.severity.lower() for f in findings)
    summary = "   ".join(
        f"[{_SEV_STYLE.get(s, 'white')}]{counts[s]} {s}[/]"
        for s in ("critical", "high", "medium", "low", "info") if counts.get(s))

    console.print()
    table = Table(title=f"Vulnérabilités trouvées — {result['target']} ({len(findings)})",
                  header_style="bold")
    table.add_column("Sévérité"); table.add_column("Technique")
    table.add_column("URL", max_width=55); table.add_column("Preuve", max_width=55)
    for f in findings:
        style = _SEV_STYLE.get(f.severity.lower(), "white")
        table.add_row(f"[{style}]{f.severity.upper()}[/]", f.technique, f.url, f.evidence)
    console.print(table)
    if summary:
        console.print(f"[bold]Résumé :[/bold] {summary}")
    else:
        console.print("[green]Aucune vulnérabilité confirmée.[/green]")

    json_path = os.path.join(out_dir, "audit.json")
    serializable = {
        "target": result["target"],
        "findings": [dataclasses.asdict(f) for f in findings],
        "ran": result["ran"],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(serializable, fh, indent=2, ensure_ascii=False)

    html_path = os.path.join(out_dir, "audit.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(_render_audit_html(result))

    console.print(f"\n[green]→[/green] JSON : {json_path}")
    console.print(f"[green]→[/green] Rapport HTML : {html_path}")


def _trunc(s: str, n: int = 70) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="URL/hôte cible (lab autorisé)."),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirme explicitement l'autorisation de tester la cible."),
    scope: str = typer.Option(None, "--scope", "-s", help="Fichier d'allowlist (défaut : scope.txt)."),
    out: str = typer.Option(None, "--out", "-o", help="Dossier de sortie (défaut : runs/<timestamp>)."),
    wordlists: str = typer.Option(None, "--wordlists", "-w", help="Dossier de wordlists monté dans les conteneurs."),
    templates: str = typer.Option(None, "--templates", help="Dossier des templates de rapport."),
    max_pages: int = typer.Option(100, "--max-pages", help="Nombre maximum de pages explorées lors du crawl."),
    max_depth: int = typer.Option(3, "--max-depth", help="Profondeur maximale du crawl."),
    no_auth: bool = typer.Option(False, "--no-auth", help="Désactive l'authentification automatique avant le crawl."),
):
    """Pipeline complet : recon (nmap) → auth → crawl → attaques par catégorie → rapport riche."""
    try:
        guard = _load_scope(scope)
    except typer.BadParameter as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1)

    # Même double garde-fou que `run`/`solve`/`audit` : flag explicite ET appartenance au scope.
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

    wl_dir = os.path.abspath(wordlists or str(_WORDLISTS_DIR))
    out_dir = out or str(_ROOT / "runs" / datetime.now().strftime("%Y%m%d-%H%M%S"))
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        f"[b]Cible[/b] : {target}\n"
        f"[b]Scope OK[/b] : {guard.host_of(target)}\n"
        f"[b]Sortie[/b] : {out_dir}", title="Pentaster — Scan", border_style="green"))

    _last_phase: list[str] = [""]
    _PHASE_TITLE = {
        "recon": "🛰  Recon (nmap + fingerprint)",
        "auth": "🔐 Authentification",
        "crawl": "🕸  Cartographie (crawl)",
        "attack": "🔎 Attaques par catégorie",
        "nuclei": "☢  Nuclei (templates de vulnérabilités)",
        "exploit": "💥 Exploitation profonde (vulns réelles du site)",
    }

    def _header(phase: str) -> None:
        if _last_phase[0] != phase:
            _last_phase[0] = phase
            title = _PHASE_TITLE.get(phase, phase)
            console.print(f"\n[bold cyan]{title}[/bold cyan]")

    def _on_scan(phase, event, payload):
        _header(phase)
        if phase == "recon":
            if event == "port":
                svc = payload
                console.print(
                    f"  [cyan]▪[/cyan] port {svc.port}/{svc.proto} "
                    f"[dim]{svc.name} {svc.product} {svc.version}[/dim]".rstrip())
            elif event == "tech":
                console.print(f"  [green]▪[/green] techno : {payload}")
        elif phase == "auth":
            if event == "login-ok":
                console.print(f"  [green]🔐 login OK[/green] [dim]({payload})[/dim]")
            elif event == "login-fail":
                console.print(f"  [yellow]🔐 login échec[/yellow] [dim]({payload})[/dim]")
        elif phase == "crawl":
            if event == "endpoint":
                e = payload
                console.print(f"  [dim]→ {e.method} {_trunc(e.url)}[/dim]")
            elif event == "form":
                f = payload
                console.print(f"  [dim]⛶ form {f.method} {_trunc(f.action)}[/dim]")
        elif phase == "attack":
            if event == "start":
                _cat, name = payload
                console.print(f"  [cyan]⚙[/cyan] [dim]{name}…[/dim]")
            elif event == "done":
                name, count = payload
                if count:
                    console.print(f"     [green]✓ {count} vuln ({name})[/green]")
        elif phase == "nuclei":
            if event == "finding":
                f = payload
                style = _SEV_STYLE.get(getattr(f, "severity", "info"), "white")
                console.print(f"  [{style}]☢ {getattr(f, 'technique', '')}[/] "
                              f"[dim]{_trunc(getattr(f, 'url', ''))}[/dim]")
        elif phase == "exploit":
            if event == "solved":
                console.print(f"  [green]💥 exploit confirmé[/green] [bold]{payload}[/bold]")
            elif event == "skipped":
                console.print("  [dim]cible non compatible (pas d'API de challenges) — phase ignorée[/dim]")

    try:
        with console.status("[bold green]Exécution du pipeline de scan…", spinner="dots"):
            report = run_full_scan(
                target,
                guard=guard,
                wordlists_dir=wl_dir,
                max_pages=max_pages,
                max_depth=max_depth,
                do_auth=not no_auth,
                progress=_on_scan,
            )
    except ScopeError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=3)

    findings = report.findings
    by_category = group_by_category(findings)

    console.print()
    table = Table(title=f"Vulnérabilités trouvées — {report.target} ({len(findings)})",
                  header_style="bold")
    table.add_column("Catégorie"); table.add_column("Sévérité"); table.add_column("Technique")
    table.add_column("URL", max_width=55); table.add_column("Preuve", max_width=55)
    for cat, items in by_category.items():
        for f in items:
            style = _SEV_STYLE.get(f.severity.lower(), "white")
            table.add_row(cat, f"[{style}]{f.severity.upper()}[/]", f.technique, f.url, f.evidence)
    console.print(table)

    from collections import Counter
    counts = Counter(f.severity.lower() for f in findings)
    summary = "   ".join(
        f"[{_SEV_STYLE.get(s, 'white')}]{counts[s]} {s}[/]"
        for s in ("critical", "high", "medium", "low", "info") if counts.get(s))
    if summary:
        console.print(f"[bold]Résumé :[/bold] {summary}")
    else:
        console.print("[green]Aucune vulnérabilité confirmée.[/green]")

    json_path, html_path = save_scan(report, out_dir)
    console.print(f"\n[green]→[/green] JSON : {json_path}")
    console.print(f"[green]→[/green] Rapport HTML : {html_path}")


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
