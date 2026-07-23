"""Génération du rapport HTML autonome (jinja2) à partir d'un RunReport."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .engine import RunReport

# Racine du projet -> templates/ par défaut.
_DEFAULT_TEMPLATE_DIR = str(Path(__file__).resolve().parent.parent / "templates")

# Ordre de tri (le plus grave d'abord) + palette.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEVERITY_COLOR = {
    "critical": "#7c1d1d", "high": "#b91c1c", "medium": "#c2740c",
    "low": "#2563eb", "info": "#4b5563", "unknown": "#6b7280",
}


def _severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "unknown").lower(), 5)


def _duration(report: RunReport) -> str:
    fmt = "%Y-%m-%dT%H:%M:%S"
    try:
        delta = datetime.strptime(report.finished_at, fmt) - datetime.strptime(report.started_at, fmt)
        return f"{int(delta.total_seconds())} s"
    except (ValueError, TypeError):
        return "n/a"


def _build_context(report: RunReport) -> dict:
    findings = sorted(report.findings, key=lambda f: _severity_rank(f.severity))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
    techs = sorted({
        f.name for f in report.findings if f.type == "tech" and f.name
    })
    return {
        "report": report,
        "findings": findings,
        "counts": counts,
        "techs": techs,
        "duration": _duration(report),
        "severity_color": SEVERITY_COLOR,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def render_report(report: RunReport, template_dir: str | None = None,
                  template_name: str = "report.html.j2") -> str:
    env = Environment(
        loader=FileSystemLoader(template_dir or _DEFAULT_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    env.filters["sev_color"] = lambda s: SEVERITY_COLOR.get((s or "unknown").lower(), "#6b7280")
    template = env.get_template(template_name)
    return template.render(**_build_context(report))


def save_report(report: RunReport, out_dir: str, template_dir: str | None = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    html = render_report(report, template_dir=template_dir)
    path = os.path.join(out_dir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path
