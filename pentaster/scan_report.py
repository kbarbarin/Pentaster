"""Assemblage du rapport riche `pentaster scan` : groupage par catégorie,
rendu HTML (jinja2, autoescape) et écriture disque (`scan.json` + `scan.html`).

Mirroire le pattern de `report.py` / `cli._render_audit_html` : même
`Environment(autoescape=select_autoescape([...]))`, même filtre `sev_color`.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .report import SEVERITY_COLOR, SEVERITY_ORDER
from .scan_models import Finding, ScanReport, scan_to_dict

_DEFAULT_TEMPLATE_DIR = str(Path(__file__).resolve().parent.parent / "templates")


def _severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "unknown").lower(), 5)


def group_by_category(findings: list[Finding]) -> dict:
    """Groupe les findings par `category`, triés par sévérité au sein de chaque groupe.

    Préserve l'ordre d'apparition des catégories (premier finding rencontré).
    """
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.category, []).append(f)
    for cat, items in grouped.items():
        grouped[cat] = sorted(items, key=lambda f: _severity_rank(f.severity))
    return grouped


def render_scan_html(report: ScanReport, template_dir: Optional[str] = None) -> str:
    env = Environment(
        loader=FileSystemLoader(template_dir or _DEFAULT_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    env.filters["sev_color"] = lambda s: SEVERITY_COLOR.get((s or "unknown").lower(), "#6b7280")

    by_category = group_by_category(report.findings)
    counts = Counter(f.severity.lower() for f in report.findings)

    template = env.get_template("scan.html.j2")
    return template.render(
        report=report,
        by_category=by_category,
        counts=counts,
        severity_color=SEVERITY_COLOR,
        generated_at=datetime.now().isoformat(timespec="seconds"),
    )


def save_scan(report: ScanReport, out_dir: str) -> tuple[str, str]:
    """Écrit `scan.json` et `scan.html` dans `out_dir` ; retourne les deux chemins."""
    os.makedirs(out_dir, exist_ok=True)

    json_path = os.path.join(out_dir, "scan.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(scan_to_dict(report), fh, indent=2, ensure_ascii=False)

    html_path = os.path.join(out_dir, "scan.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render_scan_html(report))

    return json_path, html_path
