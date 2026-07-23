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
