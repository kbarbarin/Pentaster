"""Modules d'attaque par catégorie de vulnérabilité.

Chaque module expose une (ou plusieurs) fonction `Callable[[AttackContext],
list[Finding]]` enregistrée dans `ATTACKS`. `run_attacks` les exécute toutes
en émettant une progression, à la manière de `techniques.run_techniques`.
"""
from __future__ import annotations

from typing import Callable

from ..scan_models import Finding
from .base import AttackContext

# Registre (category, nom lisible, fonction). Rempli à l'étape « attaques ».
ATTACKS: list[tuple[str, str, Callable[["AttackContext"], list[Finding]]]] = []


def run_attacks(ctx: AttackContext,
                progress: Callable[[str, str, object], None] | None = None) -> list[Finding]:
    """Exécute tous les modules d'attaque enregistrés contre `ctx`.

    Chaque module est isolé (try/except → []) pour qu'un module qui plante
    n'avorte pas la phase. `progress` reçoit ("attack","start",(category,name))
    avant chaque module puis ("attack","done",(name,count)) après.
    """
    from ..scan_models import Finding as _F  # noqa: F401 (garde le type importé)
    findings: list[Finding] = []
    for category, name, fn in ATTACKS:
        if progress:
            progress("attack", "start", (category, name))
        try:
            res = fn(ctx)
        except Exception:  # noqa: BLE001
            res = []
        findings.extend(res)
        if progress:
            progress("attack", "done", (name, len(res)))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity, 5))
    return findings
