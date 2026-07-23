#!/usr/bin/env python3
"""Pentaster — solveur de challenges OWASP Juice Shop (CLI autonome).

Fine enveloppe autour de `pentaster.solvers.run_solvers` : parse la cible
depuis argv (défaut : http://localhost:3000) et affiche le même résumé
lisible qu'auparavant. Toute la logique d'exploit vit maintenant dans
`pentaster/solvers.py` (module importable, testable sans réseau).

Usage : python3 scripts/solve.py [http://localhost:3000]
"""
from __future__ import annotations

import sys
from pathlib import Path

# Permet l'exécution directe (`python3 scripts/solve.py`) sans installation
# préalable du package : on ajoute la racine du repo au PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pentaster.solvers import run_solvers  # noqa: E402


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    result = run_solvers(base)

    print(f"Avant : {result['before']}/{result['total']} résolus\n")
    for label, ok in result["ran"]:
        print(f"  {'→' if ok else '·'} {label:32} exploit {'exécuté' if ok else 'échec'}")

    print(f"\nAprès : {result['after']}/{result['total']} résolus  "
          f"(+{result['after'] - result['before']})")
    print("Nouvellement résolus :")
    for k in result["newly_solved"]:
        print("  ✓", k)


if __name__ == "__main__":
    main()
