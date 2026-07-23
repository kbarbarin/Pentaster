"""Tests d'import/registre pour `pentaster.solvers` — aucun accès réseau.

`run_solvers` (et donc les solveurs eux-mêmes) exécutent des requêtes HTTP
réelles contre une cible Juice Shop : on ne les appelle jamais ici.
"""
from pentaster.solvers import SOLVERS, run_solvers


def test_solvers_module_imports():
    assert callable(run_solvers)
    assert isinstance(SOLVERS, list)


def test_solvers_registry_has_at_least_25_entries():
    assert len(SOLVERS) >= 25


def test_solvers_registry_entries_are_name_callable_tuples():
    for entry in SOLVERS:
        assert isinstance(entry, tuple)
        assert len(entry) == 2
        name, fn = entry
        assert isinstance(name, str) and name
        assert callable(fn)
