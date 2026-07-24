"""Contexte et helpers partagés par les modules d'attaque.

`AttackContext` porte le client HTTP (authentifié), la SiteMap découverte, la
session d'auth, le garde-fou de scope et l'origine. Les accès réseau passent
par `safe_get`/`safe_post` qui re-vérifient le scope à CHAQUE requête (une URL
dérivée du crawl pourrait pointer hors périmètre) — dernière barrière contre
le « scope drift ».
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..scan_models import SiteMap
from ..scope import ScopeGuard
from ..techniques import Http

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class AttackContext:
    http: Http
    sitemap: SiteMap
    guard: ScopeGuard
    origin: str
    session: Any = None          # AuthSession (fournie à l'étape auth) ; libre ici
    extra_headers: dict = field(default_factory=dict)

    # -- accès réseau garde-scopé -----------------------------------------
    def _abs(self, path: str) -> str:
        return path if path.startswith("http") else self.origin.rstrip("/") + path

    def _authorized(self, url: str) -> bool:
        return self.guard.is_authorized(url)

    def safe_get(self, path: str, **kw):
        url = self._abs(path)
        if not self._authorized(url):
            return (-1, {}, "")
        return self.http.get(path, **self._merge(kw))

    def safe_post(self, path: str, **kw):
        url = self._abs(path)
        if not self._authorized(url):
            return (-1, {}, "")
        return self.http.post(path, **self._merge(kw))

    def _merge(self, kw: dict) -> dict:
        """Fusionne les en-têtes d'auth/session dans la requête."""
        if not self.extra_headers:
            return kw
        headers = dict(self.extra_headers)
        headers.update(kw.get("headers") or {})
        return {**kw, "headers": headers}


def is_spa_shell(body: str) -> bool:
    """Vrai si la réponse est vraisemblablement la coquille HTML d'une SPA
    (beaucoup d'apps renvoient index.html en 200 pour tout chemin inconnu)."""
    head = body[:600].lower()
    return ("<!doctype html" in head or "<html" in head
            or "<app-root" in head or '<div id="root"' in head)


def negative_control_confirms(marker: str, positive_body: str, negative_body: str) -> bool:
    """Anti-faux-positif : le `marker` doit apparaître dans la réponse au
    payload actif MAIS PAS dans la réponse de contrôle (payload inerte)."""
    return marker in (positive_body or "") and marker not in (negative_body or "")
