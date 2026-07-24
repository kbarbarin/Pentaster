"""Structures de données du pipeline `scan` (recon → crawl → attaques → rapport).

Toutes les classes sont des dataclasses pures, sérialisables en JSON via
`scan_to_dict`. Elles sont volontairement isolées de toute I/O pour rester
testables sans réseau ni Docker.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field


# --------------------------------------------------------------------------
# Finding (propre au pipeline scan — 3e variante, avec `category` pour grouper).
# On NE touche pas à parsers.Finding ni techniques.Finding (chargées ailleurs).
# --------------------------------------------------------------------------
@dataclass
class Finding:
    category: str            # clé de groupe : "sqli", "xss", "idor", ...
    technique: str           # nom lisible du module/vérification
    severity: str            # critical | high | medium | low | info
    url: str
    evidence: str = ""
    confirmed: bool = True
    request: str = ""        # détail de reproduction optionnel
    raw: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Cartographie (SiteMap) produite par le crawl.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Endpoint:
    url: str                 # absolue, same-origin
    method: str              # GET | POST
    params: tuple[str, ...] = ()   # noms de paramètres (query/body)
    source: str = "link"     # link | form | api | seed
    content_type: str = ""


@dataclass(frozen=True)
class Form:
    action: str
    method: str
    fields: tuple[tuple[str, str], ...] = ()   # (nom, type) ex. ("email","email")


@dataclass
class SiteMap:
    origin: str
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    params: dict = field(default_factory=dict)      # url -> set[str] (noms de params)
    api_endpoints: list[Endpoint] = field(default_factory=list)
    authenticated: bool = False


# --------------------------------------------------------------------------
# Recon (nmap + fingerprint httpx).
# --------------------------------------------------------------------------
@dataclass
class Service:
    port: int
    proto: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""


@dataclass
class ReconResult:
    host: str
    docker_target: str = ""
    services: list[Service] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    raw_nmap_xml: str = ""
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Journal d'exécution + rapport global.
# --------------------------------------------------------------------------
@dataclass
class TimelineEvent:
    phase: str               # recon | crawl | attack | report
    event: str               # message court
    detail: str = ""
    ts: str = ""             # horodatage ISO (injecté)


@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str
    recon: ReconResult
    sitemap: SiteMap
    findings: list[Finding] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)


# --------------------------------------------------------------------------
# Sérialisation JSON — `dataclasses.asdict` ne gère pas les `set`
# (utilisés dans SiteMap.params) : on les convertit en listes triées.
# --------------------------------------------------------------------------
def _jsonable(value):
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def scan_to_dict(report: ScanReport) -> dict:
    """Rend un ScanReport pleinement JSON-sérialisable (sets → listes triées)."""
    return _jsonable(dataclasses.asdict(report))
