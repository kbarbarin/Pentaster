"""Stage 4 — Orchestrateur : enchaîne Recon → Auth → Crawl → Attaques et
assemble un `ScanReport` unique.

Pur et injectable : Docker (`docker_fn`) et le client HTTP (`http_factory`)
sont toujours fournis par l'appelant (jamais de réseau/Docker réel ici, ni
dans les tests). Une phase qui plante n'avorte jamais le scan — sauf le
contrôle de scope à l'entrée, qui lève `ScopeError` immédiatement — elle
dégrade proprement (résultat vide) et laisse une trace dans la timeline.
"""
from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from .attacks import run_attacks
from .attacks.base import SEVERITY_ORDER, AttackContext
from .auth import AuthSession, authenticate
from .crawler import run_crawl
from .recon import run_recon
from .runner import DockerFn
from .scan_models import ReconResult, ScanReport, SiteMap, TimelineEvent
from .scope import ScopeError
from .techniques import Http

Progress = Callable[[str, str, object], None]


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def run_full_scan(
    target: str,
    *,
    guard,
    wordlists_dir: str,
    docker_fn: Optional[DockerFn] = None,
    http_factory: Optional[Callable[[str], object]] = None,
    max_pages: int = 100,
    max_depth: int = 3,
    do_auth: bool = True,
    now: Callable[[], str] = _now_iso,
    progress: Optional[Progress] = None,
) -> ScanReport:
    """Exécute le pipeline complet contre `target` (autorisé par `guard`)."""
    if not guard.is_authorized(target):
        raise ScopeError(f"Cible non autorisée par le scope : {target}")

    http_factory = http_factory or (lambda base: Http(base))
    origin = target

    timeline: list[TimelineEvent] = []

    def emit(phase: str, event: str, detail: object = "") -> None:
        timeline.append(TimelineEvent(phase=phase, event=event, detail=str(detail), ts=now()))

    def fwd(phase: str, event: str, payload: object) -> None:
        if progress is not None:
            progress(phase, event, payload)

    started = now()
    http = http_factory(origin)

    # -- 1. Recon ----------------------------------------------------------
    emit("recon", "start")
    try:
        recon = run_recon(target, guard=guard, wordlists_dir=wordlists_dir,
                          docker_fn=docker_fn, progress=fwd)
        emit("recon", "done", f"{len(recon.services)} service(s), {len(recon.tech)} techno(s)")
    except Exception as exc:  # noqa: BLE001 - une phase ne doit jamais avorter le scan
        recon = ReconResult(host=guard.host_of(target) or target)
        emit("recon", "error", f"recon en échec : {exc}")

    # -- 2. Auth -------------------------------------------------------------
    session: Optional[AuthSession] = None
    if do_auth:
        emit("auth", "start")
        try:
            session = authenticate(http, origin, guard=guard, progress=fwd)
            emit("auth", "done", "authentifié" if session.authenticated else "non authentifié")
        except Exception as exc:  # noqa: BLE001
            session = AuthSession(authenticated=False)
            emit("auth", "error", f"auth en échec : {exc}")
    else:
        emit("auth", "skipped")

    # -- 3. Crawl --------------------------------------------------------
    emit("crawl", "start")
    try:
        sitemap = run_crawl(origin, http=http, guard=guard, session=session,
                            max_pages=max_pages, max_depth=max_depth, progress=fwd)
        emit("crawl", "done",
             f"{len(sitemap.endpoints)} endpoint(s), {len(sitemap.forms)} formulaire(s)")
    except Exception as exc:  # noqa: BLE001
        sitemap = SiteMap(origin=origin, authenticated=bool(session and session.authenticated))
        emit("crawl", "error", f"crawl en échec : {exc}")

    # -- 4. Attaques -------------------------------------------------------
    emit("attack", "start")
    try:
        extra_headers = dict(session.headers) if (session and session.authenticated) else {}
        ctx = AttackContext(http=http, sitemap=sitemap, guard=guard, origin=origin,
                            session=session, extra_headers=extra_headers)
        findings = run_attacks(ctx, progress=fwd)
        emit("attack", "done", f"{len(findings)} finding(s)")
    except Exception as exc:  # noqa: BLE001
        findings = []
        emit("attack", "error", f"attaques en échec : {exc}")

    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))

    finished = now()

    return ScanReport(
        target=target,
        started_at=started,
        finished_at=finished,
        recon=recon,
        sitemap=sitemap,
        findings=findings,
        timeline=timeline,
    )
