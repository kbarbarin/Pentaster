"""Stage 1 — Recon : nmap (via Docker) + fingerprint httpx → ReconResult."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Callable, Optional

from .parsers import parse_httpx
from .runner import DockerFn, DockerRunner
from .scan_models import ReconResult, Service
from .workflow import Step

Progress = Callable[[str, str, object], None]

_NMAP_STEP = Step(
    id="nmap",
    tool="nmap",
    image="instrumentisto/nmap:latest",
    args=["-oX", "-", "-Pn", "{{target}}"],
    parser="nmap",
)

_HTTPX_STEP = Step(
    id="fingerprint",
    tool="httpx",
    image="projectdiscovery/httpx:latest",
    args=["-u", "{{target}}", "-json", "-tech-detect", "-silent"],
    parser="httpx",
)


def parse_nmap_xml(xml: str) -> list[Service]:
    """Parse la sortie `nmap -oX -`. Défensif : XML vide/invalide → []."""
    if not xml or not xml.strip():
        return []
    # Défense en profondeur XXE/entity-expansion : la sortie `nmap -oX -` ne
    # contient jamais légitimement de DOCTYPE/ENTITY ; on rejette par prudence
    # plutôt que de laisser le parseur stdlib les résoudre.
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        return []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []

    services: list[Service] = []
    for host in root.findall("host"):
        for ports in host.findall("ports"):
            for port in ports.findall("port"):
                state_el = port.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                service_el = port.find("service")
                name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                try:
                    portid = int(port.get("portid", "0"))
                except ValueError:
                    continue
                services.append(
                    Service(
                        port=portid,
                        proto=port.get("protocol", "tcp"),
                        state=state,
                        name=name,
                        product=product,
                        version=version,
                    )
                )
    return services


def run_recon(
    target: str,
    *,
    guard,
    wordlists_dir: str,
    docker_fn: Optional[DockerFn] = None,
    progress: Optional[Progress] = None,
) -> ReconResult:
    """Exécute nmap + httpx (fingerprint) sur `target`, jamais d'exception."""

    def emit(event: str, payload: object = None) -> None:
        if progress is not None:
            progress("recon", event, payload)

    host = guard.host_of(target) or target
    runner = DockerRunner(wordlists_dir, run_docker=docker_fn)
    result = ReconResult(host=host)

    emit("start", host)

    # -- nmap ---------------------------------------------------------
    try:
        nmap_res = runner.run(_NMAP_STEP, host)
        result.raw_nmap_xml = nmap_res.stdout
        if nmap_res.exit_code != 0 or not nmap_res.stdout.strip():
            result.notes.append(
                f"nmap a échoué ou n'a rien renvoyé (code {nmap_res.exit_code})."
            )
        else:
            result.services = parse_nmap_xml(nmap_res.stdout)
    except Exception as exc:  # pragma: no cover - défensif, ne doit jamais lever
        result.notes.append(f"nmap : erreur inattendue ({exc}).")

    for svc in result.services:
        emit("port", svc)

    # -- httpx fingerprint ---------------------------------------------
    try:
        httpx_res = runner.run(_HTTPX_STEP, target)
        if httpx_res.exit_code != 0 or not httpx_res.stdout.strip():
            if httpx_res.exit_code != 0:
                result.notes.append(
                    f"httpx (fingerprint) a échoué (code {httpx_res.exit_code})."
                )
        else:
            findings = parse_httpx(httpx_res.stdout, target)
            techs: list[str] = []
            for f in findings:
                for name in f.raw.get("tech") or f.raw.get("technologies") or []:
                    if name not in techs:
                        techs.append(name)
            result.tech = techs
    except Exception as exc:  # pragma: no cover - défensif, ne doit jamais lever
        result.notes.append(f"httpx : erreur inattendue ({exc}).")

    for name in result.tech:
        emit("tech", name)

    # -- caveat Docker-VM ------------------------------------------------
    docker_target = runner.rewrite_target(host)
    result.docker_target = docker_target
    if docker_target == "host.docker.internal":
        result.notes.append(
            "nmap s'exécute dans la VM Docker (host.docker.internal), pas l'hôte "
            "macOS — ports indicatifs."
        )

    emit("done", result)
    return result
