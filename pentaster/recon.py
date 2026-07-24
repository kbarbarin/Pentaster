"""Stage 1 — Recon : nmap (via Docker) + fingerprint httpx → ReconResult."""
from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from typing import Callable, Optional
from urllib.parse import urlparse

from .parsers import parse_httpx
from .runner import DockerFn, DockerRunner
from .scan_models import ReconResult, Service
from .workflow import Step

Progress = Callable[[str, str, object], None]

# Ports courants scannés en plus du port explicite de la cible, pour que le
# scan trouve les services dev/web habituels (dont 3000, souvent hors du
# top-1000 par défaut de nmap → cause du « 0 port » sur localhost:3000).
_COMMON_PORTS = "21,22,25,53,80,110,143,443,3000,3306,5432,6379,8000,8080,8443,9200,27017"


def _target_port(target: str) -> int:
    parsed = urlparse(target if "://" in target else "http://" + target)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


_PORT_NAMES = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 3000: "http-dev", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


def _socket_connect(host: str, port: int, timeout: float = 0.6) -> bool:
    """Teste un port TCP depuis l'HÔTE (pas un conteneur) : atteint localhost."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


def tcp_port_scan(host: str, ports: list[int],
                  connect: Callable[[str, int], bool] = _socket_connect) -> list[Service]:
    """Scan TCP-connect natif depuis l'hôte Python (complément à nmap, qui via
    Docker ne peut pas atteindre un service lié à 127.0.0.1)."""
    found = []
    for port in ports:
        if connect(host, port):
            found.append(Service(port=port, state="open", name=_PORT_NAMES.get(port, "")))
    return found


def _scan_ports(target: str) -> list[int]:
    tp = _target_port(target)
    common = [int(p) for p in _COMMON_PORTS.split(",")]
    return [tp] + [p for p in common if p != tp]


def _nmap_step_for(target: str) -> Step:
    """Construit une étape nmap qui scanne le port de la cible + ports courants,
    avec détection de service/version (`-sV`)."""
    ports = f"{_target_port(target)},{_COMMON_PORTS}"
    return Step(
        id="nmap",
        tool="nmap",
        image="instrumentisto/nmap:latest",
        # -T4 (timing agressif) + --host-timeout borne la durée : sinon les
        # ports fermés/filtrés font attendre nmap (scan interminable).
        args=["-Pn", "-sV", "-T4", "--host-timeout", "20s",
              "-p", ports, "-oX", "-", "{{target}}"],
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
    connect: Optional[Callable[[str, int], bool]] = None,
) -> ReconResult:
    """Exécute nmap (Docker) + un scan TCP natif + httpx (fingerprint) sur
    `target`, jamais d'exception. `connect` (injectable) permet de tester le
    scan TCP sans réseau."""
    connect = connect or _socket_connect

    def emit(event: str, payload: object = None) -> None:
        if progress is not None:
            progress("recon", event, payload)

    host = guard.host_of(target) or target
    runner = DockerRunner(wordlists_dir, run_docker=docker_fn)
    result = ReconResult(host=host)

    emit("start", host)

    # -- nmap ---------------------------------------------------------
    try:
        nmap_res = runner.run(_nmap_step_for(target), host)
        result.raw_nmap_xml = nmap_res.stdout
        if nmap_res.exit_code != 0 or not nmap_res.stdout.strip():
            result.notes.append(
                f"nmap a échoué ou n'a rien renvoyé (code {nmap_res.exit_code})."
            )
        else:
            result.services = parse_nmap_xml(nmap_res.stdout)
    except Exception as exc:  # pragma: no cover - défensif, ne doit jamais lever
        result.notes.append(f"nmap : erreur inattendue ({exc}).")

    # -- scan TCP natif (depuis l'hôte : atteint localhost/127.0.0.1) --
    try:
        seen = {s.port for s in result.services}
        for svc in tcp_port_scan(host, _scan_ports(target), connect=connect):
            if svc.port not in seen:
                result.services.append(svc)
                seen.add(svc.port)
        result.notes.append("Ports confirmés par scan TCP natif (depuis l'hôte).")
    except Exception as exc:  # pragma: no cover - défensif
        result.notes.append(f"scan TCP : erreur inattendue ({exc}).")

    result.services.sort(key=lambda s: s.port)
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
