"""Parsers : convertissent la sortie brute de chaque outil en Findings normalisés."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Finding:
    tool: str
    target: str
    type: str
    severity: str
    name: str
    evidence: str = ""
    raw: dict = field(default_factory=dict)


def _iter_json_lines(stdout: str):
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def parse_httpx(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for obj in _iter_json_lines(stdout):
        techs = obj.get("tech") or obj.get("technologies") or []
        status = obj.get("status_code", "")
        url = obj.get("url", target)
        evidence = f"status {status}; tech: {', '.join(techs)}".strip()
        findings.append(
            Finding(
                tool="httpx",
                target=target,
                type="tech",
                severity="info",
                name=obj.get("title") or url,
                evidence=evidence,
                raw=obj,
            )
        )
    return findings


def parse_ffuf(stdout: str, target: str) -> list[Finding]:
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for res in data.get("results", []):
        url = res.get("url", "")
        findings.append(
            Finding(
                tool="ffuf",
                target=target,
                type="endpoint",
                severity="info",
                name=url,
                evidence=f"status {res.get('status', '')}; len {res.get('length', '')}",
                raw=res,
            )
        )
    return findings


def parse_nuclei(stdout: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for obj in _iter_json_lines(stdout):
        info = obj.get("info", {})
        findings.append(
            Finding(
                tool="nuclei",
                target=target,
                type="vulnerability",
                severity=info.get("severity", "info"),
                name=info.get("name", obj.get("template-id", "unknown")),
                evidence=obj.get("matched-at", ""),
                raw=obj,
            )
        )
    return findings


PARSERS: dict[str, Callable[[str, str], list[Finding]]] = {
    "httpx": parse_httpx,
    "ffuf": parse_ffuf,
    "nuclei": parse_nuclei,
}


def get_parser(name: str) -> Callable[[str, str], list[Finding]]:
    return PARSERS[name]
