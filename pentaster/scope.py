"""Garde-fou d'autorisation : refuse toute cible hors allowlist."""
from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(Exception):
    """Levée quand une cible n'est pas autorisée par le scope."""


class ScopeGuard:
    DEFAULT_ALLOWED = ["localhost", "127.0.0.1"]

    def __init__(self, allowed: list[str]):
        entries = [a.strip().lower() for a in allowed if a.strip() and not a.strip().startswith("#")]
        self.allowed = list(dict.fromkeys(self.DEFAULT_ALLOWED + entries))

    @classmethod
    def from_file(cls, path: str) -> "ScopeGuard":
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        return cls(lines)

    def host_of(self, target: str) -> str | None:
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            hostname = parsed.hostname
        except ValueError:
            return None
        if hostname and " " not in hostname:
            return hostname
        return None

    def is_authorized(self, target: str) -> bool:
        host = self.host_of(target)
        if host is None:
            return False
        host = host.lower()
        for entry in self.allowed:
            if host == entry or host.endswith("." + entry):
                return True
        return False
