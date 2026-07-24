"""Exposition de données : fichiers sensibles courants (dotfiles, backups,
config) et bypass d'extension par null byte sur des sauvegardes probables."""
from __future__ import annotations

import re

from ..scan_models import Finding
from .base import is_spa_shell

SENSITIVE_PATHS = {
    "/.env": r"[A-Z0-9_]+=",
    "/.git/config": r"\[core\]|\[remote",
    "/.git/HEAD": r"ref:\s*refs/",
    "/.aws/credentials": r"aws_access_key_id",
    "/config.json": r"[{].*[}]",
    "/package.json": r'"dependencies"|"name"\s*:',
    "/wp-config.php.bak": r"DB_PASSWORD|define\(",
    "/server-status": r"Apache Server Status",
    "/phpinfo.php": r"phpinfo\(\)|PHP Version",
    "/.well-known/security.txt": r"Contact:",
    "/backup.zip": r"PK\x03\x04",
    "/robots.txt": r"Disallow:",
}

NULL_BYTE_TARGETS = ["/ftp/package.json.bak", "/ftp/coupons.md.bak",
                     "/backup.zip", "/config.bak"]


def t_sensitive_files(ctx) -> list[Finding]:
    out: list[Finding] = []
    for path, sig in SENSITIVE_PATHS.items():
        st, _, body = ctx.safe_get(path)
        if st == 200 and not is_spa_shell(body or "") and re.search(sig, (body or "")[:4000], re.I | re.S):
            out.append(Finding("data-exposure", "sensitive-file-exposure", "medium",
                               ctx.origin.rstrip("/") + path,
                               f"HTTP 200, signature attendue présente ({path})",
                               request=f"GET {path}"))
    return out


def t_null_byte_backup_exposure(ctx) -> list[Finding]:
    out: list[Finding] = []
    for f in NULL_BYTE_TARGETS:
        target = f + "%2500.md"
        st, _, body = ctx.safe_get(target)
        if st == 200 and len(body or "") > 0 and not is_spa_shell(body or ""):
            out.append(Finding("data-exposure", "null-byte-extension-bypass", "medium",
                               ctx.origin.rstrip("/") + target,
                               "Filtre d'extension contourné via null byte (%2500)",
                               request=f"GET {target}"))
    return out


ATTACKS = [
    ("data-exposure", "Sensitive file exposure", t_sensitive_files),
    ("data-exposure", "Null-byte backup exposure", t_null_byte_backup_exposure),
]
