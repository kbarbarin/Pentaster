"""Stage 2 — Auth : session applicative GÉNÉRIQUE (register puis login).

Contrairement à `solvers.Session.login` (spécifique à OWASP Juice Shop), ce
module ne connaît aucune application en particulier : il tente une poignée
d'endpoints d'inscription/connexion usuels et capture soit un jeton bearer,
soit un cookie de session, quel que soit le shape exact de la réponse.

Ne lève jamais : un échec de register/login dégrade proprement en session
non authentifiée (`authenticated=False`) plutôt que d'avorter le pipeline.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

Progress = Callable[[str, str, object], None]

REGISTER_ENDPOINTS = ["/api/Users", "/api/register", "/register", "/api/auth/register"]
LOGIN_ENDPOINTS = ["/rest/user/login", "/api/login", "/api/auth/login", "/login"]


@dataclass
class AuthSession:
    headers: dict = field(default_factory=dict)
    token: Optional[str] = None
    authenticated: bool = False
    email: Optional[str] = None


def _throwaway_credentials(origin: str) -> tuple[str, str]:
    """Identifiants déterministes dérivés de `origin` (pas de random : tests stables)."""
    n = abs(hash(origin)) % 100000
    email = f"pentaster_{n}@probe.tld"
    password = f"Pxr!{n}Aa9Zq"
    return email, password


def _extract_token(body: str) -> Optional[str]:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    auth = data.get("authentication")
    if isinstance(auth, dict) and auth.get("token"):
        return auth["token"]
    for key in ("token", "jwt", "accessToken"):
        val = data.get(key)
        if val:
            return val
    return None


def _extract_cookie(headers: dict) -> Optional[str]:
    if not headers:
        return None
    for k, v in headers.items():
        if k.lower() == "set-cookie" and v:
            # Ne garde que le couple nom=valeur (avant le premier ';').
            return v.split(";", 1)[0].strip()
    return None


def authenticate(http, origin: str, *, guard, progress: Progress | None = None) -> AuthSession:
    """Tente register puis login contre `origin` ; ne lève jamais."""
    if progress:
        progress("auth", "start", origin)

    try:
        if not guard.is_authorized(origin):
            if progress:
                progress("auth", "login-fail", "hors scope")
            return AuthSession(authenticated=False, headers={})

        email, password = _throwaway_credentials(origin)
        payload = {"email": email, "password": password, "passwordRepeat": password,
                   "username": email}

        for ep in REGISTER_ENDPOINTS:
            if not guard.is_authorized(origin):
                break
            try:
                http.post(ep, data=payload)
            except Exception:  # noqa: BLE001
                continue

        for ep in LOGIN_ENDPOINTS:
            if not guard.is_authorized(origin):
                break
            try:
                st, headers, body = http.post(ep, data={"email": email, "password": password,
                                                          "username": email})
            except Exception:  # noqa: BLE001
                continue
            if st in (-1, 404):
                continue

            token = _extract_token(body)
            cookie = _extract_cookie(headers)
            if token or cookie:
                out_headers = {}
                if token:
                    out_headers["Authorization"] = f"Bearer {token}"
                if cookie:
                    out_headers["Cookie"] = cookie
                if progress:
                    progress("auth", "login-ok", ep)
                return AuthSession(headers=out_headers, token=token,
                                   authenticated=True, email=email)

        if progress:
            progress("auth", "login-fail", "aucun endpoint n'a renvoyé de jeton/cookie")
        return AuthSession(authenticated=False, headers={}, email=email)
    except Exception:  # noqa: BLE001
        if progress:
            progress("auth", "login-fail", "exception inattendue")
        return AuthSession(authenticated=False, headers={})
