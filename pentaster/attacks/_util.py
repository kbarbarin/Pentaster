"""Aides internes partagées par les modules d'attaque (Stage 3).

Volontairement indépendant de `techniques.py` : ces helpers pilotent les
modules à partir de la SiteMap découverte par le crawl plutôt que de listes
d'endpoints en dur. Ne PAS importer depuis `techniques.py` — les deux moteurs
restent découplés (voir plan « Contrat des modules d'attaque »).
"""
from __future__ import annotations

import urllib.parse as _up

LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session")


def with_query_param(url: str, param: str, value: str) -> str:
    """Retourne `url` avec `param` ajouté/remplacé dans la query string."""
    parts = _up.urlsplit(url)
    q = _up.parse_qs(parts.query, keep_blank_values=True)
    q[param] = [value]
    new_query = _up.urlencode(q, doseq=True)
    return _up.urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def strip_query(url: str) -> str:
    parts = _up.urlsplit(url)
    return _up.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def iter_param_targets(sitemap):
    """Yield (url_sans_query, nom_param) découverts au crawl : `sitemap.params`
    et les paramètres des endpoints GET (`endpoints`/`api_endpoints`)."""
    seen = set()
    for url, names in (sitemap.params or {}).items():
        base = strip_query(url)
        for name in names:
            key = (base, name)
            if key not in seen:
                seen.add(key)
                yield base, name
    for ep in list(sitemap.endpoints) + list(sitemap.api_endpoints):
        if ep.method.upper() != "GET":
            continue
        base = strip_query(ep.url)
        for name in ep.params:
            key = (base, name)
            if key not in seen:
                seen.add(key)
                yield base, name


def iter_login_targets(sitemap):
    """Yield (url_post, noms_de_champs) pour les endpoints susceptibles
    d'accepter des identifiants : formulaires avec un champ password, et
    endpoints/api_endpoints POST dont le chemin évoque l'authentification."""
    seen = set()
    for form in sitemap.forms:
        has_pwd = any(t.lower() == "password" or n.lower() == "password"
                     for n, t in form.fields)
        if has_pwd and form.action not in seen:
            seen.add(form.action)
            names = [n for n, t in form.fields
                     if t.lower() != "password" and n.lower() != "password"]
            yield form.action, (names or ["email", "username"])
    for ep in list(sitemap.endpoints) + list(sitemap.api_endpoints):
        if ep.method.upper() != "POST":
            continue
        if ep.url in seen:
            continue
        low = ep.url.lower()
        if any(h in low for h in LOGIN_HINTS):
            seen.add(ep.url)
            yield ep.url, (list(ep.params) or ["email", "username"])


def ci_header(headers: dict, name: str, default: str = "") -> str:
    """Lecture d'en-tête insensible à la casse."""
    name = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return default


# --------------------------------------------------------------------------
# Fusion « découvert (SiteMap) + repli intégré (constantes en dur) ».
#
# Certains modules n'avaient de cibles QUE si le crawl avait trouvé quelque
# chose (SiteMap vide -> aucun test). Ces helpers fusionnent les cibles
# découvertes avec une base de repli générique (endpoints/paramètres REST
# courants), dédupliquée, pour que chaque module teste toujours au moins la
# surface standard — même contre une SPA que le crawler n'a pas su explorer.
# --------------------------------------------------------------------------

def merged_param_targets(sitemap, origin, common_endpoints=(), common_params=()):
    """(url_sans_query, param) découverts au crawl + repli intégré, dédupliqués."""
    seen = set()
    out = []
    for base_url, param in iter_param_targets(sitemap):
        key = (base_url, param)
        if key not in seen:
            seen.add(key)
            out.append((base_url, param))
    base = origin.rstrip("/")
    for ep in common_endpoints:
        base_url = base + ep
        for param in common_params:
            key = (base_url, param)
            if key not in seen:
                seen.add(key)
                out.append((base_url, param))
    return out


def merged_login_targets(sitemap, origin, common_endpoints=(),
                         common_fields=("email", "username")):
    """(url_post, noms_de_champs) découverts au crawl + repli intégré, dédupliqués."""
    seen = set()
    out = []
    for action, fields in iter_login_targets(sitemap):
        if action not in seen:
            seen.add(action)
            out.append((action, fields))
    base = origin.rstrip("/")
    for ep in common_endpoints:
        url = base + ep
        if url not in seen:
            seen.add(url)
            out.append((url, list(common_fields)))
    return out
