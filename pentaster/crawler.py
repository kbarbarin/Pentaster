"""Stage 2 — Crawl : BFS same-origin (authentifié ou non) → SiteMap.

Parse le HTML avec `html.parser.HTMLParser` (stdlib) : liens `<a href>`,
formulaires `<form>` (+ champs), et une regex sur le texte brut pour repérer
les fragments `/api/...` / `/rest/...` (enregistrés mais jamais suivis).

Anti-scope-drift : chaque URL déqueuée est revérifiée via
`guard.is_authorized(url)` *avant* toute requête HTTP, en plus du filtre
same-origin sur le netloc.
"""
from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse, parse_qsl

from .scan_models import Endpoint, Form, SiteMap

Progress = Callable[[str, str, object], None]

API_FRAGMENT_RE = re.compile(r"(?:\"|'|\s|^)(/(?:api|rest)/[A-Za-z0-9_\-/.]+)")

# Fragments d'endpoints dans un bundle JS : `/api/...` ou `/rest/...` entre
# guillemets (routes/appels fetch), ou tout chemin absolu quoté générique
# qui « ressemble » à un endpoint (filtré ensuite par `_looks_like_endpoint`).
JS_API_FRAGMENT_RE = re.compile(r"[\"'](/(?:api|rest)/[A-Za-z0-9_\-/.]+)[\"']")
JS_GENERIC_PATH_RE = re.compile(r"[\"'](/[A-Za-z][A-Za-z0-9_\-/]{1,60})[\"']")
ASSET_EXT_RE = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?|json)$", re.I)

MAX_JS_FILES = 10
MAX_JS_BODY_CHARS = 5_000_000

# Endpoints REST/API courants ajoutés systématiquement à la SiteMap (source
# "seed"), pour donner une base de test aux modules d'attaque même quand le
# crawl HTML/JS reste maigre (SPA peu explorable). Conventions génériques +
# quelques chemins fréquents (ex. OWASP Juice Shop) à titre d'exemples usuels.
COMMON_ENDPOINTS = [
    "/api/Users", "/api/Products", "/api/Feedbacks", "/api/Addresses",
    "/api/BasketItems", "/api/login", "/api/register", "/api/me",
    "/api/profile", "/api/products", "/api/users", "/api/search",
    "/rest/user/login", "/rest/user/whoami", "/rest/user/register",
    "/rest/products/search", "/rest/basket", "/rest/basket/1",
]


def _looks_like_endpoint(path: str) -> bool:
    if not (2 <= len(path) <= 60):
        return False
    if ASSET_EXT_RE.search(path):
        return False
    if path.count("/") > 5:
        return False
    if any(c in path for c in (" ", "\\", "{", "}", "<", ">")):
        return False
    return True


def _extract_js_endpoint_paths(body: str) -> set[str]:
    """Extrait les fragments `/api/...`/`/rest/...` et chemins quotés
    génériques ressemblant à des endpoints, depuis un corps de bundle JS."""
    paths: set[str] = set()
    for m in JS_API_FRAGMENT_RE.finditer(body):
        paths.add(m.group(1))
    for m in JS_GENERIC_PATH_RE.finditer(body):
        candidate = m.group(1)
        if _looks_like_endpoint(candidate):
            paths.add(candidate)
    return paths


class LinkFormParser(HTMLParser):
    """Extrait les liens `<a href>` et les formulaires `<form>` d'une page HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self._form: Optional[dict] = None
        self.forms: list[dict] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        adict = dict(attrs)
        if tag == "a" and adict.get("href"):
            self.links.append(adict["href"])
        elif tag == "script" and adict.get("src"):
            self.scripts.append(adict["src"])
        elif tag == "form":
            self._form = {
                "action": adict.get("action", ""),
                "method": (adict.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = adict.get("name")
            if name:
                typ = adict.get("type", "text") if tag == "input" else tag
                self._form["fields"].append((name, typ))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _is_html(headers: dict) -> bool:
    lc = {k.lower(): v for k, v in (headers or {}).items()}
    ct = lc.get("content-type", "")
    return "html" in ct.lower()


def _dedupe_key(url: str) -> tuple[str, tuple[str, ...]]:
    parsed = urlparse(url)
    params = tuple(sorted({k for k, _v in parse_qsl(parsed.query)}))
    return (parsed.path, params)


def _normalize(url: str) -> str:
    """Ajoute un `/` final si l'URL n'a pas de chemin (ex. bare origin)."""
    parsed = urlparse(url)
    if parsed.path == "":
        return url + "/"
    return url


def run_crawl(origin: str, *, http, guard, session=None, max_pages: int = 100,
              max_depth: int = 3, seeds=None, progress: Progress | None = None) -> SiteMap:
    sitemap = SiteMap(origin=origin, authenticated=bool(session and session.authenticated))

    origin_netloc = urlparse(origin).netloc

    extra_headers = {}
    if session and session.authenticated:
        extra_headers = dict(session.headers)

    start_urls = [_normalize(origin)] + list(seeds or [])
    queue = deque((u, 0) for u in start_urls)
    seen_keys: set[tuple[str, tuple[str, ...]]] = set()
    seen_api_urls: set[str] = set()
    fetched = 0
    js_fetched = 0

    def _add_api_endpoint(api_url: str, source: str) -> None:
        if urlparse(api_url).netloc != origin_netloc or not guard.is_authorized(api_url):
            return
        if api_url in seen_api_urls:
            return
        seen_api_urls.add(api_url)
        api_ep = Endpoint(url=api_url, method="GET", source=source)
        sitemap.api_endpoints.append(api_ep)
        if progress:
            progress("crawl", "endpoint", api_ep)

    while queue and fetched < max_pages:
        url, depth = queue.popleft()

        if urlparse(url).netloc != origin_netloc:
            continue
        if not guard.is_authorized(url):
            continue

        key = _dedupe_key(url)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        try:
            st, headers, body = http.get(url, headers=extra_headers) if extra_headers \
                else http.get(url)
        except Exception:  # noqa: BLE001
            continue
        fetched += 1

        if st == -1 or st >= 400:
            continue

        parsed_url = urlparse(url)
        params = tuple(sorted({k for k, _v in parse_qsl(parsed_url.query)}))
        if params:
            sitemap.params.setdefault(url, set()).update(params)

        endpoint = Endpoint(url=url, method="GET", params=params, source="link",
                            content_type=(headers or {}).get("content-type", ""))
        sitemap.endpoints.append(endpoint)
        if progress:
            progress("crawl", "endpoint", endpoint)

        # Fragments /api/.../rest/... repérés dans le corps (même hors HTML).
        for m in API_FRAGMENT_RE.finditer(body or ""):
            _add_api_endpoint(urljoin(url, m.group(1)), "api")

        if not _is_html(headers):
            continue  # ne pas suivre les liens depuis du contenu non-HTML

        parser = LinkFormParser()
        try:
            parser.feed(body or "")
        except Exception:  # noqa: BLE001
            continue

        for form_dict in parser.forms:
            action_url = urljoin(url, form_dict["action"] or url)
            if urlparse(action_url).netloc != origin_netloc or not guard.is_authorized(action_url):
                continue
            form = Form(action=action_url, method=form_dict["method"],
                       fields=tuple(form_dict["fields"]))
            sitemap.forms.append(form)
            if progress:
                progress("crawl", "form", form)

        # Bundles JS liés (<script src>) : on les récupère (bornés) et on en
        # extrait les fragments d'endpoints /api/.../rest/... (SPA : les
        # routes vivent souvent uniquement dans le JS, pas dans le HTML).
        for src in parser.scripts:
            if js_fetched >= MAX_JS_FILES:
                break
            script_url = urljoin(url, src)
            if urlparse(script_url).netloc != origin_netloc:
                continue
            if not guard.is_authorized(script_url):
                continue
            js_fetched += 1
            try:
                jst, _jheaders, jbody = (
                    http.get(script_url, headers=extra_headers) if extra_headers
                    else http.get(script_url))
            except Exception:  # noqa: BLE001
                continue
            if jst != 200 or not jbody:
                continue
            if len(jbody) > MAX_JS_BODY_CHARS:
                jbody = jbody[:MAX_JS_BODY_CHARS]
            for path in _extract_js_endpoint_paths(jbody):
                _add_api_endpoint(urljoin(origin, path), "api")

        if depth >= max_depth:
            continue

        for href in parser.links:
            next_url = urljoin(url, href)
            if urlparse(next_url).netloc != origin_netloc:
                continue
            if not guard.is_authorized(next_url):
                continue
            if _dedupe_key(next_url) in seen_keys:
                continue
            queue.append((next_url, depth + 1))

    # Base de repli : endpoints REST/API courants, ajoutés systématiquement
    # (source="seed") pour que les modules d'attaque aient toujours une
    # surface à tester même quand le crawl HTML/JS reste maigre (SPA).
    for path in COMMON_ENDPOINTS:
        _add_api_endpoint(urljoin(origin, path), "seed")

    return sitemap
