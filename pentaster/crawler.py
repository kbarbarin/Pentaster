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


class LinkFormParser(HTMLParser):
    """Extrait les liens `<a href>` et les formulaires `<form>` d'une page HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self._form: Optional[dict] = None
        self.forms: list[dict] = []

    def handle_starttag(self, tag, attrs):
        adict = dict(attrs)
        if tag == "a" and adict.get("href"):
            self.links.append(adict["href"])
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
    fetched = 0

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
            api_path = m.group(1)
            api_url = urljoin(url, api_path)
            if urlparse(api_url).netloc != origin_netloc or not guard.is_authorized(api_url):
                continue
            api_ep = Endpoint(url=api_url, method="GET", source="api")
            sitemap.api_endpoints.append(api_ep)

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

    return sitemap
