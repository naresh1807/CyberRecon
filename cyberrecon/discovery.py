"""Bounded public route extraction. Never submit forms or retain source content."""
import json
import re
from urllib.parse import urlsplit, unquote
from defusedxml import ElementTree as ET
from .network import clean_url


def safe_navigation(url):
    path = unquote(urlsplit(url).path).lower()
    # Avoid known state-changing navigation even when implemented as GET.
    filename = path.rsplit("/", 1)[-1]
    if filename.startswith(".env") or filename in {"secrets.json", "credentials.json", "id_rsa", "id_ed25519"} or filename.endswith((".key", ".pem", ".p12", ".pfx")):
        return False
    return not re.search(r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|reset|unsubscribe)(?:/|\.|$)", path)


def candidates(response, body):
    """Return (public URL candidate, provenance); bounded, no source-map contents."""
    path = urlsplit(response["url"]).path.lower()
    kind = response.get("headers", {}).get("content-type", "").lower()
    found = []
    if path.endswith("robots.txt"):
        for line in body.splitlines()[:5000]:
            key, _, value = line.partition(":")
            if key.strip().lower() in {"allow", "disallow", "sitemap"} and value.strip() and "*" not in value:
                found.append((value.strip().split("#", 1)[0].strip(), "robots.txt"))
    if "xml" in kind or path.endswith(".xml"):
        try:
            root = ET.fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
            if root.tag.rsplit("}", 1)[-1] in {"urlset", "sitemapindex"}:
                found.extend((node.text.strip(), "sitemap") for node in root.iter()
                             if node.tag.rsplit("}", 1)[-1] == "loc" and node.text and node.text.strip())
        except (ValueError, ET.ParseError):
            pass
    if "javascript" in kind or path.endswith(".js"):
        found.extend((m, "JavaScript route") for m in re.findall(r'''["']((?:https?://|/)[^"'\s<>]{1,500})["']''', body)[:200])
        found.extend((m, "JavaScript source map") for m in re.findall(r"sourceMappingURL=([^\s*]+)", body)[:20] if not m.startswith("data:"))
    if "json" in kind or path.endswith(".map"):
        try:
            data = json.loads(body)
        except (ValueError, RecursionError):
            data = None
        # Only URL-looking strings from known public route fields. Never store
        # sourceContent, secrets, configuration values or arbitrary strings.
        remaining = [data]
        visited = 0
        while remaining and visited < 1000:
            value = remaining.pop(); visited += 1
            if isinstance(value, dict):
                for key, entry in list(value.items())[:100]:
                    if key.lower() in {"url", "href", "endpoint", "apiurl", "baseurl", "route", "path"} and isinstance(entry, str) and entry.startswith(("/", "http://", "https://")):
                        found.append((entry, "public JSON route"))
                    elif isinstance(entry, (dict, list)) and key.lower() not in {"sourcescontent", "secrets", "credentials"}:
                        remaining.append(entry)
            elif isinstance(value, list):
                remaining.extend(value[:100])
    return list(dict.fromkeys(found))[:500]


def normalize_candidates(response, body, scope):
    result = []
    for value, source in candidates(response, body):
        try:
            url = clean_url(value, response["url"])
            if scope.allows(url):
                result.append((url, source))
        except ValueError:
            continue
    return list(dict.fromkeys(result))
