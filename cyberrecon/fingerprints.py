"""Project-owned MIT fingerprint rules. Update independently of orchestration.

Rules identify public response indicators, not private architecture. Cookie
values and matched response snippets are never retained. No Wappalyzer dataset
is bundled or claimed. Versions require a product-specific version pattern.
"""
import re
from .models import utcnow

RULESET_VERSION = "2026-10-10.1"
# name, category, evidence source, pattern, optional version capture
RULES = (
    ("nginx", "Web server", "server", r"\bnginx(?:/(\d+(?:\.\d+){0,3}))?"),
    ("Apache", "Web server", "server", r"\bApache(?:/(\d+(?:\.\d+){0,3}))?"),
    ("Caddy", "Web server", "server", r"\bCaddy(?:/(\d+(?:\.\d+){0,3}))?"),
    ("Microsoft IIS", "Web server", "server", r"\bMicrosoft-IIS(?:/(\d+(?:\.\d+){0,3}))?"),
    ("PHP", "Backend runtime", "x-powered-by", r"\bPHP(?:/(\d+(?:\.\d+){0,3}))?"),
    ("ASP.NET", "Backend framework", "x-powered-by", r"\bASP\.NET\b"),
    ("Express", "Backend framework", "x-powered-by", r"\bExpress\b"),
    ("WordPress", "CMS", "html", r"(?:wp-content/|wp-includes/|generator[^>]{0,100}WordPress(?:\s+(\d+(?:\.\d+){0,3}))?)"),
    ("Drupal", "CMS", "html", r"(?:Drupal\.settings|drupalSettings|generator[^>]{0,100}Drupal(?:\s+(\d+(?:\.\d+){0,3}))?)"),
    ("React", "Frontend framework", "html", r"(?:data-reactroot|react-dom(?:[./_-](\d+(?:\.\d+){0,3}))?|react(?:[./_-](\d+(?:\.\d+){0,3}))?\.?(?:min\.)?js)"),
    ("Vue", "Frontend framework", "html", r"(?:data-v-[0-9a-f]{6,}|vue(?:[./_-](\d+(?:\.\d+){0,3}))?(?:\.min)?\.js)"),
    ("Angular", "Frontend framework", "html", r"(?:ng-version=[\"'](\d+(?:\.\d+){0,3})|angular(?:[./_-](\d+(?:\.\d+){0,3}))?(?:\.min)?\.js)"),
    ("Next.js", "Frontend framework", "html", r"(?:/_next/static/|__NEXT_DATA__)"),
    ("Nuxt", "Frontend framework", "html", r"(?:/_nuxt/|__NUXT__)"),
    ("jQuery", "JavaScript library", "html", r"jquery(?:[./_-]([\d]+(?:\.[\d]+){1,3}))?(?:\.min)?\.js"),
    ("Bootstrap", "CSS framework", "html", r"bootstrap(?:[./_-]([\d]+(?:\.[\d]+){1,3}))?(?:\.min)?\.(?:css|js)"),
    ("Webpack", "Build tool", "javascript", r"(?:webpackChunk|webpackJsonp|__webpack_require__)"),
    ("Vite", "Build tool", "html", r"(?:/@vite/client|vite/modulepreload-polyfill)"),
    ("Google Analytics", "Analytics", "html", r"(?:google-analytics\.com/|googletagmanager\.com/gtag/js)"),
    ("Google Tag Manager", "Tag management", "html", r"googletagmanager\.com/gtm\.js"),
    ("Cloudflare", "CDN / WAF indicator", "server", r"\bcloudflare\b"),
    ("Cloudflare", "CDN / WAF indicator", "cf-ray", r".+"),
    ("CloudFront", "CDN indicator", "via", r"\bCloudFront\b"),
    ("Django", "Backend framework", "cookie_names", r"(?:^|\s)csrftoken(?:\s|$)"),
    ("Laravel", "Backend framework", "cookie_names", r"(?:^|\s)laravel_session(?:\s|$)"),
    ("PHP", "Backend runtime", "cookie_names", r"(?:^|\s)PHPSESSID(?:\s|$)"),
    ("Java servlet", "Backend runtime", "cookie_names", r"(?:^|\s)JSESSIONID(?:\s|$)"),
    ("ASP.NET", "Backend framework", "cookie_names", r"ASP\.NET_SessionId"),
    ("Swagger UI", "API documentation", "html", r"(?:SwaggerUIBundle|swagger-ui(?:\.min)?\.(?:js|css))"),
)


def detect(response, body, cookies=()):
    headers = response.get("headers", {})
    content_type = headers.get("content-type", "").lower()
    # Response text is inspected transiently; only rule IDs and hashes persist.
    values = {**headers, "html": body if "html" in content_type else "",
              "javascript": body if "javascript" in content_type or response["url"].split("?", 1)[0].endswith(".js") else "",
              "cookie_names": " ".join(c.split("=", 1)[0].strip() for c in cookies if "=" in c)}
    detections = {}
    for index, (name, category, source, pattern) in enumerate(RULES):
        matches = list(re.finditer(pattern, values.get(source, "")[:512 * 1024], re.I))[:100]
        if not matches:
            continue
        versions = sorted({v for match in matches for v in match.groups() if v})
        version = versions[0] if len(versions) == 1 else "Unknown"
        evidence = {"rule": index, "source": source, "url": response["url"], "body_sha256": response.get("body_sha256"),
                    "observed_versions": versions, "note": "Observable indicator; headers, cookie names and public assets may be spoofed."}
        row = detections.setdefault(name, {"technology": name, "product": name, "category": category, "version": version,
                    "classification": "Likely", "confidence": "indicator", "verified_version": False,
                    "url": response["url"], "detected_at": utcnow(), "ruleset": RULESET_VERSION, "evidence": []})
        row["evidence"].append(evidence)
        observed_versions = sorted({v for e in row["evidence"] for v in e.get("observed_versions", [])})
        row["observed_versions"] = observed_versions
        row["version"] = observed_versions[0] if len(observed_versions) == 1 else "Unknown"
        row["version_status"] = "conflicting public indicators" if len(observed_versions) > 1 else "public indicator, installed version unverified" if observed_versions else "Unknown"
        signal_sources = sorted({e["source"] for e in row["evidence"]})
        row["signal_sources"] = signal_sources
        row["confidence"] = "multiple indicators" if len(signal_sources) > 1 else "indicator"
        row["verification_status"] = "public indicators observed; product not independently verified"
    asset = ("HTML", "Confirmed") if "html" in content_type and re.search(r"<(?:html|title|body|script|a)(?:\s|>)", body, re.I) else ("CSS", "Likely") if "text/css" in content_type else ("JavaScript", "Likely") if "javascript" in content_type else None
    if asset:
        name, classification = asset
        detections[name] = {"technology": name, "product": name, "category": "Frontend asset", "version": "Unknown",
                            "classification": classification, "confidence": "response format", "verified_version": False,
                            "url": response["url"], "detected_at": utcnow(), "ruleset": RULESET_VERSION,
                            "evidence": [{"source": "content-type and public response format", "body_sha256": response.get("body_sha256")} ]}
    return list(detections.values())
