"""Offline HTTP-header observations; findings require contextual review."""
import re
from http.cookies import CookieError, SimpleCookie
import httpx

def header_findings(headers):
    headers = httpx.Headers(headers)
    rows = []
    def add(check, status, severity, evidence, recommendation):
        rows.append({"check": check, "status": status, "severity": severity,
                     "evidence": evidence, "recommendation": recommendation})
    hsts = headers.get("strict-transport-security", "")
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
    enabled = bool(match and int(match[1]) > 0)
    add("HSTS", "present" if enabled else "review", "info" if enabled else "review", hsts or "Missing",
        "Review a positive max-age policy after verifying HTTPS support." if not enabled else "Review policy duration and subdomain coverage.")
    csp = headers.get("content-security-policy", "")
    add("Content Security Policy", "present" if csp else "review", "info" if csp else "review", csp or "Missing",
        "Review an enforced CSP appropriate to the application's scripts and resources.")
    directives = {}
    duplicates = []
    for part in csp.split(";"):
        if part.strip():
            name, *sources = part.strip().split()
            name = name.lower()
            if name in directives:
                duplicates.append(name)
            directives.setdefault(name, sources)
    if duplicates:
        add("CSP duplicate directives", "review", "review", ", ".join(sorted(set(duplicates))),
            "Browsers use the first occurrence. Remove ambiguous duplicate directives.")
    if not csp and headers.get("content-security-policy-report-only"):
        add("CSP report-only mode", "observed", "review", "Report-only policy observed; no enforced CSP header",
            "Report-only policies monitor violations without enforcing them.")
    scripts = directives.get("script-src", directives.get("default-src", []))
    elements = directives.get("script-src-elem", scripts)
    broad = sorted(set(scripts + elements) & {"*", "http:", "https:", "'unsafe-inline'", "'unsafe-eval'"})
    if broad:
        add("CSP script sources", "review", "review", ", ".join(broad),
            "Review broad script permissions in context. Nonces/hashes and browser support affect inline-policy behavior; no XSS is confirmed.")
    frame = headers.get("x-frame-options", "").strip().lower()
    ancestors = directives.get("frame-ancestors")
    framed = bool(ancestors) and "*" not in ancestors if ancestors is not None else frame in {"deny", "sameorigin"}
    add("Framing protection", "present" if framed else "review", "info" if framed else "review",
        "CSP frame-ancestors present" if directives.get("frame-ancestors") else frame or "Missing",
        "Review frame-ancestors/X-Frame-Options according to embedding requirements.")
    nosniff = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
    add("MIME sniffing protection", "present" if nosniff else "review", "info" if nosniff else "review",
        headers.get("x-content-type-options", "Missing"), "Use nosniff with correct response Content-Type values.")
    for header in ("referrer-policy", "permissions-policy"):
        value = headers.get(header, "")
        add(header, "present" if value else "review", "info" if value else "review", value or "Missing",
            "Review policy values against application requirements; presence alone does not validate the policy.")
    if headers.get("server") or headers.get("x-powered-by"):
        add("Server disclosure", "observed", "info",
            "; ".join(f"{key}: {headers[key]}" for key in ("server", "x-powered-by") if key in headers),
            "Review unnecessary version disclosures; banners do not prove a vulnerability.")
    for index, raw in enumerate(headers.get_list("set-cookie"), 1):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            cookie.clear()
        if not cookie:
            add(f"Cookie {index}", "review", "review", "Cookie attributes could not be parsed; value omitted", "Review cookie configuration manually.")
        for name, morsel in cookie.items():
            flags = {"Secure": bool(morsel["secure"]), "HttpOnly": bool(morsel["httponly"]), "SameSite": morsel["samesite"] or "missing"}
            complete = flags["Secure"] and flags["HttpOnly"] and str(flags["SameSite"]).lower() in {"lax", "strict", "none"}
            add("Cookie: " + name, "present" if complete else "review", "info" if complete else "review", str(flags),
                "Review attributes by cookie purpose. JavaScript-accessible cookies may intentionally omit HttpOnly; values are not stored.")
            if name.startswith("__Host-") and (not flags["Secure"] or morsel["path"] != "/" or morsel["domain"]):
                add("Cookie prefix: " + name, "review", "review", "__Host- requirements not satisfied",
                    "Use Secure, Path=/ and no Domain for __Host- cookies; cookie value omitted.")
            elif name.startswith("__Secure-") and not flags["Secure"]:
                add("Cookie prefix: " + name, "review", "review", "__Secure- without Secure", "Set Secure for __Secure- cookies.")
    return rows
