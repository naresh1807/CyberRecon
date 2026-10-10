"""Passive bounded API/documentation extraction from already fetched responses."""
import json
import re
from urllib.parse import parse_qsl, urlsplit

from .network import clean_url


def extract(response, body, scope, registry=None):
    url = response["url"]
    path = urlsplit(url).path
    records = []
    content_type = response.get("headers", {}).get("content-type", "Unknown")
    if "javascript" in content_type.lower() or path.endswith(".js"):
        for match in re.finditer(r'(?:(?:fetch|axios\.(get|post|put|patch|delete|head|options))\s*\(\s*)["\']((?:https?://|/)[^"\'\s<>]{1,500})["\']', body):
            if len(records) >= 200:
                break
            try:
                endpoint = clean_url(match.group(2), url)
                scope.require(endpoint)
            except ValueError:
                continue
            method = match.group(1).upper() if match.group(1) else "Unknown"
            if method == "Unknown":
                tail = body[match.end():match.end() + 300].split(");", 1)[0]
                explicit = re.search(r'^\s*,\s*\{[^}]{0,250}?\bmethod\s*:\s*["\'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["\']', tail, re.I)
                method = explicit.group(1).upper() if explicit else "Unknown"
            variant = registry.remember(match.group(2), url, "JavaScript API reference") if registry is not None else None
            records.append({"url": endpoint, "query_variant_id": variant, "method": method, "methods": [] if method == "Unknown" else [method], "parameter_names": sorted({key for key, _ in parse_qsl(urlsplit(match.group(2)).query, keep_blank_values=True)}),
                            "classification": "JavaScript candidate", "verification_status": "unverified", "authentication": "Unknown",
                            "source_url": url, "confidence": "candidate", "note": "Static reference only; operation was not sent."})
    if re.search(r"/(api|graphql|swagger|openapi)(/|\.|$)", path, re.I) or response["status_code"] in {401, 403}:
        challenge = response["headers"].get("www-authenticate", "").split(" ", 1)[0]
        records.append({"url": url, "classification": "observed HTTP surface", "status_code": response["status_code"], "method": "GET", "methods": ["GET"], "content_type": content_type, "verification_status": "HTTP observed", "authentication": "challenge observed" if response["status_code"] == 401 and response["headers"].get("www-authenticate") else "Unknown",
                        "parameter_names": sorted({key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}),
                        "challenge_scheme": challenge if challenge.lower() in {"basic", "bearer", "digest", "negotiate"} else "unknown",
                        "note": "Authentication behavior and business impact have not been tested."})
    if "json" not in response["headers"].get("content-type", "").lower() or response["truncated"]:
        return inventory(records, response)
    try:
        data = json.loads(body)
    except ValueError:
        return inventory(records, response)
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict) or not (data.get("openapi") or data.get("swagger")):
        return inventory(records, response)
    base = url
    servers = data.get("servers", [])
    selected_server = False
    for server in (servers if isinstance(servers, list) else [])[:10]:
        try:
            candidate = clean_url(server["url"], url)
            if scope.allows(candidate):
                base = candidate.rstrip("/") + "/"
                selected_server = True
                break
        except (ValueError, KeyError, TypeError):
            continue
    if isinstance(servers, list) and servers and not selected_server:
        records.append({"url": url, "classification": "API document", "parameter_names": [], "verification_status": "document observed, operations skipped", "coverage_warning": "No authorized OpenAPI server in the bounded server list; operations not inventoried."})
        return inventory(records, response)
    if data.get("swagger") and isinstance(data.get("basePath", "/"), str):
        try:
            parts = urlsplit(url)
            host = data.get("host", parts.netloc)
            if not isinstance(host, str):
                raise ValueError("Invalid Swagger host")
            candidate = clean_url(parts.scheme + "://" + host + data.get("basePath", "/").rstrip("/") + "/")
            if scope.allows(candidate):
                base = candidate
            else:
                records.append({"url": url, "classification": "API document", "parameter_names": [], "coverage_warning": "Swagger destination is outside authorized scope; operations skipped."})
                return inventory(records, response)
        except ValueError:
            pass
    for path, operations in list(data["paths"].items())[:500]:
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(operations, dict):
            continue
        try:
            endpoint = clean_url(base.rstrip("/") + path if base != url else path, base)
            scope.require(endpoint)
        except ValueError:
            continue
        methods = sorted(method.upper() for method in operations if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"} and isinstance(operations[method], dict))
        names = set()
        for method in methods:
            operation = operations.get(method.lower(), {})
            if not isinstance(operation, dict):
                continue
            parameters = operation.get("parameters", [])
            inherited = operations.get("parameters", [])
            parameters = (parameters if isinstance(parameters, list) else []) + (inherited if isinstance(inherited, list) else [])
            for parameter in parameters[:100]:
                if isinstance(parameter, dict) and isinstance(parameter.get("name"), str):
                    names.add(parameter["name"][:200])
        records.append({"url": endpoint, "classification": "documented endpoint (unverified)", "methods": methods, "method": methods[0] if len(methods) == 1 else "Multiple documented",
                        "operation_metadata": {method: {"operation_id": operations[method.lower()].get("operationId") if isinstance(operations[method.lower()].get("operationId"), str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", operations[method.lower()]["operationId"]) else "Unknown",
                                   "authentication": "declared required" if operations[method.lower()].get("security", data.get("security")) else "declared none" if "security" in operations[method.lower()] or "security" in data else "Unknown"}
                                               for method in methods if isinstance(operations.get(method.lower()), dict)},
                        "authentication": "See operation declarations; not tested", "verification_status": "documented, unverified", "confidence": "documented",
                        "parameter_names": sorted(names), "documentation_url": url,
                        "spec_version": str(data.get("openapi") or data.get("swagger"))[:30],
                        "declares_security": any(bool(operations[method.lower()].get("security", data.get("security")))
                                                 for method in methods if isinstance(operations.get(method.lower()), dict)),
                        "note": "Documented methods and schemas do not establish reachable or vulnerable endpoints."})
    if len(data["paths"]) > 500:
        for row in records:
            row["coverage_warning"] = "OpenAPI path budget reached (500); operations inventory is incomplete."
    return inventory(records, response)


def inventory(records, response=None):
    """Normalize and deduplicate without replacing method-specific evidence."""
    from .models import utcnow
    found = {}
    for row in records:
        if response is not None:
            row["evidence"] = {"source_url": response["url"], "response_sha256": response.get("body_sha256", "Unknown"), "status_code": response["status_code"]}
        row["verified"] = row["classification"] == "observed HTTP surface"
        parts = urlsplit(row["url"])
        row.update(host=parts.hostname, path=parts.path, base_url=parts.scheme + "://" + parts.netloc,
                   discovered_at=utcnow())
        row.setdefault("content_type", "Unknown")
        row.setdefault("confidence", "observed")
        found[(row["url"], tuple(row.get("methods", [])), row["classification"], row.get("query_variant_id"))] = row
    return list(found.values())
