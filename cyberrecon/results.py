"""Offline unified results. Relationships are observed joins, never authorization."""
import hashlib
import ipaddress
from urllib.parse import urlsplit

STAGES = dict(assets="http", subdomains="subdomains", dns="dns", http="http",
              ports="nmap", services="nmap", technologies="technologies", urls="urls",
              apis="apis", javascript="urls", historical="urls", findings="http")


def _host(value):
    from .scope import host_of
    if not isinstance(value, str) or not value: return None
    try: return host_of(value)
    except ValueError: return None


def _url_host(value):
    if not isinstance(value, str): return None
    try: return _host(urlsplit(value).hostname)
    except ValueError: return None


def _known(value):
    return "Unknown" if value is None or value == "" else value


def unified_results(snapshot):
    from .storage import KINDS
    scan = snapshot["scan"]
    settings = scan.get("settings", {})
    host_ips = {}
    for row in snapshot.get("dns", []):
        if row.get("type") in {"A", "AAAA"} and _host(row.get("host")):
            try: address = str(ipaddress.ip_address(row.get("value")))
            except (ValueError, TypeError): continue
            host_ips.setdefault(_host(row["host"]), set()).add(address)
    records = []
    for kind in KINDS:
        for row in snapshot.get(kind, []):
            host = _host(row.get("host")) or _host(row.get("hostname")) or _url_host(row.get("url"))
            address = row.get("ip") or row.get("address")
            try:
                address = str(ipaddress.ip_address(address or host or ""))
            except (ValueError, TypeError):
                address = None
            stage = "nmap" if kind == "assets" and "os_matches" in row else STAGES.get(kind)
            stage_result = settings.get("stages", {}).get(stage, {})
            evidence = row.get("evidence") or row.get("evidence_sha256") or row.get("body_sha256") or row.get("sha256")
            variants = row.get("source_observations", [])
            confidences = sorted({str(v.get("confidence", "Unknown")) for v in variants} | {str(row.get("confidence") or "Unknown")})
            verification = row.get("verification_status") or row.get("resolution_status")
            if not verification:
                verification = "HTTP observed" if row.get("verified") is True or row.get("active_verified") is True else "Unknown"
            conflict_fields = []
            for field in ("state", "severity", "version", "method"):
                assertions = {str(v.get("attributes", {}).get(field)) for v in variants
                              if v.get("attributes", {}).get(field) not in (None, "", "Unknown")}
                if len(assertions) > 1: conflict_fields.append(field)
            if conflict_fields:
                verification = "multiple recorded assertions; review required"
            if kind == "findings" and not conflict_fields:
                verification = row.get("verification_status", "potential issue" if evidence else "inconclusive: evidence unavailable")
            limitations = ["Observed relationships do not establish ownership, exploitability or authorization."]
            if isinstance(row.get("url"), str) and "?" in row["url"]:
                limitations.append("Query values are redacted; parameter-value variants cannot be distinguished or verified by this URL.")
            if scan.get("status") != "complete":
                limitations.append("Scan is incomplete; absence of an observation is inconclusive.")
            if not evidence:
                limitations.append("No supporting response hash or original tool evidence attached.")
            if row.get("note"): limitations.append(row["note"])
            identifier = row.get("asset_id") or hashlib.sha256((kind + "\0" + row.get("key", "")).encode()).hexdigest()
            records.append({"result_id": hashlib.sha256((scan["id"] + "\0" + identifier).encode()).hexdigest(),
                "asset_id": identifier, "kind": kind, "scan_id": scan["id"], "target": scan.get("target", "Unknown"),
                "hostname": host or "Unknown", "ip_address": address or "Unknown", "ip_addresses": sorted(host_ips.get(host, set()) | ({address} if address else set())),
                "service": _known(row.get("service")), "technology": _known(row.get("technology")),
                "port": _known(row.get("port")), "protocol": _known(row.get("protocol")),
                "url": row.get("url") if isinstance(row.get("url"), str) and _url_host(row["url"]) else "Unknown", "method": _known(row.get("method")), "methods": row.get("methods", []),
                "query_variants": row.get("query_variants", []), "query_variant_id": row.get("query_variant_id"),
                "category": row.get("category") or row.get("classification") or kind,
                "title": row.get("title") or row.get("check") or row.get("technology") or row.get("service") or row.get("key", "Unknown"),
                "description": row.get("description") or row.get("note") or "Unknown",
                "severity": _known(row.get("severity")), "confidence": row.get("confidence") or "Unknown",
                "confidence_levels": confidences, "conflicting_fields": conflict_fields, "sources": row.get("sources") or ([row["source"]] if row.get("source") else []),
                "first_seen": row.get("first_seen") or row.get("collected_at") or "Unknown",
                "last_seen": row.get("last_seen") or row.get("collected_at") or "Unknown", "verification_status": verification,
                "evidence": evidence or "Unknown", "evidence_available": bool(evidence), "source_observations": variants,
                "coverage": {"scan_status": scan.get("status", "Unknown"), "stage": stage or "Unknown", "stage_status": stage_result.get("status", "Unknown")},
                "scan_profile": {k: settings[k] for k in ("nmap_profile", "ports", "udp", "max_hosts", "max_pages", "max_depth", "requests", "rate") if k in settings},
                "limitations": limitations, "next_steps": row.get("recommendation") or row.get("next_step") or "Review the recorded source evidence and coverage before drawing conclusions.",
                "original": row})
    # Offline projections reuse collected observations; they make no new probes.
    derived = []
    for result in records:
        original = result["original"]
        observations = []
        if result["kind"] == "http" and isinstance(original.get("tls"), dict):
            tls = original["tls"]
            observations.append(("tls", "TLS", "TLS connection: " + result["url"], tls,
                                 "verified connection" if tls.get("verified") is True else "Unknown",
                                 "Review certificate validity and SANs; protocol coverage is limited to the negotiated connection."))
        if result["kind"] == "assets":
            matches = original.get("os_matches")
            if isinstance(matches, list):
                for match in matches[:100]:
                    if isinstance(match, dict) and isinstance(match.get("name"), str):
                        observations.append(("os", "OS fingerprint", match["name"], match,
                                             "fingerprint; OS not confirmed",
                                             "Corroborate with authorized asset-owner inventory; Nmap accuracy is a tool estimate, not proof."))
        for index, (kind, category, title, facts, verification, next_steps) in enumerate(observations):
            derived.append({**result,
                "result_id": hashlib.sha256((result["result_id"] + kind + str(index)).encode()).hexdigest(),
                "kind": kind, "category": category, "title": title, "verification_status": verification,
                "confidence": "tool estimate" if kind == "os" else result["confidence"],
                "confidence_levels": ["tool estimate"] if kind == "os" else result["confidence_levels"],
                "evidence": {"observation_result_id": result["result_id"], "facts": facts, "source_evidence": result["evidence"]},
                "evidence_available": bool(facts), "next_steps": next_steps,
                "limitations": result["limitations"] + (["An OS fingerprint is not a confirmed operating system."] if kind == "os" else
                    ["No protocol-support enumeration was performed; chain availability depends on the runtime public API."]),
                "original": {"parent_observation": original, "facts": facts}})
    records.extend(derived)
    variants = []
    for result in records:
        if result["kind"] != "urls": continue
        for variant in result["query_variants"]:
            variants.append({**result, "result_id": hashlib.sha256((result["result_id"] + variant["query_variant_id"]).encode()).hexdigest(),
                "title": "Unverified query variant: " + result["url"], "query_variant_id": variant["query_variant_id"], "query_variants": [],
                "verification_status": variant["verification_status"], "confidence": "candidate", "confidence_levels": ["candidate"],
                "sources": variant["sources"], "evidence": "Unknown", "evidence_available": False,
                "source_observations": [], "original": {"redacted_url": result["url"], "query_variant": variant}})
    records.extend(variants)
    # Exact-host joins are correlations. Avoid quadratic all-pairs comparisons.
    groups, ip_counts = {}, {}
    for row in records:
        if row["hostname"] != "Unknown": groups.setdefault(row["hostname"], []).append(row["result_id"])
        for address in row["ip_addresses"]: ip_counts[address] = ip_counts.get(address, 0) + 1
    for row in records:
        row["ip_correlation_groups"] = row["ip_addresses"]
        row["related_ip_observation_count"] = sum(max(0, ip_counts[a] - 1) for a in row["ip_addresses"])
        row["correlation_group"] = row["hostname"]
        row["related_observation_count"] = max(0, len(groups.get(row["hostname"], [])) - 1)
    return records
