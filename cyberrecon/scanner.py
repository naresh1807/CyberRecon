"""Bounded, scope checked native reconnaissance workflow."""
import hashlib
import ipaddress
import json
import re
import ssl
import threading
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit
from pathlib import Path

import dns.reversename
import dns.resolver
import httpx

from . import engines
from .errors import operation_error
from .network import ScopedHTTP, clean_url
from .normalization import dns_attributes, dns_key
from .scope import host_of


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.title = ""
        self.in_title = False
        self.generator = ""

    def handle_starttag(self, tag, attrs):
        self.in_title = self.in_title or tag == "title"
        attributes = dict(attrs)
        if tag == "meta" and attributes.get("name", "").lower() == "generator":
            self.generator = (attributes.get("content") or "")[:256]
        for name, value in attrs:
            if value and (name == "href" or tag == "script" and name == "src" or tag == "form" and name == "action"):
                self.links.append((value, "form:" + attributes.get("method", "GET").upper() if tag == "form" else tag))

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:512]


def scan(repository, project, target, passive=None, crawl=False, history=None,
         ports=None, udp=False, transport=None, cancel=None, lifecycle=False, go_dns=False, words=None, cve=False, progress=None, ca_bundle=None, nmap_unprivileged=False, nmap_diagnostic=None, nmap_profile="service", nmap_timing=3, nmap_timeout=180, nmap_host_timeout=120, nmap_rate=2, nmap_os=False, nmap_scripts=False, max_hosts=30, max_pages=30, max_depth=2, max_requests=100, rate=2, dns_words=None, check_wildcard=False):
    from .models import ValidationError
    from .stages import Stages
    from .discovery import normalize_candidates, safe_navigation
    for value, upper, name in ((max_hosts, 5000, "hosts"), (max_pages, 500, "pages"), (max_depth, 5, "depth"), (max_requests, 500, "requests"), (rate, 10, "rate")):
        if type(value) is not int or not 1 <= value <= upper:
            raise ValidationError("Invalid " + name + " limit.")
    cancel = cancel or threading.Event()
    words = list(dict.fromkeys(word.strip().lstrip("/") for word in words or [] if word.strip()))
    if len(words) > 200 or any(not re.fullmatch(r"[a-zA-Z0-9_./-]{1,100}", word) or ".." in word for word in words):
        raise ValueError("Content discovery accepts at most 200 relative paths without traversal or parameters.")
    from .subdomains import PROVIDERS
    selected_providers = passive.split(",") if isinstance(passive, str) else list(passive or [])
    if any(provider not in PROVIDERS for provider in selected_providers):
        raise ValidationError("Unsupported passive provider.")
    if dns_words or check_wildcard:
        dns_root = repository.scope(project).require(target, passive=True)
        try:
            ipaddress.ip_address(dns_root)
        except ValueError:
            pass
        else:
            raise ValidationError("Active DNS enumeration and wildcard controls require a domain.")
    if dns_words:
        from .dns_inventory import wordlist_hosts
        wordlist_hosts(repository.scope(project).require(target, passive=True), dns_words, repository.scope(project))
    if type(nmap_timeout) is not int or not 10 <= nmap_timeout <= 600 or type(nmap_rate) is not int or not 1 <= nmap_rate <= 1000:
        raise ValidationError("Invalid Nmap resource limits.")
    if udp and nmap_profile == "full":
        raise ValidationError("Full profile is TCP only; choose bounded UDP ports separately.")
    if udp and ports is None:
        raise ValueError("UDP requires an explicit --ports selection.")
    if ports is not None:
        root = repository.scope(project).require(target)
        engines.scan_arguments(root, ports, profile=nmap_profile, timing=nmap_timing, host_timeout=nmap_host_timeout, os_detection=nmap_os, default_scripts=nmap_scripts)
    verification, ca_digest = True, None
    if ca_bundle:
        path = Path(ca_bundle)
        if not path.is_file():
            raise ValueError("CA bundle must be a regular PEM certificate file.")
        with path.open("rb") as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("CA bundle exceeds 2 MiB.")
        verification = ssl.create_default_context()
        verification.load_verify_locations(cadata=data.decode("ascii"))
        ca_digest = hashlib.sha256(data).hexdigest()
    settings = dict(passive=passive, crawl=crawl, history=history, ports=ports, udp=udp, nmap_unprivileged=nmap_unprivileged,
                    nmap_profile=nmap_profile, nmap_timing=nmap_timing, nmap_timeout=nmap_timeout, nmap_host_timeout=nmap_host_timeout, nmap_rate=nmap_rate, nmap_os=nmap_os, nmap_scripts=nmap_scripts,
                    max_pages=max_pages, max_hosts=max_hosts, max_depth=max_depth, requests=max_requests, rate=rate, dns_wordlist_enabled=bool(dns_words), check_wildcard=check_wildcard, lifecycle=lifecycle, go_dns=go_dns, content_paths=words, cve=cve, ca_bundle_sha256=ca_digest)
    identifier = repository.start_scan(project, target, settings)
    warnings = []
    verified_urls = set()
    progress = progress or (lambda message: None)
    progress("Scan job: " + identifier)
    stages = Stages(repository, identifier, progress)
    stages.start("validation"); stages.finish("validation")
    scope = lambda: repository.scope(project)
    save = lambda kind, key, value, source, **kw: repository.save(identifier, kind, key, value, source, **kw)
    def warn(message, exc=None, code_override=None):
        code, detail = operation_error(exc) if exc is not None else ("coverage_warning", message)
        message = message + ": " + detail if exc is not None else message
        code = code_override or code
        warnings.append(message)
        save("errors", str(len(warnings)), {"code": code, "message": message}, "scan workflow", confidence="diagnostic")

    def edge(left, right, relation):
        save("relationships", left + "|" + relation + "|" + right,
             dict(from_node=left, to_node=right, relation=relation), "correlation")
    def host_node(host):
        try:
            ipaddress.ip_address(host)
            return "ip:" + host
        except ValueError:
            return "host:" + host
    try:
        root = scope().require(target, passive=True)
        hosts = {root} if scope().allows(root) else set()
        if passive and not cancel.is_set():
            from .subdomains import enumerate_hosts
            stages.start("subdomains")
            names, outcomes = enumerate_hosts(passive, root, scope(), cancel)
            for outcome in outcomes:
                if outcome["status"] != "complete":
                    warn("Passive provider " + outcome["provider"] + ": " + outcome["status"], code_override=outcome.get("code"))
            for row in names:
                hosts.add(row["host"])
                for provider in row["providers"]:
                    save("subdomains", row["host"], row, provider, historical=provider == "ct")
                edge("domain:" + root, "host:" + row["host"], "contains")
            stages.finish("subdomains", "failed" if outcomes and all(o["status"] == "failed" for o in outcomes) else "partial" if any(o["status"] != "complete" for o in outcomes) else "complete",
                          providers=outcomes, discovered=len(names), coverage="Configured sources only; not exhaustive.")
        active_word_hosts = set()
        if dns_words:
            from .dns_inventory import wordlist_hosts
            active_word_hosts = set(wordlist_hosts(root, dns_words, scope()))
            hosts.update(active_word_hosts)
            if not passive:
                stages.start("subdomains", method="opt-in authorized DNS wordlist")
        selected_hosts = (([root] if root in hosts else []) + sorted(hosts - {root}))[:max_hosts]
        if len(hosts) > max_hosts:
            warn("Host budget reached; unprocessed discovered hosts remain in the inventory.")
        http = ScopedHTTP(scope, transport=transport, cancel=cancel, verify=verification, max_requests=max_requests, rate=rate)
        if transport is None and not cancel.is_set():
            from .dns_inventory import resolve_host, resolve_ip, wildcard_control
            from concurrent.futures import ThreadPoolExecutor
            stages.start("dns", requested=len(hosts), budget=max_hosts, concurrency=2)
            dns_hosts = selected_hosts
            control = {"status": "not checked", "addresses": []}
            failed_dns = 0
            if check_wildcard:
                try:
                    control = wildcard_control(root, scope, cancel)
                except Exception as exc:
                    warn("Wildcard control unavailable", exc)
                    control = {"status": "failed", "addresses": [], "code": operation_error(exc)[0]}
                    failed_dns = 1
            # DNS work is concurrent; storage and progress remain serialized.
            with ThreadPoolExecutor(max_workers=2) as pool:
                def resolve_inventory(h):
                    try:
                        ipaddress.ip_address(h)
                    except ValueError:
                        return resolve_host(h, scope, cancel)
                    return resolve_ip(h, scope, cancel)
                futures = [(h, pool.submit(resolve_inventory, h)) for h in dns_hosts]
                for index, (h, future) in enumerate(futures, 1):
                    try:
                        records, summary = future.result()
                        progress(f"DNS {index}/{len(dns_hosts)}: {h}")
                        summary["wildcard_status"] = control["status"]
                        summary["possible_wildcard_response"] = bool(set(summary["addresses"]) & set(control["addresses"]))
                        save("dns", h + ":resolution", summary, "DNS resolver")
                        save("assets", h, {"host": h, "dns_resolution": summary}, "DNS resolver")
                        if h in active_word_hosts and summary["addresses"]:
                            save("subdomains", h, {"host": h, "verified_current": True, "possible_wildcard_response": summary["possible_wildcard_response"]}, "authorized DNS wordlist")
                        for row in records:
                            save("dns", dns_key(h, row["type"], row.get("value", row.get("sha256"))), row, "DNS resolver")
                            if row["type"] in {"A", "AAAA"}:
                                edge("host:" + h, "ip:" + row["value"], "resolves_to")
                        if summary["resolution_status"] == "partial":
                            failed_dns += 1; warn("DNS partial resolution: " + h)
                    except Exception as exc:
                        failed_dns += 1; warn("DNS " + h, exc)
            stages.finish("dns", "partial" if failed_dns or len(hosts) > max_hosts or cancel.is_set() else "complete",
                          processed=len(dns_hosts), failures=failed_dns, wildcard=control)
            if active_word_hosts:
                previous = stages.rows["subdomains"]["status"]
                stages.finish("subdomains", "partial" if failed_dns or len(hosts) > max_hosts or previous in {"partial", "failed"} else "complete",
                              active_wordlist={"candidates": len(active_word_hosts), "note": "Only resolved names recorded; wildcard answers remain candidates."})
        else:
            stages.finish("dns", "skipped", reason="Injected HTTP transport; DNS not executed" if transport else "cancelled")
        if go_dns and hosts and not cancel.is_set():
            from .go_worker import resolve_hosts
            progress("Optional Go A/AAAA observations (maximum 30 hosts)")
            repository.update_scan_settings(identifier, {"go_dns_coverage": {"maximum_hosts": 30, "requested_hosts": len(hosts), "note": "Supplemental worker; Python inventories all selected hosts within the configured host budget."}})
            try:
                go_results = resolve_hosts(selected_hosts[:30], scope(), cancel)
            except Exception as exc:
                warn("Go DNS unavailable; using the Python resolver", exc)
                go_results = []
            for row in go_results:
                scope().require(row["host"])
                if row.get("error"):
                    warn("Go DNS " + row["host"] + ": " + row["error"])
                for value in row["addresses"]:
                    family = "A" if ipaddress.ip_address(value).version == 4 else "AAAA"
                    save("dns", dns_key(row["host"], family, value),
                         {"host": row["host"], "type": family, "value": value}, "Go DNS worker")
                    edge("host:" + row["host"], "ip:" + value, "resolves_to")
        web_warning_start = len(warnings)
        for name in ("http", "technologies", "urls", "apis"):
            stages.start(name)
        for host in selected_hosts:
            if cancel.is_set():
                break
            scope().require(host)
            progress("Processing host: " + host)
            save("assets", host, {"host": host, "active_verified": False}, "scope")
            try:
                ipaddress.ip_address(host)
                literal_ip = True
            except ValueError:
                literal_ip = False
            initial = clean_url(target) if "://" in target and host == root else "https://" + (f"[{host}]" if ":" in host else host) + "/"
            queue, seen = deque([(initial, 0, "target")]), set()
            if crawl:
                queue.extend((clean_url(path, initial), 1, "public discovery document") for path in ("/robots.txt", "/sitemap.xml"))
            baseline = None
            if words and not cancel.is_set():
                try:
                    control = clean_url("cyberrecon-missing-" + identifier, initial)
                    control_response = http.fetch(control)
                    baseline = {"url": control_response["url"], "status_code": control_response["status_code"],
                                "bytes_read": control_response["bytes_read"], "body_sha256": control_response["body_sha256"]}
                    save("http", control_response["url"], {**baseline, "purpose": "content discovery negative control"}, "scoped HTTP")
                except Exception as exc:
                    warn("Content discovery calibration unavailable", exc)
            for word in words:
                queue.append((clean_url(word, initial.rstrip("/") + "/"), 1, "wordlist"))
            while queue and len(seen) < max_pages and not cancel.is_set():
                url, depth, discovery_source = queue.popleft()
                if url in seen or not safe_navigation(url):
                    continue
                seen.add(url)
                progress(f"HTTP {http.count}/{http.maximum}: {url}")
                try:
                    result = http.fetch(url)
                    body = result.pop("text")
                    if result["truncated"]:
                        warn("HTTP body truncated; discovery coverage incomplete: " + result["url"])
                    cookies = result.pop("cookie_headers")
                    save("http", result["url"], result, "scoped HTTP")
                    from .api import extract
                    extracted_apis = extract(result, body, scope())
                    for api in extracted_apis:
                        if api.get("coverage_warning"):
                            warn(api["coverage_warning"])
                        save("apis", api["url"] + ":" + ",".join(api.get("methods", [])), api, "HTTP/API document extraction")
                        edge("url:" + result["url"], "api:" + api["url"], "describes")
                        for name in api.get("parameter_names", []):
                            edge("api:" + api["url"], "parameter:" + api["url"] + ":" + name, "documents_parameter")
                    save("assets", host, {"host": host, "active_verified": True}, "scoped HTTP")
                    verified_urls.add(result["url"])
                    content_notes = {}
                    if discovery_source == "wordlist":
                        content_notes = {"negative_control": baseline, "requires_validation": True,
                                         "possible_wildcard_response": bool(baseline and baseline["status_code"] == result["status_code"] and
                                                                           baseline["body_sha256"] == result["body_sha256"]),
                                         "note": "Compare the negative control and application behavior; response success is not proof of exposure."}
                    save("urls", result["url"], {"url": result["url"], "status_code": result["status_code"], "content_type": result["headers"].get("content-type", "Unknown"), "redirect_chain": result["redirect_chain"], "discovered_by": discovery_source, "verified": True, "verification_status": "HTTP observed", **content_notes}, discovery_source)
                    actual_host = host_of(result["url"])
                    if actual_host != host:
                        save("assets", actual_host, {"host": actual_host, "active_verified": True}, "scoped HTTP")
                    edge(host_node(actual_host), "url:" + result["url"], "serves")
                    for redirect in result["redirect_chain"]:
                        save("urls", redirect["from"], {"url": redirect["from"], "status_code": redirect["status"], "redirect_destination": redirect["to"], "verified": True, "verification_status": "redirect observed", "discovered_by": discovery_source}, "scoped redirect")
                        edge("url:" + redirect["from"], "url:" + redirect["to"], "redirects_to")
                    for key, _ in parse_qsl(urlsplit(result["url"]).query, keep_blank_values=True):
                        edge("url:" + result["url"], "parameter:" + result["url"] + ":" + key, "accepts_parameter")
                    from .fingerprints import detect
                    for detection in detect(result, body, cookies):
                        save("technologies", result["url"] + ":fingerprint:" + detection["technology"], detection,
                             "public response fingerprint", confidence=detection["confidence"])
                    if "html" in result["headers"].get("content-type", "").lower():
                        if 200 <= result["status_code"] < 300:
                            from .web_assessment import header_findings
                            headers = httpx.Headers(list(result["headers"].items()) + [("set-cookie", value) for value in cookies])
                            for finding in header_findings(headers):
                                if finding["status"] == "review":
                                    save("findings", result["url"] + ":" + finding["check"],
                                         {**finding, "url": result["url"], "classification": "configuration-review",
                                          "confirmed_vulnerability": False, "evidence_sha256": result["body_sha256"]},
                                         "HTTP configuration review", confidence="requires-validation")
                        parser = Links()
                        parser.feed(body)
                        save("http", result["url"], {**result, "title": parser.title.strip(),
                             "generator": parser.generator}, "scoped HTTP")
                        if parser.generator:
                            save("technologies", result["url"] + ":generator", {"banner": parser.generator, "category": "CMS indicator", "classification": "Unknown", "version": "Unknown", "url": result["url"], "evidence_sha256": result["body_sha256"], "note": "Self-reported generator text; not independent product verification."}, "HTML generator metadata", confidence="self-reported")
                        candidates = parser.links
                    elif "javascript" in result["headers"].get("content-type", "").lower() or urlsplit(url).path.lower().endswith(".js"):
                        maps = []
                        for match in re.findall(r"sourceMappingURL=([^\s*]+)", body)[:20]:
                            try:
                                source_map = clean_url(match, result["url"])
                                if scope().allows(source_map):
                                    maps.append(source_map)
                                    save("urls", source_map, {"url": source_map, "verified": False}, "JavaScript source map comment")
                            except ValueError:
                                continue
                        potential = [match.start() for match in re.finditer(r'''(?i)(?:api[_-]?key|secret|access[_-]?token)\s*[:=]\s*["'][^"']{16,}["']''', body)][:100]
                        save("javascript", result["url"], {"url": result["url"], "sha256": result["body_sha256"],
                             "truncated": result["truncated"], "source_map_candidates": maps,
                             "potential_sensitive_assignments": len(potential), "values_retained": False}, "scoped HTTP")
                        edge("url:" + result["url"], "content-sha256:" + result["body_sha256"], "has_content")
                        if potential:
                            save("findings", result["url"] + ":sensitive-assignment-candidates", {"url": result["url"],
                                 "classification": "review", "confirmed_vulnerability": False,
                                 "count": len(potential), "character_offsets": potential, "evidence_sha256": result["body_sha256"],
                                 "note": "Pattern matches may be public keys or placeholders. Values are omitted; verify ownership and intended exposure."},
                                 "JavaScript static patterns", confidence="requires-validation")
                        candidates = []
                    else:
                        candidates = []
                    if urlsplit(result["url"]).path.endswith(".map") and "json" in result["headers"].get("content-type", ""):
                        try:
                            source_map = json.loads(body)
                            if isinstance(source_map, dict) and isinstance(source_map.get("sources"), list):
                                save("javascript", result["url"], {"url": result["url"], "source_map": True, "source_count": len(source_map["sources"]), "source_content_retained": False, "sha256": result["body_sha256"]}, "public source map metadata")
                        except (ValueError, RecursionError):
                            pass
                    candidates = list(dict.fromkeys(candidates + normalize_candidates(result, body, scope())))
                    for value, tag in candidates[:500]:
                        try:
                            link = clean_url(value, result["url"])
                            if not scope().allows(link):
                                continue
                            if link not in verified_urls:
                                save("urls", link, {"url": link, "discovered_by": tag, "verified": False, "verification_status": "unverified candidate", "crawl_status": "excluded navigation or form" if not safe_navigation(link) or tag.startswith("form") else "candidate"}, tag)
                            edge("url:" + result["url"], "url:" + link, "links_to")
                            if link not in verified_urls and not any(a["url"] == link for a in extracted_apis) and re.search(r"/(api|graphql|swagger|openapi)(/|\.|$)", urlsplit(link).path, re.I):
                                save("apis", link + ":", {"url": link, "host": host_of(link), "path": urlsplit(link).path, "method": "Unknown", "authentication": "Unknown", "verification_status": "unverified candidate", "classification": "candidate", "note": "Endpoint requires validation."}, "page extraction")
                            if crawl and not tag.startswith("form") and safe_navigation(link) and depth < max_depth and len(queue) < max_requests and link not in seen:
                                queue.append((link, depth + 1, tag))
                        except ValueError:
                            continue
                except Exception as exc:
                    warn(f"HTTP {url}", exc)
            if queue:
                warn(f"Crawl page limit reached for {host}.")
        for name in ("http", "technologies", "urls", "apis"):
            stages.finish(name, "partial" if len(warnings) > web_warning_start or len(hosts) > max_hosts or cancel.is_set() else "complete", requests=http.count, budget=http.maximum, reason="Results from responses actually collected; configured crawl limits apply.")
        if history and not cancel.is_set():
            progress("Historical URLs: " + history)
            try:
                urls, _ = engines.historical_urls(history, root, scope(), cancel)
            except Exception as exc:
                warn(f"Historical {history}", exc)
                urls = []
            for url in urls[:5000]:
                if url not in verified_urls:
                    save("urls", url, {"url": url, "discovered_by": "historical", "verified": False, "verification_status": "historical, unverified"}, history, historical=True)
                save("historical", url, {"url": url, "verified_current": url in verified_urls}, history, historical=True)
            if len(urls) > 5000:
                warn("Historical URL limit reached.")
        if ports is None:
            stages.finish("nmap", "skipped", reason="Not selected; discovered DNS addresses do not authorize IP scans.")
        if ports is not None and not cancel.is_set():
            stages.start("nmap", profile=nmap_profile)
            progress("Nmap service inventory: " + root)
            try:
                records, raw = engines.port_scan(root, scope(), ports, udp, cancel, **({"profile": nmap_profile, "timing": nmap_timing, "timeout": nmap_timeout, "host_timeout": nmap_host_timeout, "rate": nmap_rate, "os_detection": nmap_os, "default_scripts": nmap_scripts} if (nmap_profile, nmap_timing, nmap_timeout, nmap_host_timeout, nmap_rate, nmap_os, nmap_scripts) != ("service", 3, 180, 120, 2, False, False) else {}), **({"unprivileged": True} if nmap_unprivileged else {}), **({"diagnostic": nmap_diagnostic} if nmap_diagnostic is not None else {}))
                evidence = repository.evidence(identifier, "nmap.xml", raw)
                if records.get("partial"):
                    warn("Nmap partial scan; requested port coverage was not completed.")
                stages.finish("nmap", "partial" if records.get("partial") else "complete",
                              profile=records.get("profile"), scaninfo=records.get("scaninfo"), reported_ports=records.get("reported_ports"), open_ports=records.get("open_ports"), coverage_note=records.get("coverage_note"), coverage=records.get("coverage"), stage_notes=records.get("stage_notes"), evidence=evidence)
            except Exception as exc:
                if getattr(exc, "raw_xml", None):
                    repository.evidence(identifier, "nmap-incomplete.xml", exc.raw_xml)
                stages.finish("nmap", "failed", code=operation_error(exc)[0])
                warn("Nmap unavailable or incomplete", exc)
                records, evidence = {"records": [], "hosts": []}, None
            for row in records["records"]:
                key = f'{row["ip"]}:{row["protocol"]}:{row["port"]}'
                save("ports", key, {"host": row["ip"], "port": row["port"], "protocol": row["protocol"], "state": row["state"], "evidence": evidence}, "Nmap")
                save("services", key, {**row, "evidence": evidence}, "Nmap", confidence="engine-observed")
                edge("ip:" + row["ip"], "port:" + key, "exposes")
                edge("port:" + key, "service:" + key + ":" + row["service"], "runs")
                if row["product"]:
                    save("technologies", key, {"technology": row["product"], "category": "Network service", "classification": "Confirmed" if row.get("detection_method") == "probed" else "Likely", "evidence": evidence, "product": row["product"], "version": row["version"],
                         "cpe": row["cpe"], "lifecycle": "UNKNOWN", "note": "Validate version and distribution backports before assessing CVEs."}, "Nmap", confidence="engine-observed")
                    edge("service:" + key + ":" + row["service"], "technology:" + key, "reports")
            for row in records["hosts"]:
                save("assets", row["ip"], {"host": row["ip"], "nmap_host": row,
                     "nmap_version": records.get("nmap_version"), "nmap_completion": records.get("completion"), "evidence": evidence}, "Nmap")
                if row["timed_out"]:
                    warn("Nmap host timed out; port inventory may be incomplete: " + row["ip"])
        if not hosts:
            warn("No active hosts authorized/discovered. Wildcard scope does not authorize its apex.")
        if lifecycle and not cancel.is_set():
            progress("Upstream release lifecycle lookup")
            from .intelligence import enrich
            warnings.extend(enrich(repository, identifier, cancel=cancel))
        if cve and not cancel.is_set():
            progress("NVD CPE candidate lookup")
            from .intelligence import enrich_cves
            warnings.extend(enrich_cves(repository, identifier, cancel=cancel))
    except KeyboardInterrupt:
        stages.close(cancelled=True)
        repository.finish(identifier, warnings + ["Interrupted by operator."], cancelled=True)
        raise
    except Exception as exc:
        warn("Workflow", exc)
        stages.close(cancelled=cancel.is_set(), failed=True)
        repository.finish(identifier, warnings, failed=True, cancelled=cancel.is_set())
        return identifier
    stages.close(cancelled=cancel.is_set())
    stages.start("normalization"); stages.finish("normalization")
    stages.start("reports")
    try:
        repository.finish(identifier, warnings, cancelled=cancel.is_set())
        stages.finish("reports", directory="managed scan JSON exports")
        repository.export_json(identifier, repository.managed_directory("scans", identifier))
    except Exception as exc:
        warn("Managed JSON report generation failed; observations remain in the database", exc)
        stages.finish("reports", "failed", code=operation_error(exc)[0])
        repository.finish(identifier, warnings, cancelled=cancel.is_set(), export=False)
    return identifier
