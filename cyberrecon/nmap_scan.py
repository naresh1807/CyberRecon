"""Bounded IP-only Nmap arguments and safe inventory XML parsing.

Execution and authorization live in engines.port_scan and scanner.scan.
"""
import ipaddress
import re
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from .models import ValidationError

def scan_arguments(targets, ports="", vulnerabilities=False, *, profile="service", timing=3, host_timeout=120, os_detection=False, default_scripts=False):
    if profile not in {"quick", "service", "full"} or type(timing) is not int or not 0 <= timing <= 4 or type(host_timeout) is not int or not 10 <= host_timeout <= 600:
        raise ValidationError("Invalid Nmap profile, timing (0–4) or host timeout (10–600 seconds).")
    if vulnerabilities:
        raise ValidationError("Vulnerability scripts are not supported by inventory profiles.")
    if not isinstance(targets, str) or len(targets) > 4096 or not isinstance(ports, str) or len(ports) > 8192:
        raise ValidationError("Invalid Nmap argument text or size.")
    values = re.split(r"[\s,]+", targets.strip())
    try:
        addresses = list(dict.fromkeys(str(ipaddress.ip_address(value)) for value in values))
    except ValueError as exc:
        raise ValidationError("Enter individual IPv4 or IPv6 addresses separated by commas. No ranges or hostnames.") from exc
    if not 1 <= len(addresses) <= 16:
        raise ValidationError("Choose between 1 and 16 IP addresses.")
    families = {ipaddress.ip_address(value).version for value in addresses}
    if len(families) != 1:
        raise ValidationError("Scan IPv4 and IPv6 in separate batches.")
    if any(ipaddress.ip_address(value).is_multicast or ipaddress.ip_address(value).is_unspecified for value in addresses):
        raise ValidationError("Multicast and unspecified addresses cannot be scanned.")
    args = ["-sT", "-n", "-Pn", "-T" + str(timing), "--max-retries", "1",
            "--host-timeout", str(host_timeout) + "s", "--script-timeout", "30s"]
    if profile != "quick":
        args += ["-sV", "--version-light"]
    if os_detection:
        args += ["-O", "--osscan-limit"]
    if default_scripts:
        args += ["--script", "default and safe"]
    if profile == "full":
        if ports.strip():
            raise ValidationError("Full TCP profile selects 1–65535; do not combine with custom ports.")
        args += ["-p", "1-65535"]
    if families == {6}:
        args.append("-6")
    if profile == "full":
        pass
    elif ports.strip():
        selected = set()
        for part in ports.strip().split(","):
            if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", part.strip()):
                raise ValidationError("Ports must be numbers or ranges, for example 22,80,443,8000-8010.")
            bounds = [int(value) for value in part.split("-")]
            start, end = bounds[0], bounds[-1]
            if not 1 <= start <= end <= 65535 or end - start >= 1000:
                raise ValidationError("Select valid ports from 1 to 65535, at most 1000 total.")
            selected.update(range(start, end + 1))
        if len(selected) > 1000:
            raise ValidationError("Select at most 1000 ports.")
        args += ["-p", ",".join(str(port) for port in sorted(selected))]
    else:
        args += ["--top-ports", "100"]
    return args, addresses

def parse_scan(payload, *, allow_partial=False):
    if not isinstance(payload, bytes):
        raise ValidationError("Nmap XML must be bytes.")
    if len(payload) > 16 * 1024 * 1024 or b"<!ENTITY" in payload.upper():
        raise ValidationError("Nmap output exceeds limits or contains XML entities.")
    try:
        root = ET.fromstring(payload, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except ET.ParseError as exc:
        if not allow_partial or not re.search(br"<nmaprun(?:\s|>)", payload):
            raise ValidationError("Nmap did not produce valid XML output.") from exc
        # Recover only fully closed host elements. Never invent the missing tail.
        fragments = re.findall(br"<host(?:\s[^>]*)?>.*?</host>", payload, re.S)
        root = ET.fromstring(b"<nmaprun>" + b"".join(fragments) + b"</nmaprun>", forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise ValidationError("Nmap did not produce safe XML output.") from exc
    if root.tag != "nmaprun":
        raise ValidationError("This is not Nmap XML output.")
    finished = root.find("runstats/finished")
    if not allow_partial and (finished is None or finished.get("exit") != "success"):
        raise ValidationError("Nmap scan did not finish successfully.")
    records, hosts = [], []
    for host in root.findall("host"):
        addresses = [a.get("addr", "") for a in host.findall("address") if a.get("addrtype") in {"ipv4", "ipv6"}]
        try:
            if len(addresses) != 1:
                raise ValueError()
            address = str(ipaddress.ip_address(addresses[0]))
        except ValueError:
            raise ValidationError("Nmap host must have one valid IP address.") from None
        hosts.append({"ip": address, "status": host.find("status").get("state", "unknown") if host.find("status") is not None else "unknown",
                      "timed_out": host.get("timedout") == "true",
                      "timing": {key: host.get(key) for key in ("starttime", "endtime") if host.get(key)},
                      "os_matches": [item.attrib for item in host.findall("os/osmatch")],
                      "port_summary": [item.attrib for item in host.findall("ports/extraports")]})
        for port in host.findall("ports/port"):
            try:
                port_number = int(port.get("portid", ""))
                if not 1 <= port_number <= 65535:
                    raise ValueError()
            except ValueError:
                raise ValidationError("Nmap returned an invalid port number.") from None
            service = port.find("service")
            state = port.find("state")
            attrs = service.attrib if service is not None else {}
            scripts = [{"id": item.get("id"), "output": item.get("output", "")} for item in port.findall("script")]
            records.append({"ip": address, "port": port_number, "protocol": port.get("protocol"),
                            "state": state.get("state", "unknown") if state is not None else "unknown",
                            "service": attrs.get("name", "unknown"), "product": attrs.get("product", ""),
                            "version": attrs.get("version", ""), "extra_info": attrs.get("extrainfo", ""),
                            "tunnel": attrs.get("tunnel", ""), "os_hint": attrs.get("ostype", ""),
                            "confidence": attrs.get("conf", ""), "service_confidence": attrs.get("conf", "Unknown"), "detection_method": attrs.get("method", ""),
                            "cpe": [item.text for item in service.findall("cpe")] if service is not None else [],
                            "script_findings": scripts})
    deduplicated = {}
    conflicts = False
    for record in records:
        key = record["ip"], record["protocol"], record["port"]
        if key not in deduplicated:
            deduplicated[key] = record
        else:
            existing = deduplicated[key]
            assertions = existing.get("port_assertions", [{k: v for k, v in existing.items() if k != "port_assertions"}])
            if record not in assertions:
                assertions.append(record)
                existing["port_assertions"] = assertions
                existing["verification_status"] = "conflicting XML assertions; review required"
                conflicts = True
                for field in ("state", "service", "product", "version"):
                    if len({str(a.get(field)) for a in assertions}) > 1:
                        existing[field] = "unknown" if field in {"state", "service"} else "Unknown"
    records = list(deduplicated.values())
    return {"records": records, "hosts": hosts, "nmap_version": root.get("version", ""), "completion": dict(finished.attrib) if finished is not None else {},
            "partial": conflicts or finished is None or finished.get("exit") != "success" or any(h["timed_out"] for h in hosts),
            "scaninfo": [dict(item.attrib) for item in root.findall("scaninfo")],
            "reported_ports": len(records), "open_ports": sum(r["state"] == "open" for r in records),
            "coverage_note": "scaninfo describes requested coverage; partial runs do not prove every requested port was attempted. Summarized extraports do not identify individual port numbers.",
            "note": "Service versions and OS hints are observations, not proof. Vulners matches are potential vulnerabilities requiring validation; no matches does not establish safety. Host timeouts can leave incomplete results. OS, UDP and scripts depend on the explicitly selected profile; absent results are not proof of absence."}
