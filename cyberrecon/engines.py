"""Controlled external engine adapters and normalized imports."""
import json
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

from .models import ValidationError
from .nmap_scan import parse_scan, scan_arguments
from .scope import host_of

TOOLS = {"subfinder": "Passive discovery adapter", "assetfinder": "Passive discovery adapter",
         "amass": "Passive discovery adapter (v3 CLI; verify installed version)", "nmap": "TCP/UDP service adapter",
         "ffuf": "Native content fallback (external execution disabled for scope safety)", "whatweb": "Native fingerprint fallback (external execution disabled for scope safety)",
         "gau": "Historical URL adapter", "waybackurls": "Historical URL adapter",
         "dnsx": "Optional normalized JSONL import", "httpx": "ProjectDiscovery JSONL import (not Python httpx CLI)",
         "naabu": "Optional normalized JSONL import", "katana": "Optional normalized JSONL import",
         "gobuster": "Planned integration (not implemented)"}


class ToolError(ValidationError):
    def __init__(self, code, tool):
        self.code, self.tool = code, Path(tool).name
        super().__init__(f"{self.tool}: {code}; check Doctor, configuration and permissions.")


def run_process(args, input_bytes=None, timeout=120, cancel=None, output_paths=(), max_output=16 * 1024 * 1024, combine_stderr=False, diagnostic=None):
    if not isinstance(args, (list, tuple)) or not args or len(args) > 1024 or any(not isinstance(arg, str) or len(arg) > 8192 or "\x00" in arg for arg in args):
        raise ValidationError("Command must be a nonempty text argument array.")
    if not 0 < timeout <= 600 or not 0 < max_output <= 16 * 1024 * 1024:
        raise ValidationError("Invalid subprocess resource limits.")
    if input_bytes is not None and (not isinstance(input_bytes, bytes) or len(input_bytes) > 1024 * 1024):
        raise ValidationError("Subprocess input must be at most 1 MiB of bytes.")
    if cancel and cancel.is_set():
        raise ToolError("cancelled", args[0])
    executable = shutil.which(args[0])
    if not executable:
        raise ToolError("tool_missing", args[0])
    # Direct argv only. No user supplied extra flags, shell commands or proxy inheritance.
    environment = {key: value for key, value in os.environ.items() if key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as stdin:
        if input_bytes:
            stdin.write(input_bytes)
            stdin.seek(0)
        try:
            process = subprocess.Popen([executable, *args[1:]], stdin=stdin, stdout=output, stderr=errors, env=environment,
                                       shell=False, start_new_session=os.name == "posix")
        except PermissionError:
            raise ToolError("permission_denied", args[0]) from None
        except OSError:
            raise ToolError("tool_failed", args[0]) from None
        def diagnose():
            if diagnostic is not None:
                output.seek(0)
                errors.seek(0)
                diagnostic({"command": [executable, *args[1:]], "returncode": process.returncode,
                            "stdout": output.read(8192).decode("utf-8", errors="replace"),
                            "stderr": errors.read(8192).decode("utf-8", errors="replace")})
        def stop():
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait()
        import time
        deadline = time.monotonic() + timeout
        try:
            def oversized():
                return (os.fstat(output.fileno()).st_size > max_output or
                        os.fstat(errors.fileno()).st_size > max_output or
                        any(Path(path).is_symlink() or Path(path).exists() and Path(path).stat().st_size > max_output
                            for path in output_paths))
            while process.poll() is None:
                code = ("cancelled" if cancel and cancel.is_set() else
                        "timeout" if time.monotonic() >= deadline else
                        "output_limit" if oversized() else None)
                if code:
                    stop()
                    diagnose()
                    raise ToolError(code, args[0])
                time.sleep(.05)
            if oversized():
                raise ToolError("output_limit", args[0])
            diagnose()
            if process.returncode:
                raise ToolError("tool_failed", args[0])
            output.seek(0)
            payload = output.read()
            if combine_stderr:
                errors.seek(0)
                payload += errors.read()
                if len(payload) > max_output:
                    raise ToolError("output_limit", args[0])
            return payload
        finally:
            if process.poll() is None:
                stop()


def passive_domains(engine, target, scope, cancel=None, transport=None):
    target = scope.require(target, passive=True)
    try:
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False
    else:
        is_ip = True
    if is_ip:
        raise ValidationError("Passive enumeration needs a domain.")
    if engine == "ct":
        from types import SimpleNamespace
        from .connectors import Collector
        config = SimpleNamespace(timeout_seconds=5, endpoints={"ct": "https://crt.sh", "certspotter": "https://api.certspotter.com/v1"})
        result = Collector(config, None, cancel=cancel)._collect("ct", target)
        if cancel and cancel.is_set():
            raise ValidationError("Certificate collection cancelled.")
        names = [host for host in result.data["concrete_names"] if scope.allows(host)]
        metadata = {"source": result.source, "reference": result.reference,
                    "warnings": result.data["warnings"], "truncated": result.data["truncated"]}
        return names, json.dumps(metadata).encode()
    if engine == "dnsdumpster":
        from .dnsdumpster import lookup
        names, records, metadata = lookup(target, scope, cancel=cancel, transport=transport)
        return names, json.dumps({**metadata, "records": records}, allow_nan=False).encode()
    commands = {"subfinder": ["subfinder", "-d", target, "-silent", "-duc", "-rl", "2", "-timeout", "10", "-max-time", "1"],
                "assetfinder": ["assetfinder", "--subs-only", target],
                "amass": ["amass", "enum", "-passive", "-d", target, "-timeout", "1"]}
    if engine not in commands:
        raise ValidationError("Unsupported passive engine.")
    if engine == "amass":
        version = run_process(["amass", "-version"], timeout=3, max_output=65536, combine_stderr=True).decode(errors="replace")
        if not re.search(r"\bv?3\.\d+", version):
            raise ValidationError("Amass passive adapter supports verified v3 CLI only; use CT or Subfinder.")
    raw = run_process(commands[engine], cancel=cancel)
    names = set()
    for line in raw.decode("utf-8", errors="replace").splitlines():
        try:
            host = host_of(line)
            if scope.allows(host) and (host == target or host.endswith("." + target)):
                names.add(host)
        except ValueError:
            continue
    return sorted(names), raw


def port_scan(target, scope, ports="", udp=False, cancel=None, *, unprivileged=False, diagnostic=None, profile="service", timing=3, host_timeout=120, timeout=180, rate=2, os_detection=False, default_scripts=False):
    scope.require(target)
    # Strict IP-only target; DNS resolution never implicitly authorizes Nmap.
    if type(timeout) is not int or not 10 <= timeout <= 600 or type(rate) is not int or not 1 <= rate <= 1000:
        raise ValidationError("Nmap timeout must be 10–600 seconds and rate 1–1000 probes/second.")
    if udp and profile == "full":
        raise ValidationError("Full profile is TCP only; choose bounded UDP ports separately.")
    if os_detection and (unprivileged or os.name != "posix" or os.geteuid() != 0):
        raise ToolError("privileges_required", "nmap")
    args, addresses = scan_arguments(target, ports, profile=profile, timing=timing, host_timeout=host_timeout, os_detection=os_detection, default_scripts=default_scripts)
    for address in addresses:
        scope.require(address)
    args += ["--max-rate", str(rate), "--max-parallelism", "2"]
    if unprivileged:
        if udp:
            raise ValidationError("Unprivileged lab mode supports TCP only.")
        args.insert(0, "--unprivileged")
    if udp:
        args[args.index("-sT")] = "-sU"
        if os.name == "posix" and os.geteuid() != 0:
            raise ToolError("privileges_required", "nmap")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "nmap.xml"
        failure = None
        try:
            run_process(["nmap", *args, "-oX", str(output), *addresses], timeout=timeout, cancel=cancel, output_paths=(output,), **({"diagnostic": diagnostic} if diagnostic is not None else {}))
        except ToolError as exc:
            failure = exc
            if not output.is_file() or output.is_symlink():
                raise
        if output.is_symlink() or not output.exists() or output.stat().st_size > 16 * 1024 * 1024:
            raise ValidationError("Nmap output missing or oversized.")
        payload = output.read_bytes()
    try:
        parsed = parse_scan(payload, allow_partial=True)
    except ValueError:
        exc = failure or ToolError("invalid_xml", "nmap")
        exc.raw_xml = payload
        raise exc from None
    if failure:
        parsed.update(partial=True, failure_code=failure.code)
    parsed["profile"] = dict(name=profile, protocol="udp" if udp else "tcp", ports=ports or ("1-65535" if profile == "full" else "top-100"), timing=timing, timeout=timeout, rate=rate, os_detection=os_detection, default_scripts=default_scripts)
    coverage = []
    protocol = "udp" if udp else "tcp"
    scaninfo = [r for r in parsed["scaninfo"] if r.get("protocol") == protocol]
    requested = None
    if len(scaninfo) == 1 and scaninfo[0].get("numservices", "").isdigit():
        count = int(scaninfo[0]["numservices"])
        if 1 <= count <= 65535:
            requested = count
    for host in parsed["hosts"]:
        explicit = sum(r["ip"] == host["ip"] and r["protocol"] == protocol for r in parsed["records"])
        summaries = host["port_summary"]
        summarized = sum(int(r["count"]) for r in summaries if r.get("count", "").isdigit() and int(r["count"]) <= 65535)
        observed = explicit + summarized
        verified = requested is not None and observed == requested and not host["timed_out"] and not parsed["partial"]
        coverage.append({"host": host["ip"], "requested_ports": requested, "reported_individual_ports": explicit,
                         "summarized_ports": summarized, "reported_total_ports": observed, "coverage_verified": verified})
        if requested is not None and not verified:
            parsed["partial"] = True
    if {h["ip"] for h in parsed["hosts"]} != set(addresses):
        parsed["partial"] = True
    if profile == "full" and (requested != 65535 or not coverage or not all(c["coverage_verified"] for c in coverage)):
        parsed["partial"] = True
    parsed["coverage"] = coverage
    parsed["stage_notes"] = {"os": "requested; inconclusive if no matches" if os_detection else "skipped (not requested)", "udp": "requested; slower and potentially inconclusive" if udp else "skipped (not requested)", "scripts": "default and safe requested" if default_scripts else "skipped (not requested)"}
    for row in (*parsed["hosts"], *parsed["records"]):
        if row["ip"] not in addresses:
            raise ValidationError("Nmap returned an unexpected target address.")
        scope.require(row["ip"])
    if any(row["protocol"] not in {"tcp", "udp"} for row in parsed["records"]):
        raise ValidationError("Nmap returned an unexpected port protocol.")
    return parsed, payload


def historical_urls(engine, target, scope, cancel=None):
    target = scope.require(target, passive=True)
    if engine == "gau":
        raw = run_process(["gau", "--threads", "1", "--timeout", "10", target], cancel=cancel)
    elif engine == "waybackurls":
        raw = run_process(["waybackurls"], (target + "\n").encode(), cancel=cancel)
    else:
        raise ValidationError("Unsupported historical URL engine.")
    from .network import clean_url
    urls = set()
    for value in raw.decode(errors="replace").splitlines():
        try:
            value = clean_url(value)
            if scope.allows(value):
                urls.add(value)
        except ValueError:
            continue
    # Historical raw URLs can contain credentials/tokens; preserve sanitized output only.
    return sorted(urls), ("\n".join(sorted(urls))).encode()


def fingerprint(url, scope, cancel=None):
    """Safe native replacement: tool-owned DNS cannot enforce IP exclusions."""
    from .network import ScopedHTTP
    response = ScopedHTTP(lambda: scope, cancel=cancel, max_requests=5).fetch(url)
    from .fingerprints import detect
    return detect(response, response["text"], response["cookie_headers"])



def content_scan(url, scope, words, rate=2, cancel=None):
    """Bounded native requests replace the unsafe tool-owned DNS adapter."""
    from .network import ScopedHTTP, clean_url
    url = clean_url(url)
    scope.require(url)
    words = list(dict.fromkeys(word.strip().lstrip("/") for word in words if word.strip()))
    if not 1 <= len(words) <= 200 or any(not re.fullmatch(r"[a-zA-Z0-9_./-]{1,100}", word) or ".." in word for word in words):
        raise ValidationError("Use 1–200 relative paths with no traversal, query or hostname fuzzing.")
    client = ScopedHTTP(lambda: scope, rate=rate, max_requests=200, cancel=cancel)
    records = []
    for word in words:
        target = url.split("?", 1)[0].rstrip("/") + "/" + word
        response = client.fetch(target)
        if response["status_code"] != 404:
            records.append({"url": response["url"], "status_code": response["status_code"], "length": response["bytes_read"],
                            "confidence": "requires-validation",
                            "note": "May be a soft-404 or wildcard response; not proof of exposed content."})
    return records
