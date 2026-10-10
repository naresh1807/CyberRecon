"""Bounded public certificate metadata, with no case-store dependency.

Only CT collection is supported. Injected transports are for deterministic tests.
Real requests pin public addresses and verify TLS against the original hostname.
"""
import ipaddress
import json
import math
import socket
import threading
import time
from types import SimpleNamespace
from urllib.parse import quote, urljoin, urlsplit

import httpx

from .domains import domain
from .models import Result, ValidationError
from .network import resolve_addresses

_rate_lock = threading.Lock()
_next_request = {}


def public_address(host, cancel=None, timeout=5):
    try:
        ipaddress.ip_address(host)
        dns_host = host
    except ValueError:
        dns_host = domain(host) + "."
    addresses = resolve_addresses(dns_host, 443, cancel, timeout)
    def allowed(value):
        ip = ipaddress.ip_address(value)
        return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified or getattr(ip, "is_site_local", False))
    if not addresses or any(not allowed(row[4][0]) for row in addresses):
        raise ValidationError("HTTP collection permits only public Internet addresses.")
    return addresses[0][4][0]


class Collector:
    """CT-only adapter preserving the interface used by the passive engine."""
    def __init__(self, config=None, store=None, transport=None, sleeper=None, cancel=None):
        if store is not None:
            raise ValidationError("Certificate collection does not use a case store.")
        self.config = config or SimpleNamespace(timeout_seconds=5, endpoints={
            "ct": "https://crt.sh", "certspotter": "https://api.certspotter.com/v1"})
        if not isinstance(self.config.timeout_seconds, (int, float)) or not math.isfinite(self.config.timeout_seconds) or not 0 < self.config.timeout_seconds <= 10:
            raise ValidationError("Metadata timeout must be between zero and ten seconds.")
        self.transport, self.sleep = transport, sleeper
        self.cancel = cancel or threading.Event()
        self.deadline = time.monotonic() + 60
        self.requests = 0

    def _remaining(self):
        if self.cancel.is_set():
            raise ValidationError("Certificate collection cancelled.")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ValidationError("Certificate collection time budget exhausted.")
        return remaining

    def _pause(self, delay):
        if delay >= self._remaining():
            raise ValidationError("Certificate collection time budget exhausted.")
        if self.sleep is not None:
            self.sleep(delay)
        elif self.cancel.wait(delay):
            raise ValidationError("Certificate collection cancelled.")
        self._remaining()

    def endpoint(self, name):
        return self.config.endpoints[name].rstrip("/")

    def _request(self, method, url, attempts=3, timeout_seconds=None):
        if method != "GET" or not isinstance(attempts, int) or not 1 <= attempts <= 3:
            raise ValidationError("Metadata requests support bounded GET only.")
        original = url
        for redirect in range(5):
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443) or len(url) > 4096 or any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in url):
                raise ValidationError("Connector endpoints must use HTTPS on port 443 without credentials.")
            host = domain(parts.hostname)
            pinned = url
            if self.transport is None:
                address = public_address(host, self.cancel, min(5, self._remaining()))
                pinned = parts._replace(netloc=f"[{address}]" if ":" in address else address).geturl()
            for attempt in range(attempts):
                self._remaining()
                if self.requests >= 20:
                    raise ValidationError("Certificate request limit reached.")
                # Shared reservations retain the one-request/second provider rate,
                # including across collectors. Test sleepers avoid real delays.
                with _rate_lock:
                    now = time.monotonic()
                    delay = max(0, _next_request.get(host, 0) - now)
                    if delay > 30:
                        raise RuntimeError(f"Rate limited; retry after {math.ceil(delay)} seconds.")
                    _next_request[host] = now + delay + 1
                self._pause(delay)
                self.requests += 1
                timeout = min(timeout_seconds or self.config.timeout_seconds, self._remaining())
                try:
                    with httpx.Client(timeout=timeout, verify=True, trust_env=False,
                                      follow_redirects=False, transport=self.transport) as client:
                        with client.stream("GET", pinned, headers={"Host": host,
                                "User-Agent": "CyberRecon/0.2 public certificate metadata",
                                "Accept-Encoding": "identity"}, extensions={"sni_hostname": host}) as response:
                            status = response.status_code
                            if status in {429, 500, 502, 503, 504}:
                                retry = response.headers.get("retry-after", "")
                                try:
                                    delay = float(retry)
                                except ValueError:
                                    from email.utils import parsedate_to_datetime
                                    from datetime import datetime, timezone
                                    try:
                                        delay = (parsedate_to_datetime(retry) - datetime.now(timezone.utc)).total_seconds()
                                    except (TypeError, ValueError, OverflowError):
                                        delay = 2 ** attempt
                                if not math.isfinite(delay) or delay < 0:
                                    delay = 2 ** attempt
                                with _rate_lock:
                                    _next_request[host] = max(_next_request.get(host, 0), time.monotonic() + delay)
                                if delay > 30:
                                    raise RuntimeError(f"Rate limited; retry after {math.ceil(delay)} seconds.")
                                if attempt == attempts - 1:
                                    raise RuntimeError(f"Source unavailable (HTTP {status}).")
                                self._pause(delay)
                                continue
                            if status in {301, 302, 303, 307, 308}:
                                location = response.headers.get("location")
                                destination = urljoin(url, location or "")
                                if not location or urlsplit(destination).hostname != host:
                                    raise ValidationError("Cross-host metadata redirect rejected.")
                                url = destination
                                break
                            if status >= 400:
                                raise RuntimeError(f"Source returned HTTP {status}.")
                            if response.headers.get("content-encoding", "identity").lower() not in {"identity", ""}:
                                raise ValidationError("Compressed metadata response rejected.")
                            length = response.headers.get("content-length", "")
                            if length.isdecimal() and int(length) > 8 * 1024 * 1024:
                                raise ValidationError("Source response exceeded 8 MiB limit.")
                            body = bytearray()
                            chunks = [response.content] if self.transport is not None and response.is_stream_consumed else response.iter_raw()
                            for chunk in chunks:
                                self._remaining()
                                if len(body) + len(chunk) > 8 * 1024 * 1024:
                                    raise ValidationError("Source response exceeded 8 MiB limit.")
                                body.extend(chunk)
                            payload = json.loads(body)
                            return payload, original, dict(response.headers)
                except httpx.TransportError:
                    if attempt == attempts - 1:
                        raise RuntimeError("Network or TLS connection failed.") from None
                    self._pause(2 ** attempt)
            else:
                raise RuntimeError("Retry budget exhausted.")
        raise ValidationError("Too many source redirects.")

    def _collect(self, source, target):
        self._remaining()
        if source == "ct":
            target = domain(target)
            try:
                return self._collect("ct_primary", target)
            except (RuntimeError, ValueError, socket.gaierror, KeyError) as primary_error:
                try:
                    result = self._collect("certspotter", target)
                    result.data["provider_errors"] = {"crt.sh": str(primary_error)}
                    return result
                except (RuntimeError, ValueError, socket.gaierror, KeyError) as fallback_error:
                    raise RuntimeError(f"Certificate sources unavailable. crt.sh: {primary_error}; Cert Spotter: {fallback_error}. Retry later; provider rate limits may apply.") from None
        if source in {"ct_primary", "certspotter"}:
            target = domain(target)
            truncated, warnings = False, []
            if source == "ct_primary":
                url = self.endpoint("ct") + "/?q=" + quote("%." + target) + "&output=json"
                data, ref, _ = self._request("GET", url, attempts=1,
                                             timeout_seconds=min(8, self.config.timeout_seconds))
                provider = "Certificate Transparency / crt.sh"
            else:
                url = self.endpoint("certspotter") + "/issuances?domain=" + quote(target) + "&include_subdomains=true&expand=dns_names"
                data, after, seen = [], "", set()
                provider, ref = "Certificate Transparency / Cert Spotter", url
                for page in range(5):
                    try:
                        batch, _, _ = self._request("GET", url + ("&after=" + quote(after, safe="") if after else ""))
                        if not isinstance(batch, list) or any(not isinstance(row, dict) or not isinstance(row.get("dns_names"), list)
                                or any(not isinstance(name, str) for name in row["dns_names"]) for row in batch):
                            raise RuntimeError("Malformed Cert Spotter response.")
                    except (RuntimeError, ValueError, socket.gaierror, KeyError) as exc:
                        if not data:
                            raise
                        truncated = True
                        warnings.append("Incomplete pagination: " + str(exc))
                        break
                    if not batch:
                        break
                    data.extend({"name_value": "\n".join(row["dns_names"])} for row in batch)
                    after = batch[-1].get("id")
                    if not isinstance(after, str) or not after or after in seen:
                        truncated = True
                        warnings.append("Provider omitted or repeated the pagination cursor.")
                        break
                    seen.add(after)
                else:
                    truncated = True
                    warnings.append("Stopped at the five-page request limit.")
            if isinstance(data, str):
                data = json.loads(data)
            if not isinstance(data, list) or any(not isinstance(row, dict) or not isinstance(row.get("name_value"), str) for row in data):
                raise RuntimeError("Malformed certificate transparency response.")
            names = set()
            concrete, wildcards = set(), set()
            for row in data:
                for name in row.get("name_value", "").splitlines():
                    wildcard = name.strip().startswith("*.")
                    try:
                        name = domain(name.strip().removeprefix("*."))
                    except ValueError:
                        continue
                    if name == target or name.endswith("." + target):
                        names.add(name)
                        (wildcards if wildcard else concrete).add(name)
            return Result(provider, ref, target,
                          {"subdomains": sorted(names), "certificate_count": len(data),
                           "concrete_names": sorted(concrete), "wildcard_patterns": ["*." + name for name in sorted(wildcards)],
                           "truncated": truncated, "warnings": warnings,
                           "note": "Certificate observations do not establish that a host is currently active."})
        raise ValidationError("Only CT metadata collection is supported.")
