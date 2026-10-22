"""Bounded integration with DNSDumpster's documented API.

Provider records are stored as historical observations. They never authorize or
trigger requests to the IP addresses returned by the provider.
"""
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from urllib.parse import quote

import httpx

from .models import ValidationError, utcnow
from .network import ScopedHTTP
from .scope import Scope, host_of

API_HOST = "api.dnsdumpster.com"
API_REFERENCE = "https://dnsdumpster.com/developer/"
MAX_LIST_ITEMS = 250
MAX_RECORDS = 500
MAX_RELATED_IPS = 20

_rate_lock = threading.Lock()
_next_request_at = 0.0
_clock = time.monotonic


class DNSDumpsterError(ValidationError):
    """Safe, credential-free provider error with a user-facing status code."""

    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _rate_slot(cancel):
    """Enforce the documented one-request-per-two-seconds process-wide limit."""
    global _next_request_at
    with _rate_lock:
        if cancel.is_set():
            raise DNSDumpsterError("cancelled", "DNSDumpster request cancelled; no request was made.")
        delay = max(0.0, _next_request_at - _clock())
        if cancel.wait(delay):
            raise DNSDumpsterError("cancelled", "DNSDumpster request cancelled; no request was made.")
        _next_request_at = _clock() + 2.0


def _text(value, secret, limit=256):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if secret and secret.casefold() in value.casefold():
        return None
    return value


def _in_scope_host(value, root, scope):
    value = _text(value, "", 253)
    if not value:
        return None
    try:
        host = host_of(value)
    except (TypeError, ValueError):
        return None
    if host != root and not host.endswith("." + root):
        return None
    return host if scope.allows(host) else None


def _ip_details(value, secret):
    if not isinstance(value, dict):
        return None
    try:
        address = str(ipaddress.ip_address(value.get("ip", "")))
    except (ValueError, TypeError):
        return None
    row = {"ip": address}
    asn = _text(str(value.get("asn")), secret, 20) if value.get("asn") is not None else None
    if asn and re.fullmatch(r"[0-9]{1,10}", asn):
        row["asn"] = asn
    for field, limit in (("asn_name", 160), ("country", 80), ("ptr", 253)):
        text = _text(value.get(field), secret, limit)
        if text:
            row[field] = text
    country_code = _text(value.get("country_code"), secret, 2)
    if country_code and re.fullmatch(r"[A-Za-z]{2}", country_code):
        row["country_code"] = country_code.upper()
    network = _text(value.get("asn_range"), secret, 64)
    if network:
        try:
            row["asn_range"] = str(ipaddress.ip_network(network, strict=False))
        except ValueError:
            pass
    banners = value.get("banners")
    if isinstance(banners, dict):
        safe_banners = {}
        for scheme in ("http", "https"):
            banner = banners.get(scheme)
            if not isinstance(banner, dict):
                continue
            normalized = {}
            for field in ("server", "title", "cn"):
                text = _text(banner.get(field), secret, 160)
                if text:
                    normalized[field] = text
            apps = banner.get("apps")
            if isinstance(apps, list):
                values = [_text(item, secret, 80) for item in apps[:10]]
                normalized["apps"] = [item for item in values if item]
            alt_names = banner.get("alt_n")
            if isinstance(alt_names, list):
                values = [_text(item, secret, 253) for item in alt_names[:20]]
                normalized["alt_n"] = [item for item in values if item]
            if normalized:
                safe_banners[scheme] = normalized
        if safe_banners:
            row["banners"] = safe_banners
    return row


def _target_value(item, record_type, secret):
    fields = ("value", "target", "record", "exchange", record_type.lower())
    for field in fields:
        value = item.get(field) if isinstance(item, dict) else None
        value = _text(value, secret, 512)
        if value:
            return value
    if isinstance(item, str):
        return _text(item, secret, 512)
    if record_type in {"MX", "NS"} and isinstance(item, dict):
        return _text(item.get("host"), secret, 253)
    return None


def normalize_response(domain, scope, data, secret):
    """Keep a small, known-field subset; redact TXT payloads and unknown fields."""
    if not isinstance(data, dict):
        raise DNSDumpsterError("malformed_response", "DNSDumpster returned malformed JSON data.")
    arrays = {}
    for field in ("a", "aaaa", "cname", "mx", "ns", "txt"):
        value = data.get(field, [])
        if not isinstance(value, list):
            raise DNSDumpsterError("malformed_response", "DNSDumpster returned a malformed record list.")
        arrays[field] = value
    if not any(field in data for field in arrays):
        raise DNSDumpsterError("malformed_response", "DNSDumpster returned malformed data with no recognized DNS record lists.")

    records, hosts, warnings = [], set(), []
    truncated = any(len(values) > MAX_LIST_ITEMS for values in arrays.values())
    if truncated:
        warnings.append("Provider result list exceeded the local record budget; additional rows were omitted.")

    def add(record):
        if len(records) >= MAX_RECORDS:
            if "Local provider record budget reached; results are partial." not in warnings:
                warnings.append("Local provider record budget reached; results are partial.")
            return False
        record["provider"] = "DNSDumpster"
        record["reference"] = API_REFERENCE
        record["collected_at"] = utcnow()
        record["historical"] = True
        record["verified_current"] = False
        record["verification_status"] = "DNSDumpster database observation; not independently verified current"
        record["confidence"] = "provider observation"
        record["note"] = "Provider data may be cached. CyberRecon did not scan this IP or confirm this record."
        core = {key: value for key, value in record.items() if key not in {"collected_at", "note"}}
        record["evidence_sha256"] = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        records.append(record)
        return True

    for field in ("a", "aaaa"):
        record_type = field.upper()
        for item in arrays[field][:MAX_LIST_ITEMS]:
            if not isinstance(item, dict):
                continue
            owner = _in_scope_host(item.get("host") or item.get("owner"), domain, scope)
            if not owner:
                continue
            hosts.add(owner)
            ips = item.get("ips", [])
            if not isinstance(ips, list):
                warnings.append("Provider returned a malformed IP list; that row was omitted.")
                continue
            if not ips:
                add({"host": owner, "record_type": record_type, "value": "Unknown", "provider_record_host": owner})
                continue
            for item_ip in ips[:MAX_RELATED_IPS]:
                details = _ip_details(item_ip, secret)
                if not details:
                    warnings.append("Provider returned an invalid IP row; that row was omitted.")
                    continue
                add({"host": owner, "record_type": record_type, "value": details["ip"], "ip": details["ip"],
                     "provider_record_host": owner, **{k: v for k, v in details.items() if k != "ip"}})
            if len(ips) > MAX_RELATED_IPS:
                warnings.append("Provider IP list exceeded the per-host display limit; additional rows were omitted.")

    for field in ("cname", "mx", "ns"):
        record_type = field.upper()
        for item in arrays[field][:MAX_LIST_ITEMS]:
            raw_owner = (item.get("owner") or (item.get("host") if field == "cname" else domain)) if isinstance(item, dict) else domain
            owner = _in_scope_host(raw_owner, domain, scope)
            if not owner:
                continue
            if record_type == "CNAME":
                hosts.add(owner)
            value = _target_value(item, record_type, secret)
            if not value:
                continue
            row = {"host": owner, "record_type": record_type, "value": value, "provider_record_host": _text(item.get("host"), secret, 253) if isinstance(item, dict) else None}
            related = item.get("ips", []) if isinstance(item, dict) else []
            if isinstance(related, list):
                details = [_ip_details(ip_row, secret) for ip_row in related[:MAX_RELATED_IPS]]
                row["related_ips"] = [entry for entry in details if entry]
            if add(row) and record_type == "CNAME":
                discovered = _in_scope_host(value, domain, scope)
                if discovered:
                    hosts.add(discovered)

    for item in arrays["txt"][:MAX_LIST_ITEMS]:
        if isinstance(item, dict):
            owner = _in_scope_host(item.get("owner") or item.get("host") or domain, domain, scope)
            raw_value = item.get("value", item.get("text", item.get("record", "")))
        else:
            owner, raw_value = domain, item
        if not owner or not isinstance(raw_value, str) or len(raw_value) > 8192:
            continue
        digest = hashlib.sha256(raw_value.encode("utf-8", errors="replace")).hexdigest()
        add({"host": owner, "record_type": "TXT", "value_redacted": True, "value_sha256": digest,
             "value": "[redacted; SHA-256 " + digest + "]", "provider_record_host": owner})

    reported_a = data.get("total_a_recs")
    if isinstance(reported_a, int) and not isinstance(reported_a, bool) and reported_a > sum(r["record_type"] == "A" for r in records):
        warnings.append("Provider-reported A-record total exceeds the rows returned; provider/account limits may apply.")
    return sorted(hosts), records, list(dict.fromkeys(warnings))


def lookup(domain, scope, cancel=None, transport=None):
    """Fetch a single documented domain endpoint using the configured env key."""
    cancel = cancel or threading.Event()
    domain = scope.require(domain, passive=True)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise DNSDumpsterError("invalid_target", "DNSDumpster passive discovery requires a domain target.")
    key = os.environ.get("DNSDUMPSTER_API_KEY", "")
    if not key:
        raise DNSDumpsterError("api_key_missing", "DNSDumpster skipped: set DNSDUMPSTER_API_KEY in the application environment; no request was made.")
    if len(key) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise DNSDumpsterError("invalid_configuration", "DNSDUMPSTER_API_KEY is invalid; no request was made.")
    _rate_slot(cancel)
    endpoint = "https://" + API_HOST + "/domain/" + quote(domain, safe=".-")
    client = ScopedHTTP(lambda: Scope((API_HOST,)), rate=1, max_requests=1, transport=transport, cancel=cancel)
    try:
        response = client.fetch(endpoint, request_headers={"X-API-Key": key, "Accept": "application/json"})
    except httpx.TimeoutException:
        raise DNSDumpsterError("timeout", "DNSDumpster request timed out; no provider data was returned.") from None
    except (httpx.TransportError, OSError):
        raise DNSDumpsterError("network_failure", "DNSDumpster request failed at the network or TLS layer; details were redacted.") from None
    except ValidationError as exc:
        if "cancel" in str(exc).casefold():
            raise DNSDumpsterError("cancelled", "DNSDumpster request cancelled; partial provider data is unavailable.") from None
        if "timeout" in str(exc).casefold() or "duration" in str(exc).casefold():
            raise DNSDumpsterError("timeout", "DNSDumpster request timed out; no provider data was returned.") from None
        raise DNSDumpsterError("request_rejected", "DNSDumpster request was rejected by local scope or resource controls.") from None
    if response["status_code"] in {401, 403}:
        raise DNSDumpsterError("api_key_rejected", "DNSDumpster rejected the configured API key or account access.")
    if response["status_code"] == 429:
        raise DNSDumpsterError("rate_limited", "DNSDumpster rate limit reached; wait before retrying.")
    if response["status_code"] != 200:
        raise DNSDumpsterError("provider_unavailable", "DNSDumpster returned HTTP " + str(response["status_code"]) + "; provider data is unavailable.")
    if response["truncated"]:
        raise DNSDumpsterError("response_truncated", "DNSDumpster response exceeded the safe response-size limit; no partial JSON was stored.")
    try:
        data = json.loads(response["text"])
    except (ValueError, TypeError):
        raise DNSDumpsterError("malformed_response", "DNSDumpster returned malformed JSON data.") from None
    hosts, records, warnings = normalize_response(domain, scope, data, key)
    return hosts, records, {"warnings": warnings, "returned_records": len(records),
                            "coverage_note": "One provider page only; DNSDumpster account record caps and provider freshness apply."}
