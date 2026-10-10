"""Bounded DNS inventory and opt-in wildcard controls; no IP scope expansion."""
import hashlib
import ipaddress
import dns.resolver
import dns.exception
from .normalization import dns_attributes
from .models import utcnow, ValidationError

TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def resolve_host(host, scope, cancel, resolver=None):
    load_scope = scope if callable(scope) else lambda: scope
    load_scope().require(host)
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = 3
    rows, statuses = [], {}
    for family in TYPES:
        if cancel.is_set():
            statuses[family] = "cancelled"; continue
        load_scope().require(host)
        try:
            answer = resolver.resolve(host + ".", family, search=False)
            statuses[family] = "resolved"
            for entry in answer:
                value = str(entry)
                row = {"host": host, "type": family, "ttl": answer.rrset.ttl, "resolution_status": "resolved", "resolved_at": utcnow()}
                row.update({"sha256": hashlib.sha256(value.encode()).hexdigest(), "redacted": True} if family == "TXT" else dns_attributes(family, value))
                if family in {"A", "AAAA"}:
                    row["ownership"] = "Address may be CDN/shared infrastructure; not independently authorized for scanning."
                    chain = []
                    for rrset in getattr(getattr(answer, "response", None), "answer", []):
                        if rrset.rdtype == 5:
                            chain.extend({"from": str(rrset.name).rstrip("."), "to": str(r).rstrip("."), "ttl": rrset.ttl} for r in rrset)
                    row["cname_chain"] = chain[:20]
                rows.append(row)
        except (ValueError, TypeError):
            statuses[family] = "malformed"
        except dns.resolver.NXDOMAIN:
            statuses[family] = "nxdomain"
        except dns.resolver.NoAnswer:
            statuses[family] = "no_answer"
        except dns.exception.Timeout:
            statuses[family] = "timeout"
        except dns.exception.DNSException:
            statuses[family] = "dns_failure"
    addresses = sorted({r["value"] for r in rows if r["type"] in {"A", "AAAA"}})
    summary = {"host": host, "type": "RESOLUTION", "addresses": addresses, "record_statuses": statuses,
               "resolution_status": "partial" if any(s in {"timeout", "dns_failure", "cancelled", "malformed"} for s in statuses.values()) else "resolved" if addresses else "unresolved",
               "resolved_at": utcnow(), "wildcard_status": "not checked", "exclusive_ip_ownership": "Unknown"}
    return rows, summary


def wildcard_control(root, scope, cancel, resolver=None):
    # Two independent labels reduce accidental matches; querying is opt-in and
    # requires the domain wildcard itself to be in the authorized scope.
    import uuid
    signatures = []
    for _ in range(2):
        name = "cyberrecon-control-" + uuid.uuid4().hex + "." + root
        (scope() if callable(scope) else scope).require(name)
        rows, summary = resolve_host(name, scope, cancel, resolver)
        if summary["resolution_status"] == "partial":
            return {"status": "inconclusive", "addresses": []}
        signatures.append({r["value"] for r in rows if r["type"] in {"A", "AAAA"}})
    overlap = signatures[0] & signatures[1]
    return {"status": "possible wildcard" if overlap else "not observed", "addresses": sorted(overlap),
            "note": "Rotating answers and CDN sharing can make this control inconclusive; not proof of ownership."}


def wordlist_hosts(root, words, scope):
    from .scope import host_of
    values = list(dict.fromkeys(words or []))
    if len(values) > 200:
        raise ValidationError("DNS enumeration accepts at most 200 labels.")
    hosts = []
    for value in values:
        import re
        if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", value):
            raise ValidationError("DNS wordlist requires individual hostname labels.")
        host = host_of(value + "." + root)
        (scope() if callable(scope) else scope).require(host)
        hosts.append(host)
    return hosts


def resolve_ip(host, scope, cancel, resolver=None):
    """PTR metadata for an explicitly authorized literal IP; names stay unscoped."""
    import dns.reversename
    load_scope = scope if callable(scope) else lambda: scope
    load_scope().require(host)
    address = str(ipaddress.ip_address(host))
    resolver = resolver or dns.resolver.Resolver(); resolver.lifetime = 3
    rows, status = [], "cancelled" if cancel.is_set() else "no_answer"
    if not cancel.is_set():
        try:
            load_scope().require(host)
            answer = resolver.resolve(dns.reversename.from_address(address), "PTR", search=False)
            rows = [{"host": address, "type": "PTR", "value": str(entry).rstrip('.'), "ttl": answer.rrset.ttl,
                     "resolution_status": "resolved", "authorization": "Discovered name is not automatically authorized"} for entry in answer]
            status = "resolved"
        except dns.resolver.NXDOMAIN:
            status = "nxdomain"
        except dns.resolver.NoAnswer:
            status = "no_answer"
        except dns.exception.Timeout:
            status = "timeout"
        except dns.exception.DNSException:
            status = "dns_failure"
    return rows, {"host": address, "type": "RESOLUTION", "addresses": [address], "record_statuses": {"PTR": status},
                  "resolution_status": "partial" if status in {"timeout", "dns_failure", "cancelled", "malformed"} else "literal_ip",
                  "resolved_at": utcnow(), "wildcard_status": "not applicable", "exclusive_ip_ownership": "Unknown"}
