"""Independent passive adapters with normalized multi-source provenance."""
from . import engines
from .errors import operation_error
from .scope import host_of
from .models import utcnow, ValidationError
import json

PROVIDERS = ("ct", "dnsdumpster", "subfinder", "assetfinder", "amass")


def enumerate_hosts(providers, root, scope, cancel, limit=5000, transport=None):
    if isinstance(providers, str):
        providers = providers.split(",")
    providers = list(dict.fromkeys(providers or []))
    if any(p not in PROVIDERS for p in providers) or not 1 <= limit <= 5000:
        raise ValidationError("Invalid passive providers or result limit.")
    hosts, outcomes = {}, []
    for provider in providers:
        if cancel.is_set():
            outcomes.append({"provider": provider, "status": "skipped", "reason": "cancelled"}); continue
        outcome = {"provider": provider, "started_at": utcnow(), "status": "complete", "warnings": []}
        accepted = set()
        try:
            if provider == "dnsdumpster":
                names, raw = engines.passive_domains(provider, root, scope, cancel, transport=transport)
            else:
                names, raw = engines.passive_domains(provider, root, scope, cancel)
            if provider == "ct":
                metadata = json.loads(raw)
                outcome["warnings"] = metadata.get("warnings", [])
                if metadata.get("truncated") or outcome["warnings"]:
                    outcome["status"] = "partial"
            if provider == "dnsdumpster":
                metadata = json.loads(raw)
                outcome["warnings"] = metadata.get("warnings", [])
                outcome["records"] = metadata.get("records", [])
                outcome["record_count"] = len(outcome["records"])
                outcome["coverage_note"] = metadata.get("coverage_note", "Provider coverage is not exhaustive.")
                if outcome["warnings"]:
                    outcome["status"] = "partial"
            for value in names:
                try:
                    host = host_of(value)
                except ValueError:
                    continue
                if not scope.allows(host) or not (host == root or host.endswith("." + root)):
                    continue
                if host not in hosts and len(hosts) >= limit:
                    outcome["status"] = "partial"
                    outcome["warnings"] = ["Provider result budget reached."]; break
                hosts.setdefault(host, set()).add(provider)
                accepted.add(host)
            outcome["accepted_total"] = len(accepted)
        except Exception as exc:
            if getattr(exc, "code", None) and type(exc).__name__ == "DNSDumpsterError":
                code, message = exc.code, str(exc)
            else:
                code, message = operation_error(exc)
            outcome.update(status="failed", code=code, reason=message)
        outcome["finished_at"] = utcnow(); outcomes.append(outcome)
    return [{"host": h, "providers": sorted(p), "verified_current": False, "discovered_at": utcnow(),
             "confidence": "passive observation", "note": "Discovery does not prove current resolution, ownership or completeness."}
            for h, p in sorted(hosts.items())], outcomes
