"""Independent passive adapters with normalized multi-source provenance."""
from . import engines
from .errors import operation_error
from .scope import host_of
from .models import utcnow, ValidationError
import json

PROVIDERS = ("ct", "subfinder", "assetfinder", "amass")


def enumerate_hosts(providers, root, scope, cancel, limit=5000):
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
        try:
            names, raw = engines.passive_domains(provider, root, scope, cancel)
            if provider == "ct":
                metadata = json.loads(raw)
                outcome["warnings"] = metadata.get("warnings", [])
                if metadata.get("truncated") or outcome["warnings"]:
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
            outcome["accepted_total"] = len(hosts)
        except Exception as exc:
            code, message = operation_error(exc)
            outcome.update(status="failed", code=code, reason=message)
        outcome["finished_at"] = utcnow(); outcomes.append(outcome)
    return [{"host": h, "providers": sorted(p), "verified_current": False, "discovered_at": utcnow(),
             "confidence": "passive observation", "note": "Discovery does not prove current resolution, ownership or completeness."}
            for h, p in sorted(hosts.items())], outcomes
