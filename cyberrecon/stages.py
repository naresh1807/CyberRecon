"""Persisted real stage transitions, independent of progress UI strings."""
from .models import utcnow

NAMES = ("validation", "subdomains", "dns", "http", "technologies", "urls", "apis", "nmap", "normalization", "reports")


class Stages:
    def __init__(self, repository, scan, progress):
        self.repo, self.scan, self.progress = repository, scan, progress
        self.rows = {name: {"stage": name, "status": "skipped", "reason": "not selected or not reached"} for name in NAMES}
        self.persist()

    def persist(self):
        self.repo.update_scan_settings(self.scan, {"stages": self.rows})

    def start(self, name, **details):
        self.rows[name] = {"stage": name, "status": "running", "started_at": utcnow(), **details}
        self.persist(); self.progress("Stage: " + name)

    def finish(self, name, status="complete", **details):
        self.rows[name].update(status=status, finished_at=utcnow(), **details)
        self.persist()

    def close(self, cancelled=False, failed=False):
        for name, row in self.rows.items():
            if row["status"] == "running":
                self.finish(name, "partial" if cancelled else "failed" if failed else "complete",
                            **({"reason": "cancelled; observations preserved"} if cancelled else {}))
