import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from .models import ValidationError, utcnow
from .output import atomic_output
from .scope import Scope

KINDS = ("assets", "subdomains", "dns", "dnsdumpster", "http", "ports", "services", "technologies", "urls", "apis", "javascript", "historical", "findings", "relationships", "errors")


class Repository:
    def __init__(self, home=None):
        self.home = Path(home or os.environ.get("CYBERRECON_HOME") or Path.home() / ".local/share/cyberrecon").expanduser().resolve()
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.home, 0o700)
        self.path = self.home / "cyberrecon.db"
        for name in ("cyberrecon.db", "cyberrecon.db-wal", "cyberrecon.db-shm"):
            path = self.home / name
            if path.is_symlink():
                raise ValidationError("Workspace database and sidecars cannot be symlinks.")
            if path.exists():
                os.chmod(path, 0o600)
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > 3:
                raise ValidationError("Workspace schema is newer than this CyberRecon version.")
            db.executescript("""PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,name TEXT,authority TEXT,scope TEXT,created_at TEXT);
              CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,project_id TEXT REFERENCES projects(id),target TEXT,
                started_at TEXT,finished_at TEXT,status TEXT,scope TEXT,warnings TEXT,settings TEXT);
              CREATE TABLE IF NOT EXISTS observations(scan_id TEXT REFERENCES scans(id),kind TEXT,key TEXT,value TEXT,
                PRIMARY KEY(scan_id,kind,key));
              CREATE TABLE IF NOT EXISTS scope_history(id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT REFERENCES projects(id),scope TEXT,changed_at TEXT,reason TEXT);
              CREATE INDEX IF NOT EXISTS scans_project_started ON scans(project_id,started_at);
              CREATE INDEX IF NOT EXISTS scope_history_project ON scope_history(project_id,id);
              PRAGMA user_version=3;""")
            for row in db.execute("SELECT id,scope,created_at FROM projects WHERE id NOT IN (SELECT project_id FROM scope_history)").fetchall():
                db.execute("INSERT INTO scope_history(project_id,scope,changed_at,reason) VALUES(?,?,?,?)",
                           (row["id"], row["scope"], row["created_at"], "migration snapshot; earlier policy history unavailable"))
        os.chmod(self.path, 0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def create_project(self, name, include, exclude=(), authority=""):
        if not name.strip() or not authority.strip():
            raise ValidationError("Project name and authorization/scope reference are required.")
        scope = Scope(tuple(include), tuple(exclude))
        identifier = str(uuid.uuid4())
        with self.connection() as db:
            db.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (identifier, name.strip(), authority.strip(), json.dumps(scope.to_dict()), utcnow()))
            db.execute("INSERT INTO scope_history(project_id,scope,changed_at,reason) VALUES(?,?,?,?)",
                       (identifier, json.dumps(scope.to_dict()), utcnow(), "project creation"))
        return identifier

    def projects(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM projects ORDER BY created_at DESC")]

    def project(self, identifier):
        with self.connection() as db:
            row = db.execute("SELECT * FROM projects WHERE id=?", (identifier,)).fetchone()
        if not row:
            raise ValidationError("Select an existing project.")
        return dict(row)

    def scope(self, identifier):
        data = json.loads(self.project(identifier)["scope"])
        return Scope(tuple(data["include"]), tuple(data["exclude"]))

    def update_scope(self, identifier, include, exclude=()):
        self.project(identifier)
        scope = Scope(tuple(include), tuple(exclude))
        with self.connection() as db:
            db.execute("UPDATE projects SET scope=? WHERE id=?", (json.dumps(scope.to_dict()), identifier))
            db.execute("INSERT INTO scope_history(project_id,scope,changed_at,reason) VALUES(?,?,?,?)",
                       (identifier, json.dumps(scope.to_dict()), utcnow(), "scope replacement"))

    def scope_history(self, project):
        self.project(project)
        with self.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT scope,changed_at,reason FROM scope_history WHERE project_id=? ORDER BY id", (project,))]
        for row in rows:
            row["scope"] = json.loads(row["scope"])
        return rows

    def start_scan(self, project, target, settings):
        if "://" in target:
            from .network import clean_url
            target = clean_url(target)
        scope = self.scope(project)
        scope.require(target, passive=True)
        identifier = str(uuid.uuid4())
        self.managed_directory("scans", identifier)
        with self.connection() as db:
            db.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?)",
                (identifier, project, target, utcnow(), None, "running", json.dumps(scope.to_dict()), "[]", json.dumps(settings)))
        return identifier

    def managed_directory(self, *parts):
        directory = self.home
        for part in parts:
            if not isinstance(part, str) or part in {"", ".", ".."} or Path(part).name != part:
                raise ValidationError("Invalid managed directory component.")
            directory = directory / part
            if directory.is_symlink():
                raise ValidationError("Managed workspace directories cannot be symlinks.")
            directory.mkdir(exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
        return directory

    def save(self, scan, kind, key, attributes, source, confidence="observed", historical=False):
        if kind not in KINDS or not isinstance(key, str) or not key or len(key) > 8192:
            raise ValidationError("Unknown observation kind or invalid key.")
        now = utcnow()
        with self.connection() as db:
            # Serialize read/merge/write so concurrent sources cannot lose provenance.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM observations WHERE scan_id=? AND kind=? AND key=?", (scan, kind, key)).fetchone()
            previous = json.loads(row[0]) if row else {}
            value = {**previous, **attributes}
            # Preserve distinct collector assertions rather than silently replacing them.
            metadata = {"source_observations", "key", "source", "sources", "collected_at", "first_seen", "last_seen", "asset_id", "confidence", "observation_status"}
            variants = list(previous.get("source_observations", []))
            candidates = []
            if previous and not variants:
                candidates.append((previous, previous.get("source", source), previous.get("confidence", "Unknown")))
            candidates.append((attributes, source, confidence))
            for candidate, origin, level in candidates:
                assertion = {k: v for k, v in candidate.items() if k not in metadata}
                # Collector timestamps do not create a new assertion by themselves.
                stable = {k: v for k, v in assertion.items() if k not in {"detected_at", "resolved_at", "discovered_at", "retrieved_at"}}
                digest = hashlib.sha256(json.dumps([origin, level, stable], sort_keys=True, allow_nan=False).encode()).hexdigest()
                match = next((v for v in variants if v["assertion_id"] == digest), None)
                if match:
                    match["last_seen"] = now
                else:
                    variants.append({"assertion_id": digest, "source": origin, "confidence": level,
                                     "first_seen": now, "last_seen": now, "historical": historical, "attributes": assertion})
            value["source_observations"] = variants
            if isinstance(previous.get("evidence"), list) and isinstance(attributes.get("evidence"), list):
                merged = {json.dumps(v, sort_keys=True): v for v in previous["evidence"] + attributes["evidence"]}
                value["evidence"] = list(merged.values())
            if previous.get("verified") is True and attributes.get("verified") is False:
                value["verification_status"] = previous.get("verification_status", "HTTP observed")
            for flag in ("verified", "active_verified", "verified_current"):
                if previous.get(flag) is True:
                    value[flag] = True
            value.update(key=key, source=source, collected_at=now, last_seen=now,
                         first_seen=previous.get("first_seen", previous.get("collected_at", now)),
                         sources=sorted(set(previous.get("sources", [previous["source"]] if previous else [])) | {source}),
                         asset_id=hashlib.sha256((kind + "\0" + key).encode()).hexdigest(),
                         confidence=confidence,
                         observation_status="HISTORICAL" if historical and previous.get("observation_status") != "CURRENT" else "CURRENT")
            db.execute("INSERT INTO observations VALUES(?,?,?,?) ON CONFLICT(scan_id,kind,key) DO UPDATE SET value=excluded.value",
                       (scan, kind, key, json.dumps(value, allow_nan=False)))
        return value

    def update_scan_settings(self, scan, attributes):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT settings FROM scans WHERE id=?", (scan,)).fetchone()
            if not row:
                raise ValidationError("Scan does not exist.")
            settings = {**json.loads(row[0]), **attributes}
            db.execute("UPDATE scans SET settings=? WHERE id=?", (json.dumps(settings, allow_nan=False), scan))

    def recover(self, project):
        """Explicit operator recovery only: never silently cancel another process."""
        self.project(project)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT id,warnings FROM scans WHERE project_id=? AND status='running'", (project,)).fetchall()
            for row in rows:
                warnings = json.loads(row["warnings"]) + ["Operator marked unfinished scan interrupted; collected observations preserved."]
                db.execute("UPDATE scans SET status='interrupted',finished_at=?,warnings=? WHERE id=?",
                           (utcnow(), json.dumps(warnings), row["id"]))
        for row in rows:
            self.export_json(row["id"], self.managed_directory("scans", row["id"]))
        return [row["id"] for row in rows]

    def scans(self, project):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM scans WHERE project_id=? ORDER BY started_at DESC,rowid DESC", (project,))]

    def snapshot(self, scan):
        with self.connection() as db:
            row = db.execute("SELECT * FROM scans WHERE id=?", (scan,)).fetchone()
            if not row:
                raise ValidationError("Scan does not exist.")
            meta = dict(row)
            records = db.execute("SELECT kind,value FROM observations WHERE scan_id=? ORDER BY kind,key", (scan,)).fetchall()
        for field in ("scope", "warnings", "settings"):
            meta[field] = json.loads(meta[field])
        data = {kind: [] for kind in KINDS}
        for row in records:
            data[row["kind"]].append(json.loads(row["value"]))
        project = self.project(meta["project_id"])
        project["scope_history"] = self.scope_history(meta["project_id"])
        snapshot = {"scan": meta, "project": project, **data}
        from .results import unified_results
        snapshot["results"] = unified_results(snapshot)
        return snapshot

    def finish(self, scan, warnings, failed=False, cancelled=False, *, export=True):
        self.snapshot(scan)
        status = "cancelled" if cancelled else "failed" if failed else "partial" if warnings else "complete"
        with self.connection() as db:
            db.execute("UPDATE scans SET status=?,finished_at=?,warnings=? WHERE id=?", (status, utcnow(), json.dumps(warnings), scan))
        if export:
            self.export_json(scan, self.managed_directory("scans", scan))

    def export_json(self, scan, directory):
        snapshot = self.snapshot(scan)
        directory = Path(os.path.abspath(Path(directory).expanduser()))
        if self.home in directory.parents:
            parts = directory.relative_to(self.home).parts
            if parts[0] == "scans" and "evidence" in parts:
                raise ValidationError("Reports cannot overwrite managed evidence directories.")
            if parts[0] == "scans":
                parent = self.home
                for part in parts:
                    parent = parent / part
                    if parent.is_symlink():
                        raise ValidationError("Managed workspace directories cannot be symlinks.")
        directory = directory.resolve()
        if self.home in directory.parents and "evidence" in directory.relative_to(self.home).parts:
            raise ValidationError("Reports cannot overwrite managed evidence directories.")
        # Allow managed scan exports, but never database/credential replacement.
        if directory == self.path or (directory != self.home and directory.is_file()):
            raise ValidationError("Choose an export directory.")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for kind in (*KINDS, "scan", "project", "results"):
            destination = directory / (kind + ".json")
            if destination.is_symlink():
                raise ValidationError("Export destinations cannot be symlinks.")
            with atomic_output(destination) as temporary:
                temporary.write_text(json.dumps(snapshot[kind], indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
        return str(directory)

    def evidence(self, scan, name, payload):
        self.snapshot(scan)
        if name in {"", ".", ".."} or Path(name).name != name or len(payload) > 16 * 1024 * 1024:
            raise ValidationError("Invalid or oversized tool evidence.")
        directory = self.managed_directory("scans", scan, "evidence")
        path = directory / name
        with atomic_output(path) as temporary:
            temporary.write_bytes(payload)
        return {"path": str(path.relative_to(self.home)), "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}

    def read_evidence(self, scan, descriptor):
        """Read bounded managed evidence after validating path and checksum."""
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("path"), str):
            raise ValidationError("Invalid evidence descriptor.")
        path = Path(descriptor["path"])
        if path.is_absolute() or len(path.parts) != 4 or path.parts[:3] != ("scans", scan, "evidence"):
            raise ValidationError("Evidence must belong to the selected scan.")
        current = self.home
        for part in path.parts:
            if part in {".", ".."}:
                raise ValidationError("Invalid evidence path.")
            current = current / part
            if current.is_symlink():
                raise ValidationError("Evidence paths cannot be symlinks.")
        fd = os.open(current, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            payload = stream.read(16 * 1024 * 1024 + 1)
        if len(payload) > 16 * 1024 * 1024 or len(payload) != descriptor.get("bytes") or hashlib.sha256(payload).hexdigest() != descriptor.get("sha256"):
            raise ValidationError("Evidence size or checksum mismatch.")
        return payload


def compare_snapshots(before, after, *, include_persistent=False):
    if before["scan"]["project_id"] != after["scan"]["project_id"]:
        raise ValidationError("Compare scans from the same project.")
    result = []
    for kind in KINDS:
        left = {row["key"]: row for row in before[kind] if row.get("purpose") != "content discovery negative control" and not row.get("query_variant_id")}
        right = {row["key"]: row for row in after[kind] if row.get("purpose") != "content discovery negative control" and not row.get("query_variant_id")}
        variants = {}
        for side, snapshot in (("before", before), ("after", after)):
            for row in snapshot[kind]:
                if row.get("query_variant_id"):
                    key = row.get("url", "Unknown") + ":" + ",".join(row.get("methods", []))
                    variants.setdefault(key, {"before": [], "after": []})[side].append(row)
        for key, rows in sorted(variants.items()):
            result.append({"kind": kind, "key": key, "status": "INCOMPARABLE" if rows["before"] and rows["after"] else "NEW" if not rows["before"] else "NOT_OBSERVED",
                           **rows, "before_scan_status": before["scan"]["status"], "after_scan_status": after["scan"]["status"],
                           "note": "Query variants are distinct within a scan but their opaque identifiers cannot be compared across scans. Absence does not prove removal."})
        for key in sorted(left.keys() | right.keys()):
            status = "NEW" if key not in left else "NOT_OBSERVED" if key not in right else "CHANGED"
            def stable(row):
                if isinstance(row, list):
                    return [stable(value) for value in row]
                if not isinstance(row, dict):
                    return row
                return {k: stable(v) for k, v in row.items() if k not in {"collected_at", "first_seen", "last_seen", "retrieved_at", "intelligence_generated_at", "evidence", "source_observations", "detected_at", "resolved_at", "discovered_at", "query_variants", "query_variant_id"}
                        and not (k == "url" and row.get("body_sha256") and "cyberrecon-missing-" in str(v))}
            if key in left and key in right and stable(left[key]) == stable(right[key]):
                if not include_persistent:
                    continue
                status = "PERSISTENT"
            result.append({"kind": kind, "key": key, "status": status,
                           "before": left.get(key), "after": right.get(key),
                           "before_scan_status": before["scan"]["status"], "after_scan_status": after["scan"]["status"],
                           "note": "Not observed in this scan does not prove removal; compare coverage/settings and warnings."})
    return result
