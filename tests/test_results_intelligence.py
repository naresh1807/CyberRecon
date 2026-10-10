"""Offline result accuracy, lossless provenance and dashboard regressions."""
import json
from pathlib import Path
import pytest
from PySide6.QtWidgets import QDialog, QTextEdit
from cyberrecon.storage import Repository, compare_snapshots
from cyberrecon.fingerprints import detect
from cyberrecon.dashboard import overview_data
from cyberrecon.api import extract
from cyberrecon.scope import Scope
from cyberrecon.reporting import export_reports
from cyberrecon.gui_components import ResultsTable


@pytest.fixture
def job(tmp_path):
    repo = Repository(tmp_path / "workspace")
    project = repo.create_project("Lab", ["example.org"], authority="Offline controlled fixture")
    identifier = repo.start_scan(project, "example.org", {"nmap_profile": "service", "stages": {"nmap": {"status": "partial"}}})
    return repo, project, identifier


def test_conflicting_assertions_preserved_without_duplicate_rows(job):
    repo, _, identifier = job
    repo.save(identifier, "findings", "f", {"title": "Fixture", "severity": "review", "evidence": [{"rule": 1}]}, "one", confidence="indicator")
    for _ in range(2):
        repo.save(identifier, "findings", "f", {"title": "Fixture", "severity": "info", "evidence": [{"rule": 2}]}, "two", confidence="observed")
    snapshot = repo.snapshot(identifier)
    row = snapshot["findings"][0]
    assert len(snapshot["findings"]) == 1 and len(row["source_observations"]) == 2
    assert row["evidence"] == [{"rule": 1}, {"rule": 2}]
    result = snapshot["results"][0]
    assert result["sources"] == ["one", "two"]
    assert result["confidence_levels"] == ["indicator", "observed"]
    assert result["conflicting_fields"] == ["severity"]
    assert result["verification_status"] == "multiple recorded assertions; review required"
    assert result["asset_id"] and result["result_id"] and result["original"] == row


def test_missing_evidence_is_inconclusive_not_confirmed(job):
    repo, _, identifier = job
    repo.save(identifier, "findings", "f", {"severity": "high"}, "fixture")
    row = repo.snapshot(identifier)["results"][0]
    assert row["evidence"] == "Unknown" and not row["evidence_available"]
    assert row["verification_status"] == "inconclusive: evidence unavailable"
    assert row["description"] == "Unknown"


def test_verified_url_not_downgraded_and_all_sources_preserved(job):
    repo, _, identifier = job
    url = "https://example.org/api/users"
    repo.save(identifier, "urls", url, {"url": url, "verified": True, "verification_status": "HTTP observed"}, "HTTP")
    row = repo.save(identifier, "urls", url, {"url": url, "verified": False, "verification_status": "unverified candidate"}, "JavaScript")
    assert row["verified"] and row["verification_status"] == "HTTP observed"
    assert row["sources"] == ["HTTP", "JavaScript"] and len(row["source_observations"]) == 2


def test_historical_provider_does_not_reclassify_current_observation(job):
    repo, _, identifier = job
    repo.save(identifier, "subdomains", "a.example.org", {"host": "a.example.org", "verified_current": True}, "active")
    row = repo.save(identifier, "subdomains", "a.example.org", {"host": "a.example.org", "verified_current": False}, "ct", historical=True)
    assert row["verified_current"] is True
    assert row["observation_status"] == "CURRENT"
    assert row["source_observations"][-1]["historical"] is True


def test_dns_mapping_failure_timestamp_and_correlation(job):
    repo, _, identifier = job
    repo.save(identifier, "subdomains", "a.example.org", {"host": "a.example.org"}, "fixture")
    for family, address in (("A", "192.0.2.4"), ("AAAA", "2001:db8::4")):
        repo.save(identifier, "dns", family, {"host": "a.example.org", "type": family, "value": address}, "DNS")
    repo.save(identifier, "subdomains", "b.example.org", {"host": "b.example.org"}, "fixture")
    repo.save(identifier, "dns", "failed", {"host": "b.example.org", "type": "RESOLUTION", "resolution_status": "partial", "resolved_at": "2026-10-10T00:00:00Z", "record_statuses": {"A": "timeout"}}, "DNS")
    snapshot = repo.snapshot(identifier)
    result = next(r for r in snapshot["results"] if r["kind"] == "subdomains" and r["hostname"] == "a.example.org")
    assert result["ip_addresses"] == ["192.0.2.4", "2001:db8::4"]
    assert result["related_observation_count"] == 2
    domain = next(r for r in overview_data(snapshot)["domains"] if r["subdomain"] == "b.example.org")
    assert domain["status"] == "Resolution incomplete" and domain["resolved_at"] == "2026-10-10T00:00:00Z"
    assert domain["_record"]["resolution"]["record_statuses"]["A"] == "timeout"


def test_api_observed_get_is_distinct_from_documented_post():
    response = {"url": "https://example.org/api/users", "status_code": 200, "headers": {"content-type": "application/json"}, "truncated": False}
    body = json.dumps({"openapi": "3.1.0", "paths": {"/api/users": {"post": {}}}})
    rows = extract(response, body, Scope(["example.org"]))
    observed = next(r for r in rows if r["classification"] == "observed HTTP surface")
    documented = next(r for r in rows if r["classification"].startswith("documented"))
    assert observed["methods"] == ["GET"]
    assert documented["methods"] == ["POST"] and documented["verification_status"] == "documented, unverified"


def test_conflicting_versions_not_guessed_and_independent_signals():
    response = {"url": "https://example.org/", "headers": {"content-type": "text/html", "server": "cloudflare", "cf-ray": "present"}, "body_sha256": "a" * 64}
    rows = {r["technology"]: r for r in detect(response, '<script src="/jquery-2.0.0.js"></script><script src="/jquery-3.7.1.js"></script>')}
    assert rows["jQuery"]["version"] == "Unknown"
    assert rows["jQuery"]["observed_versions"] == ["2.0.0", "3.7.1"]
    assert rows["jQuery"]["version_status"] == "conflicting public indicators"
    assert rows["Cloudflare"]["confidence"] == "multiple indicators"
    assert len(rows["Cloudflare"]["evidence"]) == 2
    assert not rows["Cloudflare"]["verified_version"]


def test_history_absence_not_removal_and_persistent_optional(job):
    repo, project, identifier = job
    repo.save(identifier, "assets", "a", {"host": "example.org"}, "fixture")
    before = repo.snapshot(identifier)
    second = repo.start_scan(project, "example.org", {})
    repo.finish(second, ["provider failed"])
    after = repo.snapshot(second)
    change = compare_snapshots(before, after)[0]
    assert change["status"] == "NOT_OBSERVED" and change["after_scan_status"] == "partial"
    repo.save(second, "assets", "a", {"host": "example.org"}, "fixture")
    assert compare_snapshots(before, repo.snapshot(second)) == []
    assert compare_snapshots(before, repo.snapshot(second), include_persistent=True)[0]["status"] == "PERSISTENT"


def test_export_consistency_contains_unified_evidence_and_status(job, tmp_path, monkeypatch):
    repo, _, identifier = job
    repo.save(identifier, "ports", "tcp:443", {"host": "192.0.2.4", "port": 443, "protocol": "tcp", "state": "open"}, "Nmap")
    snapshot = repo.snapshot(identifier)
    captured = []
    import reportlab.platypus
    original = reportlab.platypus.SimpleDocTemplate.build
    def capture(self, story, *args, **kwargs):
        captured.extend(p.text for p in story if hasattr(p, "text"))
        return original(self, story, *args, **kwargs)
    monkeypatch.setattr(reportlab.platypus.SimpleDocTemplate, "build", capture)
    out = Path(export_reports(repo, identifier, tmp_path / "exports"))
    assert json.loads((out / "results.json").read_text()) == snapshot["results"]
    assert snapshot["results"][0]["result_id"] in (out / "report.html").read_text()
    assert any(snapshot["results"][0]["result_id"] in text for text in captured)
    assert (out / "report.pdf").read_bytes().startswith(b"%PDF")


def test_evidence_reader_rejects_tamper_cross_scan_and_symlinks(job, tmp_path):
    repo, _, identifier = job
    descriptor = repo.evidence(identifier, "nmap.xml", b"<nmaprun/>")
    assert repo.read_evidence(identifier, descriptor) == b"<nmaprun/>"
    with pytest.raises(ValueError): repo.read_evidence("other", descriptor)
    path = repo.home / descriptor["path"]
    path.write_bytes(b"tampered")
    with pytest.raises(ValueError): repo.read_evidence(identifier, descriptor)
    path.unlink(); target = tmp_path / "other"; target.write_bytes(b"<nmaprun/>"); path.symlink_to(target)
    with pytest.raises(ValueError): repo.read_evidence(identifier, descriptor)


def test_global_search_combined_filters_and_bounded_large_pages(job, qt_application_lifetime, monkeypatch):
    repo, _, identifier = job
    table = ResultsTable(repo)
    records = [{"kind": "apis", "hostname": "example.org", "title": f"route-{n}", "severity": "review" if n % 2 else "info", "confidence": "candidate", "sources": ["JavaScript"], "verification_status": "unverified", "scan_id": identifier, "original": {"path": f"/api/{n}"}} for n in range(5000)]
    table.set_records(records)
    assert table.table.rowCount() == 50 and table.next.isEnabled()
    table.filter.setText("/api/4999")
    assert len(table.rows) == 1 and table.rows[0]["title"] == "route-4999"
    combo = table.selectors["severity"]; combo.setCurrentIndex(combo.findData("info"))
    assert not table.rows
    combo.setCurrentIndex(combo.findData("review")); assert len(table.rows) == 1
    details = []
    monkeypatch.setattr(QDialog, "exec", lambda dialog: details.append(dialog.findChild(QTextEdit).toPlainText()))
    table.details(0, 0)
    assert json.loads(details[0])["original"]["path"] == "/api/4999"
    table.close()


def test_nmap_duplicates_protocols_conflicts_and_partial_xml():
    from cyberrecon.nmap_scan import parse_scan
    xml = b'<nmaprun><host><address addr="192.0.2.4" addrtype="ipv4"/><ports><port portid="53" protocol="tcp"><state state="open"/><service name="domain" conf="8"/></port><port portid="53" protocol="tcp"><state state="open"/><service name="domain" conf="8"/></port><port portid="53" protocol="udp"><state state="open|filtered"/></port></ports></host>'
    parsed = parse_scan(xml, allow_partial=True)
    assert parsed['partial'] and len(parsed['records']) == 2
    assert {r['protocol'] for r in parsed['records']} == {'tcp', 'udp'}
    assert parsed['records'][0]['service_confidence'] == '8'
    changed = xml.replace(b'</ports>', b'<port portid="53" protocol="tcp"><state state="closed"/></port></ports>')
    parsed = parse_scan(changed + b'<runstats><finished exit="success"/></runstats></nmaprun>')
    tcp = next(r for r in parsed['records'] if r['protocol'] == 'tcp')
    assert tcp['state'] == 'unknown' and len(tcp['port_assertions']) == 2
    assert parsed['partial']


def test_query_variants_distinct_private_and_not_http_verified(job):
    from cyberrecon.discovery import RouteRegistry, normalize_candidates
    from cyberrecon.scanner import scan
    import httpx
    registry = RouteRegistry()
    first = registry.remember('/api/users?id=FIRST_PRIVATE', 'https://example.org/', 'HTML')
    second = registry.remember('/api/users?id=SECOND_PRIVATE', 'https://example.org/', 'JavaScript')
    assert first != second
    assert first == registry.remember('/api/users?id=FIRST_PRIVATE', 'https://example.org/', 'sitemap')
    assert len(registry.variants('https://example.org/api/users?id=')) == 2
    assert 'PRIVATE' not in json.dumps(registry.routes)
    response = {'url': 'https://example.org/app.js', 'headers': {'content-type': 'application/javascript'}, 'status_code': 200, 'truncated': False}
    body = 'fetch("/api/users?id=FIRST_PRIVATE"); fetch("/api/users?id=SECOND_PRIVATE");'
    assert len(extract(response, body, Scope(['example.org']), registry=registry)) == 2
    normalize_candidates(response, body, Scope(['example.org']), registry=registry)
    assert len(registry.variants('https://example.org/api/users?id=')) == 2
    repo, project, _ = job
    requests = []
    def respond(request):
        requests.append(str(request.url))
        return httpx.Response(200, headers={'content-type': 'text/html'}, text='<a href="/users?id=FIRST_PRIVATE">one</a><a href="/users?id=SECOND_PRIVATE">two</a>')
    identifier = scan(repo, project, 'https://example.org/', ports=None, max_pages=2, max_depth=1, transport=httpx.MockTransport(respond))
    snapshot = repo.snapshot(identifier)
    url = next(r for r in snapshot['urls'] if r['url'] == 'https://example.org/users?id=')
    assert len(url['query_variants']) == 2
    variants = [r for r in snapshot['results'] if r['kind'] == 'urls' and r['query_variant_id']]
    assert len(variants) == 2 and all(r['verification_status'].startswith('unverified query variant') for r in variants)
    assert 'PRIVATE' not in json.dumps(snapshot) and 'PRIVATE' not in json.dumps(requests)


def test_query_variant_history_cannot_claim_cross_scan_persistence(job):
    repo, project, identifier = job
    ids = [identifier, repo.start_scan(project, 'example.org', {})]
    for number, sid in enumerate(ids):
        repo.save(sid, 'apis', 'https://example.org/api?a=:GET:' + str(number), {'url': 'https://example.org/api?a=', 'methods': ['GET'], 'query_variant_id': str(number)}, 'fixture')
    result = compare_snapshots(repo.snapshot(ids[0]), repo.snapshot(ids[1]))
    assert len(result) == 1 and result[0]['status'] == 'INCOMPARABLE'


def test_close_defers_until_local_worker_signals_are_drained(job, qt_application_lifetime, monkeypatch):
    import threading, time
    from cyberrecon.gui import Window
    monkeypatch.setattr('cyberrecon.gui.doctor', lambda _: {'status': 'fixture'})
    repo, _, _ = job
    window = Window(repo); window.show(); qt_application_lifetime.processEvents()
    release = threading.Event(); completed = []
    def finish_local_task():
        assert release.wait(5)
        return "finished"
    window.local_task(finish_local_task, lambda result: completed.append(result))
    window.close()
    assert window.isVisible() and window._closing and not window.isEnabled()
    release.set()
    deadline = time.monotonic() + 5
    while window.isVisible() and time.monotonic() < deadline:
        qt_application_lifetime.processEvents(); time.sleep(.01)
    assert completed == ["finished"] and not window.local_jobs and not window.isVisible()


@pytest.mark.parametrize('url', [None, ['not-a-url'], 'https://[invalid/'])
def test_optional_invalid_fields_are_unknown_and_original_preserved(job, url):
    repo, _, identifier = job
    repo.save(identifier, 'findings', 'malformed', {'url': url, 'host': {'invalid': True}, 'port': None, 'severity': None}, 'fixture')
    row = repo.snapshot(identifier)['results'][0]
    assert row['url'] == row['hostname'] == row['port'] == row['severity'] == 'Unknown'
    assert row['original']['url'] == url
