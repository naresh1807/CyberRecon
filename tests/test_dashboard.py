import json
from pathlib import Path

import httpx
import pytest

from cyberrecon.dashboard import SECTIONS, applicable_ports, dashboard_rows, normalize_target, overview_html
from cyberrecon.scanner import scan
from cyberrecon.storage import Repository


@pytest.mark.parametrize('value,expected', [
    ('qualitythought.in', 'qualitythought.in'),
    (' https://qualitythought.in/a ', 'https://qualitythought.in/a'),
    ('192.0.2.1', '192.0.2.1'), ('2001:db8::1', '2001:db8::1'),
    ('http://[::1]:8080/', 'http://[::1]:8080/'),
])
def test_target_normalization(value, expected):
    assert normalize_target(value) == expected


@pytest.mark.parametrize('value', ['', '-sV', 'bad domain.in', 'ftp://example.org',
    'https://user:password@example.org', 'http://[bad', 'https://example.org:wrong',
    'example.org;id', 'https://example.org\\evil'])
def test_invalid_target(value):
    with pytest.raises(ValueError):
        normalize_target(value)


def test_no_implicit_nmap_ip_authorization():
    assert applicable_ports('qualitythought.in', '80') is None
    assert applicable_ports('https://qualitythought.in/', '80') is None
    assert applicable_ports('http://[::1]:8080', '8080') == '8080'


def test_dashboard_real_storage_partial_and_scope(tmp_path, monkeypatch):
    repo = Repository(tmp_path)
    project = repo.create_project('owned', ['127.0.0.1'], [], 'Owned fixture')
    requests = []
    def respond(request):
        requests.append(str(request.url))
        if request.url.path == '/robots.txt':
            raise httpx.ReadTimeout('fixture timeout')
        return httpx.Response(200, headers={'content-type': 'text/html'}, text='''
          <title>Owned fixture</title><meta name="generator" content="Fixture CMS">
          <script src="/jquery.min.js"></script><a href="https://outside.example/">outside</a>''')
    def missing(*args, **kwargs):
        raise FileNotFoundError('nmap unavailable')
    monkeypatch.setattr('cyberrecon.engines.port_scan', missing)
    identifier = scan(repo, project, 'http://127.0.0.1/', crawl=True, ports='80',
                      transport=httpx.MockTransport(respond))
    snapshot = repo.snapshot(identifier)
    rows = dashboard_rows(snapshot)
    assert snapshot['scan']['status'] == 'partial'
    assert any(row.get('title') == 'Owned fixture' for row in snapshot['http'])
    assert any(row.get('technology') == 'jQuery' and row['confidence'] == 'indicator' and row['classification'] == 'Likely' and row['evidence'] for row in rows['technologies'])
    assert any(row.get('banner') == 'Fixture CMS' for row in rows['technologies'])
    assert rows['evidence'] and not rows['ports']
    assert all(url.startswith('http://127.0.0.1/') for url in requests)
    assert 'http://127.0.0.1/sitemap.xml' in requests
    assert 'No observations' in overview_html(snapshot)
    snapshot['scan']['target'] = '<script>bad</script>'
    assert '<script>' not in overview_html(snapshot)


def test_dnsdumpster_scan_persists_records_with_provenance_and_dashboard_rows(tmp_path, monkeypatch):
    from cyberrecon import dnsdumpster
    from cyberrecon.results import STAGES

    monkeypatch.setenv("DNSDUMPSTER_API_KEY", "FAKE_DNSDUMPSTER_KEY")
    monkeypatch.setattr(dnsdumpster, "_rate_slot", lambda cancel: None)
    repo = Repository(tmp_path)
    project = repo.create_project("owned fixture", ["example.org", "*.example.org"], authority="Mock API only")
    calls = []
    def respond(request):
        calls.append((request.url.host, request.url.path))
        if request.url.host == "api.dnsdumpster.com":
            assert request.headers["x-api-key"] == "FAKE_DNSDUMPSTER_KEY"
            return httpx.Response(200, json={
                "a": [{"host": "www.example.org", "ips": [{"ip": "198.51.100.20", "asn": "64500", "asn_name": "Fixture ASN"}]}],
                "cname": [], "mx": [], "ns": [], "txt": ["private-contact@example.org"], "total_a_recs": 1,
            })
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="owned fixture")

    identifier = scan(repo, project, "https://example.org/", passive="dnsdumpster", crawl=False,
                      transport=httpx.MockTransport(respond), max_hosts=2)
    snapshot = repo.snapshot(identifier)
    assert any(host == "api.dnsdumpster.com" and path == "/domain/example.org" for host, path in calls)
    assert snapshot["scan"]["status"] == "complete"
    assert len(snapshot["dnsdumpster"]) == 2
    assert {row["record_type"] for row in snapshot["dnsdumpster"]} == {"A", "TXT"}
    assert all(row["source"] == "DNSDumpster API" and row["historical"] for row in snapshot["dnsdumpster"])
    assert all(row["verified_current"] is False for row in snapshot["dnsdumpster"])
    assert all(row["observation_status"] == "HISTORICAL" for row in snapshot["dnsdumpster"])
    assert all(row["value_redacted"] for row in snapshot["dnsdumpster"] if row["record_type"] == "TXT")
    assert any(row["kind"] == "dnsdumpster" and row["coverage"]["stage"] == "subdomains"
               for row in snapshot["results"])
    assert STAGES["dnsdumpster"] == "subdomains"
    assert len(dashboard_rows(snapshot)["dnsdumpster"]) == 2
    assert "private-contact" not in json.dumps(snapshot)
    from cyberrecon.reporting import export_reports
    output = Path(export_reports(repo, identifier, tmp_path / "provider-export"))
    assert any(row["kind"] == "dnsdumpster" for row in json.loads((output / "results.json").read_text()))
    assert "dnsdumpster" in (output / "observations.csv").read_text()
    assert "198.51.100.20" in (output / "report.html").read_text()
    assert (output / "report.pdf").read_bytes().startswith(b"%PDF")


def test_dnsdumpster_missing_key_is_visible_as_provider_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("DNSDUMPSTER_API_KEY", raising=False)
    repo = Repository(tmp_path)
    project = repo.create_project("owned fixture", ["example.org"], authority="Mock only")
    requests = []
    def respond(request):
        requests.append(request.url.host)
        assert request.url.host != "api.dnsdumpster.com"
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="owned fixture")
    snapshot = repo.snapshot(scan(repo, project, "https://example.org/", passive="dnsdumpster", crawl=False,
                                  transport=httpx.MockTransport(respond)))
    provider = snapshot["scan"]["settings"]["stages"]["subdomains"]["providers"][0]
    assert provider["status"] == "failed" and provider["code"] == "api_key_missing"
    assert "DNSDUMPSTER_API_KEY" in provider["reason"]
    assert any(row["code"] == "api_key_missing" for row in snapshot["errors"])
    assert not snapshot["dnsdumpster"] and requests


def test_simple_gui_and_authorization_cancel(tmp_path, monkeypatch):
    monkeypatch.setenv('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication, QLineEdit, QInputDialog
    from PySide6.QtCore import QThreadPool
    from cyberrecon.gui import Window
    app = QApplication.instance() or QApplication([])
    window = Window(Repository(tmp_path))
    try:
        window.show()
        app.processEvents()
        assert window.navigation.count() == len(SECTIONS) == 19
        assert [field for field in window.findChildren(QLineEdit) if field.isVisible()] == [window.target]
        monkeypatch.setattr(QInputDialog, 'getText', lambda *args: ('', False))
        window.target.setText('qualitythought.in')
        window.start_scan()
        assert window.worker is None
        assert window.repo.projects() == []
        assert 'authorization reference required' in window.status.text()
    finally:
        window.close()
        QThreadPool.globalInstance().waitForDone(45000)
        app.processEvents()


def test_nmap_metadata_projection():
    from cyberrecon.nmap_scan import parse_scan
    result = parse_scan(b'''<nmaprun version="7.99"><host starttime="10" endtime="11">
      <status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
      <os><osmatch name="fixture hint" accuracy="90"/></os></host>
      <runstats><finished exit="success" elapsed="1.0"/></runstats></nmaprun>''')
    assert result['hosts'][0]['timing'] == {'starttime': '10', 'endtime': '11'}
    assert result['hosts'][0]['os_matches'][0]['accuracy'] == '90'
    assert result['completion']['exit'] == 'success'
    rows = dashboard_rows({'scan': {'warnings': []}, 'assets': [{'host': '127.0.0.1',
        'nmap_host': result['hosts'][0], 'nmap_completion': result['completion']}]})
    assert rows['nmap'][0]['nmap_host']['status'] == 'up'
