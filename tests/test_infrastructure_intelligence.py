"""Controlled infrastructure projections: no external requests."""
import csv
import hashlib
import json
import threading
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from cyberrecon.dns_inventory import resolve_host
from cyberrecon.gui_components import ResultsTable
from cyberrecon.network import tls_metadata
from cyberrecon.normalization import dns_attributes
from cyberrecon.reporting import export_reports
from cyberrecon.scope import Scope
from cyberrecon.storage import Repository


def test_soa_normalization_privacy():
    row = dns_attributes("SOA", "ns.example.org. person.example.org. 4294967295 300 60 86400 120")
    assert row["primary_nameserver"] == "ns.example.org"
    assert row["serial"] == 4294967295 and row["retry"] == 60
    assert row["responsible_party_sha256"] == hashlib.sha256(b"person.example.org.").hexdigest()
    assert "person" not in json.dumps(row).replace("responsible_party", "")
    assert row["responsible_party_redacted"]


@pytest.mark.parametrize("value", ["ns.example.org. r.example.org. 1 2", "ns.example.org. r.example.org. -1 2 3 4 5",
                                   "ns.example.org. r.example.org. 4294967296 2 3 4 5"])
def test_soa_malformed_rejected(value):
    with pytest.raises(ValueError):
        dns_attributes("SOA", value)


@pytest.mark.parametrize("failure, expected", [(dns.exception.Timeout, "timeout"), (ValueError, "malformed")])
def test_soa_failure_partial_and_cancel(failure, expected):
    class Resolver:
        def resolve(self, host, family, search):
            assert host == "example.org." and search is False
            if family == "SOA":
                raise failure()
            raise dns.resolver.NoAnswer()
    cancel = threading.Event()
    _, summary = resolve_host("example.org", Scope(["example.org"]), cancel, Resolver())
    assert summary["record_statuses"]["SOA"] == expected and summary["resolution_status"] == "partial"
    cancel.set()
    _, summary = resolve_host("example.org", Scope(["example.org"]), cancel, Resolver())
    assert set(summary["record_statuses"].values()) == {"cancelled"}


class Certificate:
    def getpeercert(self, binary=False):
        return b"leaf" if binary else {"issuer": ((("organizationName", "Owned CA"), ("emailAddress", "PRIVATE")),),
                                      "subjectAltName": (("DNS", "example.org"), ("email", "PRIVATE")),
                                      "notBefore": "controlled start", "notAfter": "controlled end"}
    def version(self):
        return "TLSv1.3"
    def cipher(self):
        return ("controlled cipher", "TLSv1.3", 256)


def metadata(certificate):
    return tls_metadata(SimpleNamespace(extensions={"network_stream": SimpleNamespace(get_extra_info=lambda key: certificate)}))


def test_tls_leaf_privacy_and_explicit_protocol_limit():
    row = metadata(Certificate())
    assert row["verified"] and row["issuer"] == {"organizationName": "Owned CA"}
    assert row["subject_alt_names"] == [{"type": "DNS", "value": "example.org"}]
    assert "PRIVATE" not in json.dumps(row)
    assert row["chain_status"].startswith("NOT RUN") and row["chain_sha256"] == []
    assert row["protocol_support_status"].startswith("NOT RUN")


@pytest.mark.parametrize("chain, status", [([b"leaf", b"root"], "verified connection chain observed"),
                                          ([], "unavailable; transport returned no chain"),
                                          (["invalid"], "unavailable; malformed or oversized chain")])
def test_public_chain_api(chain, status):
    cert = Certificate()
    cert.get_verified_chain = lambda: chain
    row = metadata(cert)
    assert row["chain_status"] == status
    if chain and isinstance(chain[0], bytes):
        assert row["chain_sha256"] == [hashlib.sha256(item).hexdigest() for item in chain]


def test_chain_failure_preserves_http_metadata():
    cert = Certificate()
    def unavailable():
        raise OSError("controlled transport failure")
    cert.get_verified_chain = unavailable
    row = metadata(cert)
    assert row["protocol"] == "TLSv1.3" and row["chain_status"].startswith("unavailable")


def test_projection_csv_group_filters_and_uncertainty(tmp_path, monkeypatch):
    repo = Repository(tmp_path / "workspace")
    project = repo.create_project("Owned", ["example.org"], authority="Offline owned fixture")
    scan = repo.start_scan(project, "example.org", {"stages": {"nmap": {"status": "partial"}}})
    repo.save(scan, "assets", "host", {"ip": "192.0.2.1", "os_matches": [{"name": "=potential OS", "accuracy": "95"}]}, "Nmap")
    repo.save(scan, "http", "https://example.org/", {"url": "https://example.org/", "tls": metadata(Certificate()), "body_sha256": "a" * 64}, "HTTP")
    snapshot = repo.snapshot(scan)
    os_result = next(r for r in snapshot["results"] if r["kind"] == "os")
    assert os_result["verification_status"] == "fingerprint; OS not confirmed"
    assert os_result["confidence"] == "tool estimate"
    assert os_result["coverage"]["stage_status"] == "partial"
    assert os_result["original"]["facts"]["accuracy"] == "95"
    tls_result = next(r for r in snapshot["results"] if r["kind"] == "tls")
    assert tls_result["original"]["facts"]["chain_status"].startswith("NOT RUN")
    assert len({r["result_id"] for r in snapshot["results"]}) == len(snapshot["results"])
    monkeypatch.setattr("cyberrecon.graph.export_graph", lambda *args: None)
    export_reports(repo, scan, tmp_path / "reports")
    exported = json.loads((tmp_path / "reports/results.json").read_text())
    with (tmp_path / "reports/results.csv").open(newline="") as stream:
        csv_rows = list(csv.DictReader(stream))
    assert [json.loads(row["details"]) for row in csv_rows] == exported
    assert next(row for row in csv_rows if row["kind"] == "os")["title"].startswith("'=")
    widget = ResultsTable(repo)
    widget.set_records(snapshot["results"])
    combo = widget.selectors["kind"]
    combo.setCurrentIndex(combo.findData("tls"))
    assert len(widget.filtered_records()) == 1 and widget.rows[0]["kind"] == "tls"
    widget.filter.setText("absent fixture")
    assert widget.filtered_records() == []
    widget.close()


def test_results_csv_symlink_rejected(tmp_path):
    repo = Repository(tmp_path / "workspace")
    project = repo.create_project("Owned", ["example.org"], authority="Offline fixture")
    scan = repo.start_scan(project, "example.org", {})
    reports = tmp_path / "reports"
    reports.mkdir()
    original = tmp_path / "protected"
    original.write_text("intact")
    (reports / "results.csv").symlink_to(original)
    with pytest.raises(ValueError, match="symlinks"):
        export_reports(repo, scan, reports)
    assert original.read_text() == "intact"


def test_cloudflare_does_not_claim_waf():
    from cyberrecon.fingerprints import detect
    row = detect({"url": "https://example.org/", "headers": {"server": "cloudflare"}, "body_sha256": "a" * 64}, "")[0]
    assert row["category"] == "CDN indicator" and row["waf_status"].startswith("Unknown")


def test_owned_https_certificate_and_chain(tmp_path):
    """Ephemeral test certificate; no production signing material or remote probe."""
    import datetime
    import ipaddress
    import ssl
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from cyberrecon.network import ScopedHTTP
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Owned test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    certificate_path = tmp_path / "owned-cert.pem"
    key_path = tmp_path / "owned-key.pem"
    certificate_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # Test-only private bytes never leave the disposable test workspace or logs.
    key_path.touch(mode=0o600)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Owned HTTPS fixture")
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        trust = ssl.create_default_context(cafile=str(certificate_path))
        result = ScopedHTTP(lambda: Scope(["127.0.0.1"]), verify=trust).fetch("https://127.0.0.1:" + str(server.server_port))
        row = result["tls"]
        assert result["status_code"] == 200 and row["verified"]
        assert row["issuer"]["organizationName"] == "Owned test CA"
        assert row["subject_alt_names"] == [{"type": "IP Address", "value": "127.0.0.1"}]
        assert row["certificate_sha256"] == hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        if hasattr(ssl.SSLObject, "get_verified_chain"):
            assert row["chain_sha256"] == [row["certificate_sha256"]]
            assert row["chain_status"] == "verified connection chain observed"
        else:
            assert row["chain_status"].startswith("NOT RUN")
        assert row["protocol_support_status"].startswith("NOT RUN")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def test_grouping_across_pages_preserves_originals(tmp_path):
    repo = Repository(tmp_path / "workspace")
    widget = ResultsTable(repo)
    records = [{"hostname": "b.example.org" if i % 2 else "a.example.org", "title": str(i)} for i in range(120)]
    original = json.dumps(records)
    widget.set_records(records)
    widget.grouping.setCurrentIndex(widget.grouping.findData("hostname"))
    assert len(widget.rows) == 50 and {row["hostname"] for row in widget.rows} == {"a.example.org"}
    assert "2 observed groups" in widget.summary.text()
    widget.change_page(1)
    assert len(widget.rows) == 50 and {row["hostname"] for row in widget.rows} == {"a.example.org", "b.example.org"}
    assert json.dumps(records) == original
    widget.close()
