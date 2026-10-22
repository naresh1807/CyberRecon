import json
import threading

import httpx
import pytest

from cyberrecon.network import ScopedHTTP
from cyberrecon.providers import host_lookup
from cyberrecon.scope import Scope
from cyberrecon.storage import Repository


def _dnsdumpster_response():
    return {
        "a": [
            {"host": "example.org", "ips": [{"ip": "203.0.113.10", "asn": "64500",
                "asn_name": "Fixture Network", "asn_range": "203.0.113.0/24", "country": "Test Country",
                "country_code": "ZZ", "ptr": "edge.example.org", "banners": {
                    "https": {"server": "fixture-server", "apps": ["FixtureApp"], "title": "FAKE_DNSDUMPSTER_KEY"}}}]},
            {"host": "www.example.org", "ips": [{"ip": "198.51.100.20"}]},
            {"host": "secret.example.org", "ips": [{"ip": "192.0.2.50"}]},
            {"host": "outside.invalid", "ips": [{"ip": "192.0.2.99"}]},
        ],
        "cname": [{"host": "alias.example.org", "target": "www.example.org"}],
        "mx": [{"host": "mail.example.net", "ips": [{"ip": "198.51.100.30", "asn": "64501"}]}],
        "ns": [{"host": "ns1.example.net", "ips": [{"ip": "198.51.100.31"}]}],
        "txt": ["v=spf1 include:private-contact@example.org", "FAKE_DNSDUMPSTER_KEY"],
        "total_a_recs": 3,
        "unrecognized_private_field": "PRIVATE_PROVIDER_CONTACT",
    }


def test_dnsdumpster_official_api_normalizes_scoped_historical_records(monkeypatch):
    from cyberrecon import dnsdumpster
    from cyberrecon.scope import Scope

    monkeypatch.setenv("DNSDUMPSTER_API_KEY", "FAKE_DNSDUMPSTER_KEY")
    monkeypatch.setattr(dnsdumpster, "_rate_slot", lambda cancel: None)
    calls = []
    def handler(request):
        calls.append(request)
        assert request.url.host == "api.dnsdumpster.com"
        assert request.url.path == "/domain/example.org"
        assert request.headers["x-api-key"] == "FAKE_DNSDUMPSTER_KEY"
        assert request.headers["accept"] == "application/json"
        return httpx.Response(200, json=_dnsdumpster_response())

    hosts, records, metadata = dnsdumpster.lookup(
        "example.org", Scope(["example.org", "*.example.org"], ["secret.example.org"]),
        transport=httpx.MockTransport(handler))
    assert len(calls) == 1
    assert hosts == ["alias.example.org", "example.org", "www.example.org"]
    assert {row["record_type"] for row in records} == {"A", "CNAME", "MX", "NS", "TXT"}
    apex = next(row for row in records if row["record_type"] == "A" and row["host"] == "example.org")
    assert apex["ip"] == "203.0.113.10" and apex["asn"] == "64500"
    assert apex["banners"]["https"]["apps"] == ["FixtureApp"]
    assert not any(row.get("host") == "secret.example.org" for row in records)
    assert not any(row.get("provider_record_host") == "outside.invalid" for row in records)
    txt_rows = [row for row in records if row["record_type"] == "TXT"]
    assert all(row["value_redacted"] and "private-contact" not in row["value"] for row in txt_rows)
    blob = json.dumps(records)
    assert "FAKE_DNSDUMPSTER_KEY" not in blob
    assert "PRIVATE_PROVIDER_CONTACT" not in blob
    assert metadata["returned_records"] == len(records)
    assert metadata["warnings"]
    assert metadata["warnings"]
    assert all(row["verified_current"] is False and row["historical"] is True for row in records)
    assert all(row["reference"] == "https://dnsdumpster.com/developer/" for row in records)


def test_dnsdumpster_missing_key_does_not_make_a_request(monkeypatch):
    from cyberrecon.dnsdumpster import DNSDumpsterError, lookup
    from cyberrecon.scope import Scope

    monkeypatch.delenv("DNSDUMPSTER_API_KEY", raising=False)
    monkeypatch.setattr("cyberrecon.dnsdumpster._rate_slot", lambda cancel: pytest.fail("no request should be made"))
    with pytest.raises(DNSDumpsterError, match="DNSDUMPSTER_API_KEY") as error:
        lookup("example.org", Scope(["example.org"]), transport=httpx.MockTransport(lambda request: pytest.fail("no HTTP request")))
    assert error.value.code == "api_key_missing"


@pytest.mark.parametrize(("status", "code"), [(401, "api_key_rejected"), (403, "api_key_rejected"),
                                                  (429, "rate_limited"), (503, "provider_unavailable")])
def test_dnsdumpster_http_errors_are_safe_and_typed(monkeypatch, status, code):
    from cyberrecon import dnsdumpster
    from cyberrecon.dnsdumpster import DNSDumpsterError, lookup
    from cyberrecon.scope import Scope

    monkeypatch.setenv("DNSDUMPSTER_API_KEY", "FAKE_DNSDUMPSTER_KEY")
    monkeypatch.setattr(dnsdumpster, "_rate_slot", lambda cancel: None)
    def handler(request):
        return httpx.Response(status, text="FAKE_DNSDUMPSTER_KEY PRIVATE_PROVIDER_BODY")
    with pytest.raises(DNSDumpsterError) as error:
        lookup("example.org", Scope(["example.org"]), transport=httpx.MockTransport(handler))
    assert error.value.code == code
    assert "FAKE_DNSDUMPSTER_KEY" not in str(error.value)
    assert "PRIVATE_PROVIDER_BODY" not in str(error.value)


@pytest.mark.parametrize("body", ["not-json", "[]", "{\"a\": \"malformed\"}", "{\"error\": \"unknown\"}"])
def test_dnsdumpster_malformed_provider_payloads_fail_closed(monkeypatch, body):
    from cyberrecon import dnsdumpster
    from cyberrecon.dnsdumpster import DNSDumpsterError, lookup
    from cyberrecon.scope import Scope

    monkeypatch.setenv("DNSDUMPSTER_API_KEY", "FAKE_DNSDUMPSTER_KEY")
    monkeypatch.setattr(dnsdumpster, "_rate_slot", lambda cancel: None)
    with pytest.raises(DNSDumpsterError, match="malformed"):
        lookup("example.org", Scope(["example.org"]), transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text=body)))


def test_dnsdumpster_timeout_and_cancellation_are_reported_without_network_details(monkeypatch):
    from cyberrecon import dnsdumpster
    from cyberrecon.dnsdumpster import DNSDumpsterError, lookup
    from cyberrecon.scope import Scope

    monkeypatch.setenv("DNSDUMPSTER_API_KEY", "FAKE_DNSDUMPSTER_KEY")
    real_rate_slot = dnsdumpster._rate_slot
    monkeypatch.setattr(dnsdumpster, "_rate_slot", lambda cancel: None)
    def timeout(request):
        raise httpx.ReadTimeout("provider error contains FAKE_DNSDUMPSTER_KEY")
    with pytest.raises(DNSDumpsterError) as error:
        lookup("example.org", Scope(["example.org"]), transport=httpx.MockTransport(timeout))
    assert error.value.code == "timeout" and "FAKE_DNSDUMPSTER_KEY" not in str(error.value)

    event = threading.Event(); event.set()
    monkeypatch.setattr(dnsdumpster, "_rate_slot", real_rate_slot)
    with pytest.raises(DNSDumpsterError) as error:
        lookup("example.org", Scope(["example.org"]), cancel=event,
               transport=httpx.MockTransport(lambda request: pytest.fail("cancelled before request")))
    assert error.value.code == "cancelled"


def test_dnsdumpster_rate_slot_waits_two_seconds_and_honors_cancel(monkeypatch):
    from cyberrecon import dnsdumpster

    moments = iter([10.0, 10.25])
    waits = []
    class Cancel:
        def is_set(self): return False
        def wait(self, delay): waits.append(delay); return False
    monkeypatch.setattr(dnsdumpster, "_next_request_at", 12.0)
    monkeypatch.setattr(dnsdumpster, "_clock", lambda: next(moments))
    dnsdumpster._rate_slot(Cancel())
    assert waits == [2.0]
    assert dnsdumpster._next_request_at == 12.25


@pytest.mark.parametrize("provider", ["shodan", "censys"])
def test_provider_normalization_omits_credentials_and_contact_data(tmp_path, monkeypatch, provider):
    repo = Repository(tmp_path)
    project = repo.create_project("Synthetic fixture", ["8.8.8.8"], authority="Mock requests only")
    monkeypatch.setenv("SHODAN_API_KEY", "FAKE_SECRET_API_KEY")
    monkeypatch.setenv("CENSYS_PLATFORM_TOKEN", "FAKE_SECRET_BEARER_TOKEN")
    def handler(request):
        if provider == "shodan":
            assert request.url.params["key"] == "FAKE_SECRET_API_KEY"
            assert request.url.params["minify"] == "true"
            payload = {"ip_str": "8.8.8.8", "ports": [443], "contacts": "PRIVATE_CONTACT"}
        else:
            assert request.headers["authorization"] == "Bearer FAKE_SECRET_BEARER_TOKEN"
            payload = {"result": {"resource": {"ip": "8.8.8.8", "services": [{"port": 443, "transport_protocol": "tcp", "protocol": "HTTPS"}], "whois": "PRIVATE_CONTACT"}}}
        return httpx.Response(200, json=payload)
    identifier = host_lookup(repo, project, "8.8.8.8", provider, transport=httpx.MockTransport(handler))
    snapshot = repo.snapshot(identifier)
    assert snapshot["ports"][0]["port"] == 443
    assert snapshot["ports"][0]["observation_status"] == "HISTORICAL"
    assert "FAKE_SECRET" not in json.dumps(snapshot)
    assert "PRIVATE_CONTACT" not in json.dumps(snapshot)


def test_lookup_checks_scope_before_provider(tmp_path):
    repo = Repository(tmp_path)
    project = repo.create_project("Fixture", ["1.1.1.1"], authority="Mock")
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        host_lookup(repo, project, "8.8.8.8", "shodan")
    assert repo.scans(project) == []


def test_credentialled_redirect_never_reaches_other_host():
    calls = []
    def handler(request):
        calls.append(request.url.host)
        return httpx.Response(302, headers={"location": "https://other.org/"})
    client = ScopedHTTP(lambda: Scope(("example.org", "other.org")), transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="cannot follow cross-host"):
        client.fetch("https://example.org/", request_headers={"Authorization": "Bearer FAKE_TOKEN"})
    assert calls == ["example.org"]


def test_dnsdumpster_api_key_header_cannot_be_sent_to_another_host():
    calls = []
    client = ScopedHTTP(lambda: Scope(("example.org",)),
                        transport=httpx.MockTransport(lambda request: calls.append(request.url.host) or httpx.Response(200)))
    with pytest.raises(ValueError, match="restricted to the DNSDumpster"):
        client.fetch("https://example.org/", request_headers={"X-API-Key": "FAKE_KEY"})
    assert calls == []
