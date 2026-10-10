"""Engine repair regressions: deterministic fixtures, no external requests."""
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import dns.exception
import httpx
import pytest

from cyberrecon.nmap_scan import scan_arguments, parse_scan
from cyberrecon.engines import port_scan, ToolError
from cyberrecon.scope import Scope
from cyberrecon.storage import Repository
from cyberrecon.scanner import scan
from cyberrecon.fingerprints import detect
from cyberrecon.discovery import normalize_candidates, safe_navigation
from cyberrecon.api import extract
from cyberrecon.dns_inventory import resolve_host, wildcard_control, wordlist_hosts
from cyberrecon.subdomains import enumerate_hosts

XML = b'<nmaprun version="7.99"><scaninfo protocol="tcp" numservices="3" services="1-3"/><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="1"><state state="open"/><service name="http" product="Fixture" version="1.2" extrainfo="public" conf="10" method="probed"/></port><port protocol="tcp" portid="2"><state state="closed"/></port><port protocol="tcp" portid="3"><state state="filtered"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'


def response(url='https://example.org/', kind='text/html', **extras):
    return {'url': url, 'headers': {'content-type': kind}, 'status_code': 200, 'truncated': False, 'body_sha256': 'fixture-hash', **extras}


@pytest.mark.parametrize('profile,version', [('quick', False), ('service', True), ('full', True)])
def test_profiles(profile, version):
    args, hosts = scan_arguments('127.0.0.1', profile=profile, timing=2, host_timeout=60)
    assert ('-sV' in args) == version
    assert '-T2' in args and args[args.index('--host-timeout') + 1] == '60s'
    assert hosts == ['127.0.0.1']
    if profile == 'full':
        assert args[args.index('-p') + 1] == '1-65535'
    else:
        assert args[args.index('--top-ports') + 1] == '100'


@pytest.mark.parametrize('options', [{'profile': 'full', 'ports': '80'}, {'timing': 5}, {'host_timeout': 601}, {'profile': 'bad'}, {'vulnerabilities': True}])
def test_profiles_reject_unbounded_or_unsafe(options):
    with pytest.raises(ValueError):
        scan_arguments('127.0.0.1', **options)


@pytest.mark.parametrize('payload', [XML.replace(b'exit="success"', b'exit="error"'), XML.split(b'<runstats>')[0]])
def test_partial_xml_never_complete(payload):
    result = parse_scan(payload, allow_partial=True)
    assert result['partial'] and result['reported_ports'] == 3 and result['open_ports'] == 1
    assert [r['state'] for r in result['records']] == ['open', 'closed', 'filtered']
    assert result['records'][0]['confidence'] == '10'
    with pytest.raises(ValueError):
        parse_scan(payload)


def test_nmap_timeout_retains_actual_partial_xml(monkeypatch):
    def timeout(args, **kwargs):
        Path(args[args.index('-oX') + 1]).write_bytes(XML.split(b'<runstats>')[0])
        raise ToolError('timeout', 'nmap')
    monkeypatch.setattr('cyberrecon.engines.run_process', timeout)
    parsed, raw = port_scan('127.0.0.1', Scope(['127.0.0.1']), '1-3', unprivileged=True)
    assert parsed['partial'] and parsed['failure_code'] == 'timeout' and raw.endswith(b'</host>')
    assert len(parsed['records']) == 3


def test_nmap_missing_and_privileges(monkeypatch):
    def missing(*args, **kwargs):
        raise ToolError('tool_missing', 'nmap')
    monkeypatch.setattr('cyberrecon.engines.run_process', missing)
    with pytest.raises(ToolError, match='tool_missing'):
        port_scan('127.0.0.1', Scope(['127.0.0.1']))
    with pytest.raises(ValueError, match='privileges'):
        port_scan('127.0.0.1', Scope(['127.0.0.1']), os_detection=True, unprivileged=True)
    with pytest.raises(ValueError, match='TCP only'):
        port_scan('127.0.0.1', Scope(['127.0.0.1']), udp=True, profile='full')


def test_multiple_providers_normalized_and_independent(monkeypatch):
    def provider(name, *args):
        if name == 'subfinder':
            raise ToolError('tool_missing', name)
        if name == 'ct':
            return ['WWW.EXAMPLE.ORG.', 'www.example.org', 'outside.org'], json.dumps({'warnings': [], 'truncated': False}).encode()
        return ['www.example.org', 'api.example.org'], b''
    monkeypatch.setattr('cyberrecon.engines.passive_domains', provider)
    rows, outcomes = enumerate_hosts('ct,subfinder,assetfinder', 'example.org', Scope(['example.org', '*.example.org']), threading.Event())
    assert len(rows) == 2
    assert next(r for r in rows if r['host'] == 'www.example.org')['providers'] == ['assetfinder', 'ct']
    assert outcomes[1]['status'] == 'failed' and outcomes[1]['code'] == 'tool_missing'


class Resolver:
    def resolve(self, host, family, **kwargs):
        if family == 'MX':
            raise dns.exception.Timeout()
        if family == 'NS':
            raise dns.resolver.NXDOMAIN()
        values = {'A': ['192.0.2.1', '192.0.2.2'], 'AAAA': ['2001:db8::1'], 'TXT': ['secret-value'], 'CNAME': ['cdn.example.org.']}.get(family)
        if values is None:
            raise dns.resolver.NoAnswer()
        class Answer(list):
            rrset = SimpleNamespace(ttl=60)
            response = SimpleNamespace(answer=[])
        return Answer(values)


def test_dns_multiple_addresses_failure_status_and_redaction():
    records, summary = resolve_host('www.example.org', Scope(['*.example.org']), threading.Event(), Resolver())
    assert summary['addresses'] == ['192.0.2.1', '192.0.2.2', '2001:db8::1']
    assert summary['record_statuses']['MX'] == 'timeout'
    assert summary['record_statuses']['NS'] == 'nxdomain'
    assert summary['record_statuses']['CAA'] == 'no_answer'
    assert summary['resolution_status'] == 'partial'
    assert records[0]['ttl'] == 60 and 'shared' in records[0]['ownership']
    assert 'secret-value' not in json.dumps(records)


def test_wildcard_control_and_scope():
    class AllAnswers(Resolver):
        def resolve(self, host, family, **kwargs):
            if family in ('MX', 'NS'):
                raise dns.resolver.NoAnswer()
            return super().resolve(host, family, **kwargs)
    result = wildcard_control('example.org', Scope(['*.example.org']), threading.Event(), AllAnswers())
    assert result['status'] == 'possible wildcard' and len(result['addresses']) == 3
    with pytest.raises(ValueError, match='OUT OF SCOPE'):
        wildcard_control('example.org', Scope(['example.org']), threading.Event(), AllAnswers())
    with pytest.raises(ValueError):
        wordlist_hosts('example.org', ['../bad'], Scope(['*.example.org']))


def test_fingerprints_evidence_unknown_version_no_architecture_guess():
    observed = response(headers={'content-type': 'text/html', 'server': 'nginx/1.24.0', 'x-powered-by': 'generic app'})
    rows = detect(observed, '<script src="/jquery-3.7.1.min.js"></script><script src="/_next/static/a.js"></script>', ['laravel_session=PRIVATE_VALUE; Secure'])
    values = {r['technology']: r for r in rows}
    assert values['nginx']['version'] == '1.24.0' and values['jQuery']['version'] == '3.7.1'
    assert values['Laravel']['version'] == 'Unknown' and values['Next.js']['category'] == 'Frontend framework'
    assert values['HTML']['classification'] == 'Confirmed'
    assert all(r['evidence'] and r['classification'] == 'Likely' for r in rows if r['technology'] != 'HTML')
    assert 'PRIVATE_VALUE' not in json.dumps(rows)
    assert detect(response(headers={'server': 'generic', 'content-type': 'text/plain'}), 'SQL database') == []


@pytest.mark.parametrize('url', ['https://example.org/logout', 'https://example.org/delete/1', 'https://example.org/.env', 'https://example.org/secrets.json', 'https://example.org/sign%6fut'])
def test_unsafe_navigation_not_requested(url):
    assert not safe_navigation(url)


def test_discovery_robots_sitemap_js_public_json_scope():
    scope = Scope(['example.org'])
    assert normalize_candidates(response('https://example.org/robots.txt', 'text/plain'), 'Disallow: /unlinked\nSitemap: https://outside.org/a.xml', scope) == [('https://example.org/unlinked', 'robots.txt')]
    values = normalize_candidates(response('https://example.org/sitemap.xml', 'application/xml'), '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>/nested.xml</loc></sitemap></sitemapindex>', scope)
    assert values == [('https://example.org/nested.xml', 'sitemap')]
    values = normalize_candidates(response('https://example.org/app.js', 'application/javascript'), 'fetch("/api/users?token=SECRET"); //# sourceMappingURL=app.js.map', scope)
    assert ('https://example.org/api/users?token=', 'JavaScript route') in values
    assert ('https://example.org/app.js.map', 'JavaScript source map') in values
    assert 'SECRET' not in json.dumps(values)
    assert normalize_candidates(response('https://example.org/routes.json', 'application/json'), '{"endpoint":"/api/health", "secrets":{"url":"/private"}}', scope) == [('https://example.org/api/health', 'public JSON route')]


def test_api_methods_unknown_dedup_no_execution():
    rows = extract(response('https://example.org/app.js', 'application/javascript'), 'axios.post("/api/users"); axios.post("/api/users"); fetch("/api/unknown"); fetch("https://outside.org/api/x");', Scope(['example.org']))
    assert len(rows) == 2
    assert rows[0]['method'] == 'POST' and rows[0]['verification_status'] == 'unverified'
    assert rows[1]['method'] == 'Unknown' and rows[1]['authentication'] == 'Unknown'


def test_openapi_operation_auth_preserved():
    body = json.dumps({'openapi': '3.1.0', 'security': [{'bearer': []}], 'paths': {'/api/items': {'get': {'operationId': 'listItems', 'security': []}, 'delete': {'operationId': 'deleteItems'}}}})
    rows = extract(response('https://example.org/openapi.json', 'application/json'), body, Scope(['example.org']))
    row = next(r for r in rows if r.get('operation_metadata'))
    assert row['methods'] == ['DELETE', 'GET']
    assert row['operation_metadata']['GET']['authentication'] == 'declared none'
    assert row['operation_metadata']['DELETE']['authentication'] == 'declared required'


def test_orchestration_crawl_sources_stages_partial_and_exports(tmp_path, monkeypatch):
    repo = Repository(tmp_path / 'home'); project = repo.create_project('owned', ['127.0.0.1'], authority='Owned fixture')
    requests = []
    def handler(req):
        requests.append(req.url.path)
        pages = {'/': ('text/html', '<a href="/logout">logout</a><form method="POST" action="/delete"></form><script src="/app.js"></script>'),
                 '/robots.txt': ('text/plain', 'Allow: /unlinked'),
                 '/sitemap.xml': ('application/xml', '<sitemapindex><sitemap><loc>/nested.xml</loc></sitemap></sitemapindex>'),
                 '/nested.xml': ('application/xml', '<urlset><url><loc>/deep</loc></url></urlset>'),
                 '/app.js': ('application/javascript', 'axios.post("/api/item"); //# sourceMappingURL=app.js.map'),
                 '/app.js.map': ('application/json', '{"sourcesContent":["PRIVATE_SOURCE"], "route":"/frontend"}')}
        kind, body = pages.get(req.url.path, ('text/plain', 'owned'))
        return httpx.Response(200, headers={'content-type': kind, 'server': 'nginx'}, text=body)
    monkeypatch.setattr('cyberrecon.engines.port_scan', lambda *a, **kw: (_ for _ in ()).throw(ToolError('tool_missing', 'nmap')))
    snap = repo.snapshot(scan(repo, project, 'http://127.0.0.1/', crawl=True, ports='80', max_depth=3, rate=10, transport=httpx.MockTransport(handler)))
    assert snap['scan']['status'] == 'partial' and snap['http'] and snap['technologies']
    assert '/logout' not in requests and '/delete' not in requests
    assert all(p in requests for p in ('/unlinked', '/nested.xml', '/deep', '/app.js.map', '/frontend'))
    assert any(r.get('discovered_by') == 'sitemap' for r in snap['urls'])
    assert any(r.get('method') == 'POST' and r['verification_status'] == 'unverified' for r in snap['apis'])
    assert 'PRIVATE_SOURCE' not in json.dumps(snap)
    stages = snap['scan']['settings']['stages']
    assert stages['nmap']['status'] == 'failed' and stages['http']['status'] == 'complete'
    from cyberrecon.dashboard import dashboard_rows
    views = dashboard_rows(snap)
    assert views['urls'] and views['apis'] and views['backend'] and any(r.get('stage') == 'nmap' for r in views['evidence'])
    from cyberrecon.reporting import export_reports
    export_reports(repo, snap['scan']['id'], tmp_path / 'reports')
    assert json.loads((tmp_path / 'reports/scan.json').read_text())['settings']['stages'] == stages


def test_crawl_depth_and_shared_budget(tmp_path):
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org'], authority='Fixture')
    requests = []
    def handler(req):
        requests.append(req.url.path)
        return httpx.Response(200, headers={'content-type': 'text/html'}, text='<a href="' + req.url.path.rstrip('/') + '/next">next</a>')
    snap = repo.snapshot(scan(repo, project, 'https://example.org/', crawl=True, max_depth=1, max_requests=3, rate=10, transport=httpx.MockTransport(handler)))
    assert len(requests) <= 3 and '/next/next' not in requests
    assert snap['scan']['status'] == 'partial'


def test_cancelled_stages_no_false_success(tmp_path):
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org'], authority='Fixture')
    event = threading.Event(); event.set()
    snap = repo.snapshot(scan(repo, project, 'example.org', cancel=event))
    assert snap['scan']['status'] == 'cancelled'
    assert snap['scan']['settings']['stages']['http']['status'] == 'partial'


def test_full_profile_cannot_claim_coverage_from_success_marker(monkeypatch):
    def execute(args, **kwargs):
        # This finished marker only covers three ports, despite full argv.
        Path(args[args.index('-oX') + 1]).write_bytes(XML)
    monkeypatch.setattr('cyberrecon.engines.run_process', execute)
    parsed, _ = port_scan('127.0.0.1', Scope(['127.0.0.1']), profile='full')
    assert parsed['partial'] and parsed['coverage'][0]['requested_ports'] == 3
    assert parsed['profile']['ports'] == '1-65535'


def test_full_profile_aggregated_coverage_without_fake_port_rows(monkeypatch):
    full = XML.replace(b'numservices="3" services="1-3"', b'numservices="65535" services="1-65535"').replace(b'<ports>', b'<ports><extraports state="closed" count="65532"/>')
    def execute(args, **kwargs):
        Path(args[args.index('-oX') + 1]).write_bytes(full)
    monkeypatch.setattr('cyberrecon.engines.run_process', execute)
    parsed, _ = port_scan('127.0.0.1', Scope(['127.0.0.1']), profile='full')
    assert not parsed['partial'] and parsed['coverage'][0]['coverage_verified']
    assert len(parsed['records']) == 3 and parsed['coverage'][0]['reported_total_ports'] == 65535


def test_dns_scope_rechecked_before_each_query():
    calls = []
    class Revoking(Resolver):
        def resolve(self, *args, **kwargs):
            calls.append(args)
            return super().resolve(*args, **kwargs)
    def scope():
        return Scope(['*.example.org'], ['www.example.org'] if calls else [])
    with pytest.raises(ValueError, match='OUT OF SCOPE'):
        resolve_host('www.example.org', scope, threading.Event(), Revoking())
    assert len(calls) == 1


def test_partial_nmap_scan_persists_service_and_artifact(tmp_path, monkeypatch):
    def execute(args, **kwargs):
        Path(args[args.index('-oX') + 1]).write_bytes(XML.split(b'<runstats>')[0])
        raise ToolError('timeout', 'nmap')
    monkeypatch.setattr('cyberrecon.engines.run_process', execute)
    repo = Repository(tmp_path); project = repo.create_project('owned', ['127.0.0.1'], authority='Fixture')
    snap = repo.snapshot(scan(repo, project, 'http://127.0.0.1/', ports='1-3', transport=httpx.MockTransport(lambda req: httpx.Response(200))))
    assert snap['scan']['status'] == 'partial' and len(snap['services']) == 3
    assert snap['scan']['settings']['stages']['nmap']['status'] == 'partial'
    evidence = snap['services'][0]['evidence']
    assert (repo.home / evidence['path']).read_bytes().endswith(b'</host>')


def test_corrupt_nmap_xml_preserved_but_never_fabricated(tmp_path, monkeypatch):
    def execute(args, **kwargs):
        Path(args[args.index('-oX') + 1]).write_bytes(b'not XML')
        raise ToolError('timeout', 'nmap')
    monkeypatch.setattr('cyberrecon.engines.run_process', execute)
    repo = Repository(tmp_path); project = repo.create_project('owned', ['127.0.0.1'], authority='Fixture')
    snap = repo.snapshot(scan(repo, project, 'http://127.0.0.1/', ports='1-3', transport=httpx.MockTransport(lambda req: httpx.Response(200))))
    assert snap['scan']['status'] == 'partial' and not snap['ports'] and snap['http']
    assert (repo.home / 'scans' / snap['scan']['id'] / 'evidence/nmap-incomplete.xml').read_bytes() == b'not XML'


def test_off_scope_openapi_server_does_not_invent_local_operations():
    data = {'openapi': '3.1.0', 'servers': [{'url': 'https://outside.org'}], 'paths': {'/private': {'get': {}}}}
    rows = extract(response('https://example.org/spec.json', 'application/json'), json.dumps(data), Scope(['example.org']))
    assert not any(r['url'].endswith('/private') for r in rows)
    assert any(r.get('coverage_warning') for r in rows)


def test_cancellation_after_observation_preserves_partial_results(tmp_path):
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org'], authority='Fixture')
    event = threading.Event()
    def handler(req):
        event.set()
        return httpx.Response(200, headers={'content-type': 'text/plain'}, text='Owned response')
    snap = repo.snapshot(scan(repo, project, 'example.org', crawl=True, cancel=event, transport=httpx.MockTransport(handler)))
    assert snap['scan']['status'] == 'cancelled'
    assert snap['scan']['settings']['stages']['http']['status'] == 'partial'
    assert snap['scan']['settings']['stages']['nmap']['status'] == 'skipped'


def test_wordlist_requires_scope_before_any_requests(tmp_path):
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org'], authority='Fixture')
    with pytest.raises(ValueError, match='OUT OF SCOPE'):
        scan(repo, project, 'example.org', dns_words=['www'], transport=httpx.MockTransport(lambda req: pytest.fail('No requests permitted')))
    assert repo.scans(project) == []


def test_dashboard_streams_real_job_without_claiming_completion(tmp_path):
    from cyberrecon.gui import Window
    from cyberrecon.dashboard import SECTIONS
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org'], authority='Fixture')
    window = Window(repo)
    try:
        identifier = repo.start_scan(project, 'example.org', {'stages': {'http': {'status': 'running'}}})
        repo.save(identifier, 'technologies', 'express', {'technology': 'Express', 'category': 'Backend framework', 'version': 'Unknown'}, 'owned fixture')
        window.worker = SimpleNamespace(args=(repo, project, 'example.org'))
        window.running_scan_id = None; window.last_live_refresh = 0
        window.scan_progress('Scan job: ' + identifier)
        assert window.scans.currentData() == identifier
        assert window.cards['technologies'].value.text() == '1'
        assert 'provisional' in window.overview.notice.text()
        assert all(not b.isEnabled() for b in window.overview.export_buttons)
        assert window.result_views['backend'].table.rowCount() == 1
        assert len(SECTIONS) == 18 and ('results', 'All Results') in SECTIONS
    finally:
        window.worker = None; window.close()


def test_selected_target_prioritized_with_host_budget(tmp_path, monkeypatch):
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org', '*.example.org'], authority='Fixture')
    monkeypatch.setattr('cyberrecon.engines.passive_domains', lambda *args: (['a.example.org', 'b.example.org'], b'fixture'))
    observed = []
    def handler(req):
        observed.append(req.url.host)
        return httpx.Response(200)
    snap = repo.snapshot(scan(repo, project, 'example.org', passive='subfinder', max_hosts=1, transport=httpx.MockTransport(handler)))
    assert observed == ['example.org'] and len(snap['subdomains']) == 2
    assert snap['scan']['status'] == 'partial' and snap['scan']['settings']['stages']['http']['status'] == 'partial'


def test_optional_wildcard_scope_failure_keeps_valid_web(tmp_path, monkeypatch):
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org'], authority='Fixture')
    class NoRecords:
        def resolve(self, *args, **kwargs):
            raise dns.resolver.NoAnswer()
    monkeypatch.setattr('cyberrecon.dns_inventory.dns.resolver.Resolver', lambda: NoRecords())
    monkeypatch.setattr('cyberrecon.scanner.ScopedHTTP', lambda *a, **kw: __import__('cyberrecon.network', fromlist=['ScopedHTTP']).ScopedHTTP(*a, **{**kw, 'transport': httpx.MockTransport(lambda req: httpx.Response(200))}))
    snap = repo.snapshot(scan(repo, project, 'example.org', check_wildcard=True))
    assert snap['http'] and snap['scan']['status'] == 'partial'
    assert snap['scan']['settings']['stages']['dns']['wildcard']['status'] == 'failed'


def test_report_export_failure_cannot_leave_scan_complete(tmp_path, monkeypatch):
    repo = Repository(tmp_path); project = repo.create_project('owned', ['example.org'], authority='Fixture')
    monkeypatch.setattr(repo, 'export_json', lambda *args: (_ for _ in ()).throw(PermissionError('Owned export fixture')))
    snap = repo.snapshot(scan(repo, project, 'example.org', transport=httpx.MockTransport(lambda req: httpx.Response(200))))
    assert snap['http'] and snap['scan']['status'] == 'partial'
    assert snap['scan']['settings']['stages']['reports']['status'] == 'failed'
    assert any(r['code'] == 'permission_denied' for r in snap['errors'])
