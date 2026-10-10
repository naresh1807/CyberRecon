"""Standalone extraction regressions, using no external services."""
import json
import socket
import threading
from types import SimpleNamespace

import httpx
import pytest

from cyberrecon.connectors import Collector, public_address
from cyberrecon.domains import domain
from cyberrecon.models import ValidationError
from cyberrecon.nmap_scan import parse_scan, scan_arguments
from cyberrecon.output import atomic_output
from cyberrecon.scope import Scope
from cyberrecon.web_assessment import header_findings

XML = b'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun version="7.95"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><extraports state="closed" count="99"/><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Example server" version="1.2" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:example:server:1.2</cpe></service><script id="vulners" output="Potential CVE match"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''

@pytest.fixture(autouse=True)
def isolated_rates(monkeypatch):
    monkeypatch.setattr('cyberrecon.connectors._next_request', {})

@pytest.mark.parametrize('value,expected', [(' EXAMPLE.COM. ', 'example.com'), ('bücher.de','xn--bcher-kva.de')])
def test_domain_normalization(value, expected):
    assert domain(value) == expected

@pytest.mark.parametrize('value', ['', 'localhost', 'https://example.com', '-bad.com', 'a..com', 'example.com..', 'example.com\n', '127.0.0.1', 'a'*64+'.com', None])
def test_domain_rejects_invalid(value):
    with pytest.raises(ValidationError): domain(value)

@pytest.mark.parametrize('value', ['--script=all','example.com','127.0.0.1/24','0.0.0.0','224.0.0.1','127.0.0.1,::1','',','.join(f'192.0.2.{i}' for i in range(1,18))])
def test_nmap_targets(value):
    with pytest.raises(ValidationError): scan_arguments(value)

@pytest.mark.parametrize('value', ['0','65536','1-2000','443 --script all','80;whoami','100-20','1-1000,1001'])
def test_nmap_ports(value):
    with pytest.raises(ValidationError): scan_arguments('127.0.0.1',value)

def test_nmap_arguments_and_inventory():
    args, addresses = scan_arguments('::1,::1','443,80,8000-8001')
    assert addresses == ['::1'] and '-6' in args
    assert args[args.index('-p')+1] == '80,443,8000,8001'
    assert '--script' not in args
    data = parse_scan(XML)
    assert data['records'][0]['port'] == 443
    assert data['records'][0]['version'] == '1.2'
    assert data['records'][0]['script_findings'][0]['id'] == 'vulners'
    assert data['hosts'][0]['port_summary'][0]['count'] == '99'

@pytest.mark.parametrize('payload', [b'<broken', b'<other/>', XML.replace(b'exit="success"',b'exit="error"'), XML.replace(b'portid="443"',b'portid="65536"'), b'<!DOCTYPE nmaprun [<!ENTITY x "bad">]><nmaprun>&x;</nmaprun>', '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE nmaprun [<!ENTITY x "bad">]><nmaprun>&x;</nmaprun>'.encode('utf-16'), b'x'*(16*1024*1024+1)])
def test_nmap_invalid_xml(payload):
    with pytest.raises(ValidationError): parse_scan(payload)

def collector(handler):
    return Collector(transport=httpx.MockTransport(handler), sleeper=lambda _:None)

def test_ct_fallback_pagination_scope_and_wildcards():
    calls=[]
    def handler(request):
        calls.append(request)
        if request.url.host == 'crt.sh': return httpx.Response(502)
        if 'after' not in request.url.params:
            return httpx.Response(200,json=[{'id':'cursor/1','dns_names':['example.com','www.example.com','*.dev.example.com','evil-example.com']}])
        assert request.url.params['after']=='cursor/1'
        return httpx.Response(200,json=[])
    result=collector(handler)._collect('ct','example.com')
    assert len(calls)==3 and 'Cert Spotter' in result.source
    assert result.data['concrete_names']==['example.com','www.example.com']
    assert result.data['wildcard_patterns']==['*.dev.example.com']
    assert '502' in result.data['provider_errors']['crt.sh']
    assert not result.data['truncated']

def test_ct_primary_does_not_call_fallback():
    def handler(request):
        assert request.url.host=='crt.sh'
        return httpx.Response(200,json=[])
    assert collector(handler)._collect('ct','example.com').data['concrete_names']==[]

@pytest.mark.parametrize('payload',[{'error':'bad'},[{'dns_names':'bad'}],[{'dns_names':[None]}]])
def test_ct_malformed_fallback(payload):
    with pytest.raises(RuntimeError,match='Malformed Cert Spotter'):
        collector(lambda r:httpx.Response(502) if r.url.host=='crt.sh' else httpx.Response(200,json=payload))._collect('ct','example.com')

def test_ct_page_limit_and_partial_failure():
    def handler(request):
        if request.url.host=='crt.sh': return httpx.Response(502)
        cursor=int(request.url.params.get('after','0'))+1
        return httpx.Response(200,json=[{'id':str(cursor),'dns_names':[f'host{cursor}.example.com']}])
    result=collector(handler)._collect('ct','example.com')
    assert result.data['truncated'] and result.data['certificate_count']==5
    def partial(request):
        if request.url.host=='crt.sh': return httpx.Response(502)
        if 'after' in request.url.params: return httpx.Response(429,headers={'Retry-After':'120'})
        return httpx.Response(200,json=[{'id':'1','dns_names':['www.example.com']}])
    import cyberrecon.connectors as connectors
    connectors._next_request.clear()
    result=collector(partial)._collect('ct','example.com')
    assert result.data['truncated'] and result.data['concrete_names']==['www.example.com']
    assert '120' in result.data['warnings'][0]

@pytest.mark.parametrize('ip',['127.0.0.1','10.0.0.1','169.254.169.254','192.0.2.1','::1','fc00::1','224.0.0.1','ff02::1','fec0::1'])
def test_ct_public_address_policy(monkeypatch,ip):
    monkeypatch.setattr('cyberrecon.connectors.resolve_addresses',lambda *a:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))])
    with pytest.raises(ValidationError,match='public Internet'): public_address('example.com')

@pytest.mark.parametrize('location',['https://other.example/','http://crt.sh/','https://crt.sh:8443/','https://user:secret@crt.sh/'])
def test_ct_unsafe_redirects(location):
    calls=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(302,headers={'location':location})
    with pytest.raises(ValidationError): collector(handler)._request('GET','https://crt.sh/')
    assert len(calls)==1

def test_ct_resource_limits():
    c=collector(lambda _:httpx.Response(200,json=[]))
    c.requests=20
    with pytest.raises(ValidationError,match='request limit'): c._request('GET','https://crt.sh/')
    c.requests=0;c.deadline=0
    with pytest.raises(ValidationError,match='time budget'): c._request('GET','https://crt.sh/')
    c=collector(lambda _:httpx.Response(200,headers={'content-length':str(8*1024*1024+1)}))
    with pytest.raises(ValidationError,match='8 MiB'): c._request('GET','https://crt.sh/')
    c=collector(lambda _:pytest.fail('Cancelled request'))
    c.cancel.set()
    with pytest.raises(ValidationError,match='cancelled'): c._collect('ct','example.com')

def test_ct_tls_pinning_and_mixed_dns_block(monkeypatch):
    clients=[]; requests=[]
    real_client=httpx.Client
    def handler(request):
        requests.append(request)
        assert request.url.host=='8.8.8.8'
        assert request.headers['Host']=='crt.sh'
        assert request.extensions['sni_hostname']=='crt.sh'
        return httpx.Response(200,stream=httpx.ByteStream(b'[]'),headers={'content-type':'application/json'})
    def client(**kwargs):
        clients.append(kwargs)
        assert kwargs['verify'] is True and kwargs['trust_env'] is False and kwargs['follow_redirects'] is False
        kwargs['transport']=httpx.MockTransport(handler)
        return real_client(**kwargs)
    monkeypatch.setattr('cyberrecon.connectors.httpx.Client',client)
    monkeypatch.setattr('cyberrecon.connectors.resolve_addresses',lambda *a:[(2,1,6,'',('8.8.8.8',443))])
    assert Collector(sleeper=lambda _:None)._collect('ct_primary','example.com').data['concrete_names']==[]
    monkeypatch.setattr('cyberrecon.connectors.resolve_addresses',lambda *a:[(2,1,6,'',('8.8.8.8',443)),(2,1,6,'',('127.0.0.1',443))])
    with pytest.raises(ValidationError): Collector(sleeper=lambda _:None)._request('GET','https://crt.sh/')
    assert len(clients)==len(requests)==1

def test_header_findings_and_secret_redaction():
    headers=httpx.Headers([('Strict-Transport-Security','max-age=31536000'),('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'"),('Set-Cookie','session=SECRET; Secure; HttpOnly; SameSite=Lax'),('Set-Cookie','__Host-bad=OTHER; Domain=example.com')])
    rows={r['check']:r for r in header_findings(headers)}
    assert rows['HSTS']['status']=='present'
    assert rows['Framing protection']['status']=='present'
    assert rows['Cookie: session']['status']=='present'
    assert rows['Cookie prefix: __Host-bad']['status']=='review'
    assert 'SECRET' not in json.dumps(rows) and 'OTHER' not in json.dumps(rows)

@pytest.mark.parametrize('headers',[{}, {'strict-transport-security':'max-age=0'}, {'content-security-policy':'frame-ancestors *','x-frame-options':'DENY'}])
def test_header_weak_policies(headers):
    rows={r['check']:r for r in header_findings(headers)}
    assert rows['HSTS']['status']=='review' and rows['Framing protection']['status']=='review'

def test_atomic_output_failure_and_symlink(tmp_path):
    destination=tmp_path/'report';destination.write_text('previous')
    with pytest.raises(RuntimeError):
        with atomic_output(destination) as temporary:
            temporary.write_text('partial')
            raise RuntimeError('writer failed')
    assert destination.read_text()=='previous'
    assert not list(tmp_path.glob('.cyberrecon-export-*'))
    link=tmp_path/'link';link.symlink_to(destination)
    with pytest.raises(ValueError):
        with atomic_output(link): pytest.fail('Symlink write')
    assert destination.read_text()=='previous'

def test_scope_exclusions_and_passive_wildcards():
    scope=Scope(('example.com','*.example.com','192.0.2.0/24'),('secret.example.com','192.0.2.2'))
    assert scope.allows('www.example.com') and scope.allows('192.0.2.1')
    for target in ['secret.example.com','192.0.2.2','evil-example.com']:
        with pytest.raises(ValidationError): scope.require(target)
    assert Scope(('*.example.com',)).allows('example.com',passive=True)
    assert not Scope(('*.example.com',)).allows('example.com')

def test_engine_ct_filters_scope(monkeypatch):
    from cyberrecon.engines import passive_domains
    from cyberrecon.models import Result
    monkeypatch.setattr('cyberrecon.connectors.Collector._collect',lambda *a:Result('fixture','https://crt.sh','example.com',{'concrete_names':['www.example.com','secret.example.com','outside.org'],'warnings':[],'truncated':False}))
    names, raw=passive_domains('ct','example.com',Scope(('*.example.com',),('secret.example.com',)))
    assert names==['www.example.com']
    assert json.loads(raw)['source']=='fixture'


def test_module_cli_cannot_import_legacy_package():
    import subprocess, sys
    code='''import sys
class RejectLegacy:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "cyberintel" or fullname.startswith("cyberintel."):
            raise AssertionError("Legacy dependency: " + fullname)
sys.meta_path.insert(0, RejectLegacy())
from cyberrecon.cli import main
try:
    main(["--version"])
except SystemExit as exc:
    assert exc.code == 0
from cyberrecon import scanner, scope, reporting, graph, intelligence
'''
    result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='0.2.0'
