#!/usr/bin/env python3
"""Real owned loopback HTTP/Nmap and DNS qualification; no external scans.

Creates fresh output evidence. DNS records use reserved .test names and an
owned UDP listener. Only the owned HTTP listener's port is Nmap-scanned.
"""
import argparse
import json
from pathlib import Path
import sys
import threading
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists():
        parser.error('Choose a new output directory; existing evidence is preserved')
    output.mkdir(parents=True)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import dns.message
    import dns.rrset
    import dns.resolver
    import dns.rcode
    from cyberrecon.scanner import scan
    from cyberrecon.storage import Repository
    from cyberrecon.scope import Scope
    from cyberrecon.dns_inventory import resolve_host, wildcard_control
    from cyberrecon.reporting import export_reports
    from cyberrecon.models import utcnow

    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            payload, sock = self.request
            query = dns.message.from_wire(payload)
            reply = dns.message.make_response(query)
            question = query.question[0]
            name = str(question.name).rstrip('.')
            family = dns.rdatatype.to_text(question.rdtype)
            values = {'A': ['127.0.0.1', '127.0.0.2'], 'AAAA': ['::1'], 'MX': ['10 mail.owned.test.'],
                      'NS': ['ns.owned.test.'], 'TXT': ['"Owned public verification record"'], 'CAA': ['0 issue "owned.test"']}
            if name.endswith('owned.test'):
                if name == 'alias.owned.test' and family in {'A', 'AAAA', 'CNAME'}:
                    reply.answer.append(dns.rrset.from_text(name + '.', 60, 'IN', 'CNAME', 'owned.test.'))
                    name = 'owned.test'
                if family in values:
                    reply.answer.append(dns.rrset.from_text(name + '.', 60, 'IN', family, *values[family]))
            else:
                reply.set_rcode(dns.rcode.NXDOMAIN)
            sock.sendto(reply.to_wire(), self.client_address)

    class HTTPHandler(BaseHTTPRequestHandler):
        expected_disconnects = 0
        requests = []
        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                type(self).expected_disconnects += 1
        def do_GET(self):
            type(self).requests.append(self.path)
            pages = {
                '/': ('text/html', '<title>Owned engine lab</title><script src="/app.js"></script><script src="/jquery-3.7.1.min.js"></script><a href="/openapi.json">public API</a><a href="/logout">logout</a><form method="POST" action="/delete"></form>'),
                '/robots.txt': ('text/plain', 'Allow: /unlinked\nSitemap: /sitemap.xml'),
                '/sitemap.xml': ('application/xml', '<sitemapindex><sitemap><loc>/nested.xml</loc></sitemap></sitemapindex>'),
                '/nested.xml': ('application/xml', '<urlset><url><loc>/public/page</loc></url></urlset>'),
                '/app.js': ('application/javascript', 'axios.post("/api/items"); const webpackChunk=[]; //# sourceMappingURL=app.js.map'),
                '/app.js.map': ('application/json', '{"version":3,"sources":["owned.js"],"sourcesContent":["OWNED_SOURCE_CONTENT"],"route":"/frontend"}'),
                '/openapi.json': ('application/json', json.dumps({'openapi': '3.1.0', 'paths': {'/api/items': {'get': {'operationId': 'listItems', 'security': []}, 'post': {'operationId': 'createItems', 'security': [{'bearer': []}]}}}})),
                '/api/items': ('application/json', '{"status":"owned fixture"}')}
            kind, body = pages.get(self.path, ('text/plain', 'Owned public fixture'))
            self.send_response(200); self.send_header('Content-Type', kind)
            self.send_header('X-Powered-By', 'Express'); self.end_headers()
            try:
                self.wfile.write(body.encode())
            except (BrokenPipeError, ConnectionResetError):
                type(self).expected_disconnects += 1
        def log_message(self, *args):
            pass
        def do_POST(self):
            raise AssertionError('Discovery must not submit POST operations')

    dns_server = socketserver.ThreadingUDPServer(('127.0.0.1', 0), DNSHandler)
    http_server = ThreadingHTTPServer(('127.0.0.1', 0), HTTPHandler)
    threads = []
    for server in (dns_server, http_server):
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); threads.append(thread)
    report = {'started_at': utcnow(), 'status': 'RUNNING', 'production': 'NOT APPROVED / BLOCKED',
              'scope': 'Only process-owned loopback listeners; DNS .test names are reserved fixtures',
              'http_target': 'http://127.0.0.1:' + str(http_server.server_port) + '/',
              'dns_listener': list(dns_server.server_address), 'checks': {}}
    try:
        resolver = dns.resolver.Resolver(configure=False); resolver.nameservers = ['127.0.0.1']; resolver.port = dns_server.server_address[1]
        scope = Scope(['owned.test', '*.owned.test'])
        rows, summary = resolve_host('alias.owned.test', scope, threading.Event(), resolver)
        assert summary['resolution_status'] == 'resolved' and len(summary['addresses']) == 3
        assert any(row.get('cname_chain') for row in rows)
        assert all(row['ttl'] == 60 for row in rows)
        assert 'Owned public verification record' not in json.dumps(rows)
        control = wildcard_control('owned.test', scope, threading.Event(), resolver)
        assert control['status'] == 'possible wildcard'
        report['checks']['real-owned-dns-multiple-addresses-ttl-cname-redaction-wildcard'] = 'PASS'
        report['dns'] = {'records': rows, 'summary': summary, 'wildcard': control}
        repo = Repository(output / 'workspace')
        project = repo.create_project('Owned engine verification', ['127.0.0.1'], authority='Created and controlled by verification process')
        # Avoid an unrelated system PTR query; forward DNS above is real.
        with patch('dns.resolver.Resolver.resolve', side_effect=dns.resolver.NoAnswer):
            for profile in ('quick', 'service'):
                messages = []
                identifier = scan(repo, project, report['http_target'], crawl=True, max_depth=3, max_pages=30, rate=10,
                                  ports=str(http_server.server_port), nmap_profile=profile, nmap_unprivileged=True, progress=messages.append)
                snapshot = repo.snapshot(identifier)
                assert snapshot['scan']['status'] == 'complete', snapshot['scan']['warnings']
                assert any(r['port'] == http_server.server_port and r['state'] == 'open' for r in snapshot['ports'])
                assert snapshot['scan']['settings']['stages']['nmap']['status'] == 'complete'
                paths = {r['url'].split(str(http_server.server_port), 1)[-1] for r in snapshot['urls'] if r.get('verified')}
                assert all(path in paths for path in ('/unlinked', '/public/page', '/app.js.map', '/frontend'))
                assert '/logout' not in paths and '/delete' not in paths
                assert any(r.get('technology') == 'Express' for r in snapshot['technologies'])
                assert any(r.get('operation_metadata', {}).get('POST', {}).get('authentication') == 'declared required' for r in snapshot['apis'])
                assert 'OWNED_SOURCE_CONTENT' not in json.dumps(snapshot)
                destination = output / (profile + '-reports'); export_reports(repo, identifier, destination)
                (output / (profile + '-progress.json')).write_text(json.dumps(messages, indent=2))
                report['checks'][profile + '-real-http-nmap-xml-crawl-api-fingerprints-exports'] = 'PASS'
                report[profile] = {'scan': identifier, 'status': snapshot['scan']['status'], 'warnings': snapshot['scan']['warnings'],
                                   'ports': snapshot['ports'], 'stages': snapshot['scan']['settings']['stages'],
                                   'counts': {kind: len(snapshot[kind]) for kind in ('http', 'urls', 'apis', 'technologies', 'findings')}}
        report['requests'] = HTTPHandler.requests
        report['expected_nmap_disconnects'] = HTTPHandler.expected_disconnects
        report['not_run'] = ['Real full 65535-port scan', 'Privileged OS/UDP/NSE scans', 'External passive providers', 'Parrot lifecycle', 'Kali lifecycle', 'Production signing']
        report['status'] = 'PASS'
    except Exception as exc:
        report['status'] = 'FAIL'; report['error'] = type(exc).__name__ + ': local qualification assertion/operation failed'
        raise
    finally:
        for server in (dns_server, http_server):
            server.shutdown(); server.server_close()
        for thread in threads:
            thread.join(timeout=3)
        report['finished_at'] = utcnow()
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'checks': report['checks'], 'output': str(output)}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
