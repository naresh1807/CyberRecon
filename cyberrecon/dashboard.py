"""Dashboard projections of persisted observations; never expand authorization."""
from collections import Counter
from html import escape
import ipaddress
import json

from .scope import host_of
from .network import clean_url

SECTIONS = (
    ('overview', 'Overview'), ('domains', 'Subdomains'), ('dnsdumpster', 'DNSDumpster'), ('ips', 'IP Addresses'),
    ('nmap', 'Nmap Scan'), ('technologies', 'Technologies'), ('findings', 'Vulnerabilities'),
    ('dns', 'DNS'), ('tls', 'SSL/TLS'), ('web', 'HTTP Headers'),
    ('urls', 'Discovered URLs'), ('apis', 'API Inventory'), ('frontend', 'Frontend'), ('backend', 'Backend'),
    ('screenshots', 'Screenshots'), ('evidence', 'Progress & Coverage'),
    ('history', 'Scan History'), ('results', 'All Results'), ('export', 'Reports'))

VIEW_ALIASES = dict(assets='domains', subdomains='domains', dns='dns', dnsdumpster='dnsdumpster', http='web', ports='nmap',
                    services='nmap', technologies='technologies', urls='urls', apis='apis',
                    javascript='web', historical='web', findings='findings', relationships='evidence',
                    errors='evidence', hosts='ips')


def normalize_target(value):
    if not isinstance(value, str):
        raise ValueError('Enter a URL, fully qualified domain, or IP address.')
    host = host_of(value)
    return clean_url(value.strip()) if '://' in value else host


def applicable_ports(target, ports):
    try:
        ipaddress.ip_address(host_of(target))
    except ValueError:
        return None
    return ports


def dashboard_rows(snapshot):
    rows = {key: [] for key, _ in SECTIONS if key not in ('overview', 'history', 'export')}
    for kind, section in VIEW_ALIASES.items():
        if kind == 'hosts':
            continue
        for record in snapshot.get(kind, []):
            rows[section].append({'record_type': kind, **record})
    for record in snapshot.get('dns', []):
        if record.get('type') in ('A', 'AAAA'):
            rows['ips'].append({'address': record.get('value'), 'hostname': record.get('host'),
                                'authorization': 'Discovery does not authorize an IP scan', **record})
    for record in snapshot.get('assets', []):
        try:
            ipaddress.ip_address(record.get('host', ''))
        except ValueError:
            continue
        rows['ips'].append(record)
        if 'nmap_host' in record:
            rows['nmap'].append(record)
    for record in snapshot.get('technologies', []):
        category = record.get('category', '').lower()
        if any(word in category for word in ('frontend', 'javascript', 'css', 'build tool')):
            rows['frontend'].append(record)
        if any(word in category for word in ('backend', 'server', 'cms', 'cdn', 'api', 'database')):
            rows['backend'].append(record)
    for stage in snapshot['scan'].get('settings', {}).get('stages', {}).values():
        rows['evidence'].append({'record_type': 'stage', **stage})
    rows['evidence'].append({'record_type': 'scan profile', 'started_at': snapshot['scan'].get('started_at'), 'settings': snapshot['scan'].get('settings')})
    rows['ports'] = list(snapshot.get('ports', []))  # Compatibility projection.
    for record in snapshot.get('http', []):
        if record.get('tls'):
            rows['tls'].append({'url': record['url'], 'collected_at': record.get('collected_at'),
                                'source': record.get('source'), **record['tls']})
    rows['evidence'].extend({'record_type': 'warning', 'message': warning}
                            for warning in snapshot['scan'].get('warnings', []))
    return rows


def overview_html(snapshot):
    scan = snapshot['scan']
    esc = lambda value: escape(str(value))
    counts = {'Assets': len(snapshot.get('assets', [])),
              'Open ports': sum(p.get('state') == 'open' for p in snapshot.get('ports', [])),
              'Technologies': len(snapshot.get('technologies', [])), 'Findings': len(snapshot.get('findings', []))}
    cards = ' &nbsp; | &nbsp; '.join(f'<b>{number}</b> {label}' for label, number in counts.items())
    severities = Counter(row.get('severity', 'unspecified') for row in snapshot.get('findings', []))
    settings = scan['settings']
    nmap = ('Not selected / domain target requires separately authorized IP scope' if settings.get('ports') is None
            else 'Observed' if snapshot.get('services') else 'No observations; inspect errors (not proof of closed ports)')
    coverage = [('DNS', 'dns'), ('Web / TLS', 'http'), ('Technology detection', 'technologies'),
                ('Passive discovery', 'subdomains'), ('Security observations', 'findings')]
    details = ''.join(f'<li>{label}: {len(snapshot.get(kind, []))} recorded; '
                      f'{"evidence available" if snapshot.get(kind) else "no data / unavailable or not selected"}</li>'
                      for label, kind in coverage)
    return (f'<h1>{esc(scan["target"])}</h1><p>{esc(scan["status"]).upper()} • {esc(scan["started_at"])}</p>'
            f'<h2>{cards}</h2><p>Findings by severity: {esc(dict(severities))}</p>'
            '<p>Confidence, evidence and verification status are separate. Version observations do not confirm vulnerabilities.</p>'
            f'<h3>Coverage</h3><ul>{details}<li>Nmap: {esc(nmap)}</li></ul>'
            '<p>OS detection and intrusive scripts are not part of the default profile. Empty results do not establish safety.</p>'
            f'<h3>Recorded scope</h3><pre>{esc(json.dumps(scan["scope"], indent=2))}</pre>'
            f'<h3>Scan profile</h3><pre>{esc(json.dumps(settings, indent=2))}</pre>'
            f'<h3>Warnings</h3><pre>{esc(chr(10).join(scan.get("warnings", [])) or "None recorded")}</pre>')


def overview_data(snapshot):
    """Compact display projection. Missing intelligence stays unavailable.

    The original observation is carried separately for row detail inspection.
    Counts represent unique observed assets/services, never confirmed security.
    """
    empty = {'target': 'No target', 'status': 'No scan selected', 'domains': [],
             'ips': [], 'ports': [], 'technologies': [], 'findings': [],
             'information': [('Domain / target', 'Not collected'), ('Resolved IPs', 'Not collected'),
                             ('Registrar', 'Not collected'), ('Nameservers', 'Not collected'),
                             ('Organization', 'Not collected'), ('Creation date', 'Not collected'),
                             ('Last updated', 'Not collected')]}
    if not snapshot:
        return empty
    scan = snapshot['scan']
    target = scan['target']
    addresses, host_addresses = {}, {}
    for row in snapshot.get('dns', []):
        if row.get('type') in ('A', 'AAAA'):
            address = row.get('value')
            try:
                address = str(ipaddress.ip_address(address))
            except (ValueError, TypeError):
                continue
            host = row.get('host', '')
            addresses.setdefault(address, {'hosts': set(), 'record': row})['hosts'].add(host)
            host_addresses.setdefault(host, set()).add(address)
        elif row.get('type') == 'PTR':
            address = row.get('host')
            try:
                address = str(ipaddress.ip_address(address))
            except (ValueError, TypeError):
                continue
            addresses.setdefault(address, {'hosts': set(), 'record': row})['hosts'].add(row.get('value', ''))
    assets = {r.get('host'): r for r in snapshot.get('assets', []) if r.get('host')}
    for host, record in assets.items():
        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            continue
        addresses.setdefault(address, {'hosts': set(), 'record': record})
    domain_records = {r.get('host'): r for r in snapshot.get('subdomains', []) if r.get('host')}
    root = host_of(target)
    for host, record in assets.items():
        if host != root:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                domain_records.setdefault(host, record)
    dns_by_host = {}
    for row in snapshot.get('dns', []): dns_by_host.setdefault(row.get('host'), []).append(row)
    resolutions = {r.get('host'): r for r in snapshot.get('dns', []) if r.get('type') == 'RESOLUTION'}
    domains = []
    for host, record in sorted(domain_records.items()):
        status = ('Active observed' if assets.get(host, {}).get('active_verified') else
                  'Resolved' if host_addresses.get(host) else
                  'Resolution incomplete' if resolutions.get(host, {}).get('resolution_status') == 'partial' else
                  'Unresolved' if resolutions.get(host, {}).get('resolution_status') == 'unresolved' else 'Unverified')
        domains.append({'subdomain': host, 'ip_address': ', '.join(sorted(host_addresses.get(host, []))) or 'Not resolved',
                        'status': status, 'resolution_status': resolutions.get(host, {}).get('resolution_status', 'not checked'),
                        'resolved_at': resolutions.get(host, {}).get('resolved_at', 'Unknown'),
                        'wildcard_status': resolutions.get(host, {}).get('wildcard_status', 'not checked'),
                        '_record': {'discovery': record, 'resolution': resolutions.get(host),
                                    'dns_records': dns_by_host.get(host, [])}})
    ips = [{'address': address, 'hostnames': ', '.join(sorted(v['hosts'] - {''})) or 'Not collected',
            'location': v['record'].get('location') or 'Not collected',
            'asn': v['record'].get('asn') or 'Not collected', '_record': v['record']}
           for address, v in sorted(addresses.items())]
    services = {(r.get('host') or r.get('ip'), r.get('port'), r.get('protocol')): r for r in snapshot.get('services', [])}
    ports = []
    seen = set()
    for row in snapshot.get('ports', []) + snapshot.get('services', []):
        key = row.get('host') or row.get('ip'), row.get('port'), row.get('protocol')
        if key in seen:
            continue
        seen.add(key)
        service = services.get(key, row)
        ports.append({'port': row.get('port', ''), 'protocol': row.get('protocol', 'Unknown'),
                      'service': service.get('service') or row.get('service') or 'Not identified',
                      'version': ' '.join(str(service.get(k) or '') for k in ('product', 'version')).strip() or 'Not collected',
                      'state': row.get('state') or service.get('state') or 'Unknown',
                      '_record': {'port_observation': row, 'service_observation': service}})
    technologies = []
    seen = set()
    for row in snapshot.get('technologies', []):
        name = row.get('technology') or row.get('product') or row.get('banner') or 'Unspecified observation'
        version = row.get('version') or 'Not verified'
        key = str(name), str(version)
        if key not in seen:
            seen.add(key)
            technologies.append({'technology': name, 'version': version, '_record': row})
    findings = [{'severity': r.get('severity') or 'Review',
                 'title': r.get('title') or r.get('check') or r.get('classification') or 'Review observation',
                 'location': r.get('url') or r.get('host') or 'Not recorded', '_record': r}
                for r in snapshot.get('findings', [])]
    nameservers = sorted({r.get('value', '') for r in snapshot.get('dns', []) if r.get('type') == 'NS'} - {''})
    empty.update(target=target, status=scan['status'], domains=domains, ips=ips, ports=ports,
                 technologies=technologies, findings=findings)
    empty['information'] = [('Domain / target', root), ('Resolved IPs', ', '.join(addresses) or 'Not collected'),
                            ('Registrar', 'Not collected'), ('Nameservers', ', '.join(nameservers) or 'Not collected'),
                            ('Organization', 'Not collected'), ('Creation date', 'Not collected'),
                            ('Last updated', 'Not collected')]
    return empty
