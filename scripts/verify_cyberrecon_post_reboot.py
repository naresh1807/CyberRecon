#!/usr/bin/env python3
"""Read-only reboot continuity evidence; never reboots or manages packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def continuity(before, after):
    if before['boot_id'] == after['boot_id']:
        raise ValueError('No real reboot occurred; close/reopen cannot satisfy this check')
    for key in ('distro', 'installed_version', 'workspace', 'workspace_state'):
        if before[key] != after[key]:
            raise ValueError('Post-reboot state differs: ' + key)


def snapshot(home, expected_distro):
    from qualify_cyberrecon_release import workspace_fingerprint
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            release[key] = value.strip('"')
    if release.get('ID') != expected_distro:
        raise ValueError('Unexpected distribution; record real Kali/Parrot separately')
    home = Path(home).resolve(strict=True)
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'distro': release['ID'], 'installed_version': subprocess.check_output(
                ['dpkg-query', '-W', '-f=${Status} ${Version}', 'cyberrecon'], text=True, timeout=10).strip(),
            'workspace': str(home), 'workspace_state': workspace_fingerprint(home)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['before', 'after'])
    parser.add_argument('--distro', required=True, choices=['kali', 'parrot'])
    parser.add_argument('--home', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    marker = Path('/run/cyberrecon-disposable-root')
    if marker.is_symlink() or not marker.is_file() or marker.read_text().strip() != 'RELEASE_TEST_ONLY':
        parser.error('Use a marked disposable VM; this script never creates the marker or reboots.')
    evidence = Path(args.evidence)
    current = snapshot(args.home, args.distro)
    if args.phase == 'before':
        with evidence.open('x') as stream:
            json.dump(current, stream, indent=2)
    else:
        continuity(json.loads(evidence.read_text()), current)
        print(json.dumps({'status': 'PASS', 'check': 'real reboot and logical workspace preservation', 'after': current}))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
