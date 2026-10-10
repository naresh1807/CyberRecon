#!/usr/bin/env python3
"""Read-only release inventory. Presence and hashes do not establish trust."""
import argparse
import hashlib
import json
import os
from pathlib import Path

CONFIG_NAMES = ('CYBERRECON_MAINTAINER', 'APT_PUBLIC_URL', 'GITHUB_SHA',
                'RELEASE_QUALIFIED_COMMIT', 'RELEASE_QUALIFICATION_JSON',
                'APT_SIGNING_FINGERPRINT', 'APT_SIGNING_PRIVATE_KEY',
                'APT_SIGNING_PASSPHRASE')


def inspect(directory, environment):
    root = Path(directory)
    manifest = json.loads((root / 'build-manifest.json').read_text())
    artifacts = manifest.get('artifact_sha256')
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError('Manifest must list actual release artifacts')
    for name, expected in artifacts.items():
        if not isinstance(name, str) or Path(name).name != name or name in ('.', '..'):
            raise ValueError('Unsafe artifact name')
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Artifact missing or symlinked')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Artifact digest mismatch')
    return {'artifact_integrity': 'PASS', 'artifact_count': len(artifacts),
            'reviewed_commit_provenance': 'BLOCKED',
            'provenance_note': 'Manifest claims require independent reviewed-commit and build evidence',
            'manifest_source_commit': manifest.get('source_commit'),
            'configuration': {name: 'CONFIGURED' if environment.get(name) else 'MISSING'
                              for name in CONFIG_NAMES},
            'trusted_production_signatures': 'BLOCKED',
            'publication': 'DISABLED', 'deployment': 'DISABLED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    args = parser.parse_args()
    print(json.dumps(inspect(args.directory, os.environ), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
