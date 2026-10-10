#!/usr/bin/env python3
"""Audit independent source and candidate Python distribution contents."""
import argparse
import ast
import email
import json
from pathlib import Path
import tarfile
import tomllib
import zipfile


def verify(root, artifacts):
    root=Path(root);artifacts=Path(artifacts)
    config=tomllib.loads((root/'pyproject.toml').read_text())
    if config['project']['name']!='cyberrecon' or config['project']['version']!='0.2.0':
        raise ValueError('Unexpected distribution identity')
    if config['project']['scripts']!={'cyberrecon':'cyberrecon.cli:main'} or config['tool']['setuptools']['packages']['find']['include']!=['cyberrecon*']:
        raise ValueError('Unexpected package discovery/entry point')
    sources=list((root/'cyberrecon').rglob('*.py'))
    for p in sources:
        data=p.read_text()
        for node in ast.walk(ast.parse(data)):
            names=[a.name for a in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
            if any(name=='cyberintel' or name.startswith('cyberintel.') for name in names):
                raise ValueError('Legacy runtime import')
        if '/home/naresh/Desktop/CyberIntel' in data:
            raise ValueError('Original checkout path in runtime source')
    wheel=artifacts/'cyberrecon-0.2.0-py3-none-any.whl'
    with zipfile.ZipFile(wheel) as z:
        names=z.namelist()
        if 'cyberrecon/assets/cyberrecon.svg' not in names or any(n.startswith('cyberintel') for n in names):
            raise ValueError('Missing SVG or unexpected legacy package')
        prefix='cyberrecon-0.2.0.dist-info/'
        metadata=email.message_from_bytes(z.read(prefix+'METADATA'))
        if metadata['Name']!='cyberrecon' or metadata['Version']!='0.2.0':
            raise ValueError('Wheel identity mismatch')
        dependencies=metadata.get_all('Requires-Dist',[])
        if any('cyberintel' in d.lower() for d in dependencies): raise ValueError('Legacy wheel dependency')
        if 'cyberrecon = cyberrecon.cli:main' not in z.read(prefix+'entry_points.txt').decode(): raise ValueError('Missing entry point')
        for name in names:
            if not (name.startswith('cyberrecon/') or name.startswith(prefix)):
                raise ValueError('Unrelated wheel payload')
            if b'/home/naresh/Desktop/CyberIntel' in z.read(name): raise ValueError('Original path in wheel')
    with tarfile.open(artifacts/'cyberrecon-0.2.0.tar.gz') as t:
        names=set(t.getnames());base='cyberrecon-0.2.0/'
        required={'USER_MANUAL.md','CYBERRECON.md','scripts/check_release_security.py',
                  'scripts/qualify_cyberrecon_release.py','scripts/verify_release_inputs.py',
                  'workers/dns/main.go','workers/dns/main_test.go','workers/dns/go.mod',
                  '.github/workflows/verify.yml','tests/test_release_readiness.py'}
        if not all(base+n in names for n in required): raise ValueError('Source archive omits required standalone release inputs')
        if any('/cyberintel/' in n or '/.release-qualification/' in n or '/reference/' in n for n in names):
            raise ValueError('Unexpected historical/private source payload')
    return {'status':'PASS','runtime_sources_checked':len(sources),'legacy_runtime_imports':0,
            'metadata_entrypoint_assets':'PASS','source_archive_inputs':'PASS','original_path_required':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--artifacts',required=True)
    args=parser.parse_args()
    print(json.dumps(verify(args.root,args.artifacts),indent=2))
