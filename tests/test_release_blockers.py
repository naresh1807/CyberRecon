"""Integrity inventory rejects tampering and never infers trust from claims."""
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('release_blockers', Path(__file__).resolve().parents[1] / 'scripts/verify_release_blockers.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(tmp_path, name='candidate.deb'):
    (tmp_path / 'candidate.deb').write_bytes(b'candidate')
    (tmp_path / 'build-manifest.json').write_text(json.dumps({'source_commit': 'a' * 40,
        'artifact_sha256': {name: hashlib.sha256(b'candidate').hexdigest()}}))


def test_inventory_does_not_expose_secrets_or_assert_trust(tmp_path):
    fixture(tmp_path)
    report = module.inspect(tmp_path, {'APT_SIGNING_PRIVATE_KEY': 'opaque-private-fixture'})
    assert report['artifact_integrity'] == 'PASS'
    assert report['reviewed_commit_provenance'] == report['trusted_production_signatures'] == 'BLOCKED'
    assert 'opaque-private-fixture' not in json.dumps(report)
    assert report['publication'] == report['deployment'] == 'DISABLED'


def test_inventory_rejects_tampering(tmp_path):
    fixture(tmp_path)
    (tmp_path / 'candidate.deb').write_bytes(b'tampered')
    with pytest.raises(ValueError, match='digest mismatch'): module.inspect(tmp_path, {})


def test_inventory_rejects_path_escape(tmp_path):
    fixture(tmp_path, '../candidate.deb')
    with pytest.raises(ValueError, match='Unsafe'): module.inspect(tmp_path, {})


def test_inventory_rejects_symlink(tmp_path):
    fixture(tmp_path)
    (tmp_path / 'candidate.deb').rename(tmp_path / 'real.deb')
    (tmp_path / 'candidate.deb').symlink_to(tmp_path / 'real.deb')
    with pytest.raises(ValueError, match='symlinked'): module.inspect(tmp_path, {})
