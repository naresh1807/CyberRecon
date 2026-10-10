"""Verify shipped tests retain their support fixtures in the actual sdist."""
import subprocess
import sys
import tarfile
from pathlib import Path


def test_sdist_contains_complete_test_support(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, '-m', 'build', '--sdist', '--no-isolation', '--outdir', str(tmp_path)],
                            cwd=root, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, 'Local offline source archive build failed'
    archives = list(tmp_path.glob('*.tar.gz'))
    assert len(archives) == 1
    with tarfile.open(archives[0]) as archive:
        members = {member.name.split('/', 1)[-1]: member for member in archive.getmembers() if member.isfile()}
        # Tests and shared fixtures must ship together, including conftest.py.
        files = list((root / 'tests').glob('*.py'))
        assert any(path.name == 'conftest.py' for path in files)
        for path in files:
            name = 'tests/' + path.name
            assert name in members, 'Missing source test/support module: ' + name
            assert archive.extractfile(members[name]).read() == path.read_bytes()
