"""Production-readiness defects use deterministic fixtures, never real credentials."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest
from cyberrecon.go_worker import resolve_hosts
from cyberrecon.scope import Scope

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@pytest.mark.parametrize('row', [None, [], 'bad', {'id':'dns','host':'192.0.2.4'},
 {'id':'dns','host':'192.0.2.4','addresses':'192.0.2.4'},
 {'id':'dns','host':'192.0.2.4','addresses':[None]},
 {'id':'dns','host':'192.0.2.4','addresses':['192.0.2.4']*101},
 {'id':'dns','host':'192.0.2.4','addresses':[],'error':True},
 {'id':'dns','host':'192.0.2.4','addresses':['192.0.2.4'],'error':'failed'},
 {'id':'other','host':'192.0.2.4','addresses':[]}])
def test_worker_malformed_results_fail_closed(row, monkeypatch):
    monkeypatch.setattr('cyberrecon.go_worker.worker_path', lambda:'/fixture/worker')
    monkeypatch.setattr('cyberrecon.go_worker.run_process', lambda *a,**k: json.dumps(row).encode())
    with pytest.raises(ValueError): resolve_hosts(['192.0.2.4'],Scope(('192.0.2.0/24',)))

def test_worker_absent_is_explicit(monkeypatch):
    monkeypatch.setattr('cyberrecon.go_worker.worker_path',lambda:None)
    with pytest.raises(ValueError,match='unavailable'): resolve_hosts(['192.0.2.4'],Scope(('192.0.2.0/24',)))

def test_missing_worker_scanner_falls_back(tmp_path, monkeypatch):
    import httpx
    from cyberrecon.scanner import scan
    from cyberrecon.storage import Repository
    monkeypatch.setattr('cyberrecon.go_worker.worker_path',lambda:None)
    repo=Repository(tmp_path);project=repo.create_project('owned',['127.0.0.1'],authority='Own deterministic fixture')
    identifier=scan(repo,project,'http://127.0.0.1/',go_dns=True,transport=httpx.MockTransport(lambda _:httpx.Response(200)))
    snapshot=repo.snapshot(identifier)
    assert snapshot['http'] and any('Go DNS unavailable; using the Python resolver' in warning for warning in snapshot['scan']['warnings'])

def test_default_signing_dry_run_never_touches_secrets(tmp_path,monkeypatch,capsys):
    module=load('sign_cyberrecon_release')
    package=tmp_path/'candidate.deb';package.write_bytes(b'unit artifact')
    output=tmp_path/'output'
    monkeypatch.setattr(sys,'argv',['signer',str(package),'--output',str(output)])
    monkeypatch.setenv('APT_SIGNING_PRIVATE_KEY','opaque-placeholder')
    monkeypatch.setenv('APT_SIGNING_PASSPHRASE','opaque-password')
    monkeypatch.setattr(module,'load_artifact_checker',lambda:SimpleNamespace(check_artifact=lambda _:None))
    monkeypatch.setattr(module,'load_builder',lambda:pytest.fail('Dry run cannot sign'))
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**k:pytest.fail('Dry run cannot execute a signing/publication process'))
    assert module.main()==0
    result=json.loads(capsys.readouterr().out)
    assert result['mode']=='dry-run' and result['signing']=='NOT RUN'
    assert result['publication']==result['deployment']=='DISABLED'
    assert not output.exists()

def test_signing_cannot_bypass_release_gates(tmp_path,monkeypatch,capsys):
    module=load('sign_cyberrecon_release')
    monkeypatch.setattr(sys,'argv',['signer','candidate.deb','--sign','--output',str(tmp_path/'output')])
    for key,value in {'APT_SIGNING_PRIVATE_KEY':'opaque-placeholder','APT_SIGNING_PASSPHRASE':'opaque-password','APT_SIGNING_FINGERPRINT':module.PRODUCTION_FINGERPRINT}.items(): monkeypatch.setenv(key,value)
    def refused(environment): raise ValueError('BLOCKED')
    monkeypatch.setattr(module,'load_release_gate',lambda:SimpleNamespace(production_gate=refused))
    monkeypatch.setattr(module,'load_builder',lambda:pytest.fail('Blocked gate cannot reach signing'))
    with pytest.raises(SystemExit) as result: module.main()
    assert result.value.code==2
    assert 'Mandatory production' in capsys.readouterr().err
    assert not (tmp_path/'output').exists()

def test_signing_temp_cannot_be_inside_artifacts(tmp_path,monkeypatch):
    module=load('sign_cyberrecon_release');output=tmp_path/'output';output.mkdir()
    monkeypatch.setenv('RUNNER_TEMP',str(output))
    for key,value in {'APT_SIGNING_PRIVATE_KEY':'opaque-placeholder','APT_SIGNING_PASSPHRASE':'opaque-password','APT_SIGNING_FINGERPRINT':module.PRODUCTION_FINGERPRINT}.items(): monkeypatch.setenv(key,value)
    monkeypatch.setattr(sys,'argv',['signer','candidate.deb','--sign','--output',str(output)])
    monkeypatch.setattr(module,'load_release_gate',lambda:SimpleNamespace(production_gate=lambda _:None))
    with pytest.raises(SystemExit): module.main()
    assert not list(output.iterdir())

def test_archive_static_checker_needs_no_git(tmp_path,monkeypatch,capsys):
    checker=load('check_release_security')
    (tmp_path/'cyberrecon').mkdir();(tmp_path/'cyberrecon/example.py').write_text('VALUE = 1')
    (tmp_path/'README.md').write_text('Archive fixture')
    monkeypatch.setattr(checker,'ROOT',tmp_path)
    monkeypatch.setattr(sys,'argv',['checker'])
    monkeypatch.setattr(checker.subprocess,'check_output',lambda *a,**k:pytest.fail('No Git in an archive'))
    assert checker.main()==0
    assert json.loads(capsys.readouterr().out)['source_files_checked']==2
    (tmp_path/'cyberrecon/example.py').write_text('import subprocess; subprocess.run(["x"], shell=True)')
    with pytest.raises(ValueError,match='shell=True'): checker.main()

def test_desktop_verifier_navigates_current_gui(tmp_path):
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QThreadPool
    from cyberrecon.gui import Window
    from cyberrecon.storage import Repository
    app=QApplication.instance() or QApplication([])
    window=Window(Repository(tmp_path));window.show()
    verifier=load('verify_cyberrecon_desktop')
    try:
        for name in window.views:
            view=verifier.show_view(window,name);app.processEvents()
            assert view.isVisible(),name
    finally:
        window.advanced.hide();window.close()
        QThreadPool.globalInstance().waitForDone(45000);app.processEvents()

def test_verification_workflow_cannot_publish():
    text=(ROOT/'.github/workflows/verify.yml').read_text()
    assert 'contents: read' in text and 'python -m pytest' in text and 'go test -race' in text
    for forbidden in ['secrets.', 'upload-artifact', 'upload-pages', 'deploy-pages', 'gh release', 'git push', 'pages: write','contents: write','--sign']:
        assert forbidden not in text
    import re
    assert all(re.fullmatch(r'[^@]+@[a-f0-9]{40}',action) for action in re.findall(r'uses: (\S+)',text))


def test_real_reboot_required_for_continuity():
    module=load('verify_cyberrecon_post_reboot')
    before={'boot_id':'boot1','distro':'kali','installed_version':'install ok installed 0.2.0-5','workspace':'/fixture','workspace_state':{'hash':'original'}}
    with pytest.raises(ValueError,match='No real reboot'): module.continuity(before,dict(before))
    after={**before,'boot_id':'boot2'}
    module.continuity(before,after)
    after['workspace_state']={'hash':'changed'}
    with pytest.raises(ValueError,match='workspace_state'): module.continuity(before,after)


def test_lifecycle_runner_refuses_unmarked_host(monkeypatch):
    module=load('qualify_cyberrecon_release')
    monkeypatch.setattr(sys,'argv',['qualify','old.deb','new.deb'])
    monkeypatch.setattr(module.os,'geteuid',lambda:1000)
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**k:pytest.fail('Host package commands prohibited'))
    with pytest.raises(SystemExit) as result: module.main()
    assert result.value.code==2
