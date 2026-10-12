"""Release refusal and provider failures: offline, no production signing."""
import importlib.util
import json
from pathlib import Path
import subprocess
import httpx
import pytest

from cyberrecon.providers import host_lookup
from cyberrecon.storage import Repository

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.mark.parametrize("gate", ["full_range_nmap", "privileged_nmap", "external_providers", "source_provenance", "reproducibility"])
@pytest.mark.parametrize("status", ["BLOCKED", "FAIL", "NOT RUN", "SKIPPED", "CANCELLED"])
def test_required_new_gates_fail_closed(gate, status):
    prepare = module("prepare_cyberrecon_release")
    assert gate in prepare.REQUIRED_GATES
    env = {"CYBERRECON_MAINTAINER": "Synthetic fixture <fixture@example.test>",
           "APT_PUBLIC_URL": "https://example.test/apt", "GITHUB_SHA": "a" * 40, "RELEASE_QUALIFIED_COMMIT": "a" * 40}
    evidence = {"decision": "APPROVED", "source_tree_dirty": False, "commit": "a" * 40,
                "version": "0.2.0", "package_version": "0.2.0-5",
                "gates": {g: {"status": "PASS", "evidence": "Synthetic unit fixture only"} for g in prepare.REQUIRED_GATES}}
    evidence["gates"][gate]["status"] = status
    with pytest.raises(ValueError, match="Every mandatory"):
        prepare.production_gate(env, evidence)


@pytest.mark.parametrize("status", ["EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED", "KEYREVOKED", "BADSIG", "NO_PUBKEY"])
def test_signature_status_refuses_expired_or_revoked_even_with_validsig(tmp_path, monkeypatch, status):
    verifier = module("verify_cyberrecon_apt")
    fingerprint = "a" * 40
    stdout = "[GNUPG:] VALIDSIG " + fingerprint + " fixture\n[GNUPG:] " + status + " fixture\n"
    monkeypatch.setattr(verifier.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout, ""))
    with pytest.raises(ValueError, match="Expired, revoked"):
        verifier.signature(tmp_path / "public.gpg", fingerprint, tmp_path / "signature", None)


@pytest.fixture
def provider_job(tmp_path, monkeypatch):
    repo = Repository(tmp_path / "workspace")
    project = repo.create_project("Controlled", ["8.8.8.8"], authority="Mock transport only, no target request")
    monkeypatch.setenv("SHODAN_API_KEY", "SYNTHETIC_PROVIDER_CREDENTIAL")
    monkeypatch.setenv("CENSYS_PLATFORM_TOKEN", "SYNTHETIC_PROVIDER_CREDENTIAL")
    return repo, project


@pytest.mark.parametrize("provider", ["shodan", "censys"])
@pytest.mark.parametrize("failure", [httpx.ConnectError, httpx.ReadTimeout, OSError])
def test_provider_network_errors_hide_request_and_secret(provider_job, provider, failure):
    repo, project = provider_job
    calls = []
    def handler(request):
        calls.append(request)
        raise failure("SYNTHETIC_PROVIDER_CREDENTIAL echoed in a transport exception")
    with pytest.raises(ValueError, match="network or TLS") as exc:
        host_lookup(repo, project, "8.8.8.8", provider, transport=httpx.MockTransport(handler))
    assert "SYNTHETIC_PROVIDER_CREDENTIAL" not in str(exc.value)
    assert len(calls) == 1 and repo.scans(project) == []


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_provider_http_failure_no_retry_or_import(provider_job, status):
    repo, project = provider_job
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, text="SYNTHETIC_PROVIDER_CREDENTIAL")
    with pytest.raises(ValueError, match="unavailable") as exc:
        host_lookup(repo, project, "8.8.8.8", "shodan", transport=httpx.MockTransport(handler))
    assert "SYNTHETIC_PROVIDER_CREDENTIAL" not in str(exc.value)
    assert len(calls) == 1 and repo.scans(project) == []


def test_malformed_provider_json_error_generic(provider_job):
    repo, project = provider_job
    with pytest.raises(ValueError, match="Malformed provider JSON") as exc:
        host_lookup(repo, project, "8.8.8.8", "censys", transport=httpx.MockTransport(lambda request: httpx.Response(200, text="invalid")))
    assert repo.scans(project) == []


def test_provider_echoed_credential_and_unrelated_fields_not_exported(provider_job):
    repo, project = provider_job
    payload = {"result": {"resource": {"ip": "8.8.8.8",
        "services": [{"port": 443, "transport_protocol": "tcp", "protocol": "SYNTHETIC_PROVIDER_CREDENTIAL",
                      "scan_time": "SYNTHETIC_PROVIDER_CREDENTIAL"}], "person": "unrelated fixture data"}}}
    scan = host_lookup(repo, project, "8.8.8.8", "censys", transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload)))
    snapshot = repo.snapshot(scan)
    assert "SYNTHETIC_PROVIDER_CREDENTIAL" not in json.dumps(snapshot)
    assert "unrelated fixture data" not in json.dumps(snapshot)
    assert snapshot["ports"][0]["service"] == "Unknown"


@pytest.mark.parametrize("parent,current,uid,expected", [
    ("net:[1]", "net:[2]", 0, True), ("", "net:[2]", 0, False),
    ("net:[1]", "net:[1]", 0, False), ("net:[1]", "net:[2]", 1000, False),
    ("invented", "net:[2]", 0, False)])
def test_namespace_verifier_requires_distinct_valid_names(parent, current, uid, expected):
    assert module("verify_cyberrecon_nmap_namespace").isolated(parent, current, uid) is expected


def test_startup_verifier_clean_process_exit(tmp_path):
    import os
    import sys
    result = subprocess.run([sys.executable, str(ROOT / "scripts/verify_cyberrecon_startup.py")],
                            capture_output=True, text=True, timeout=60,
                            env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 0, result.stderr
    assert "startup/event-loop shutdown: PASS" in result.stdout


def test_sdist_normalization_preserves_payload_and_is_byte_reproducible(tmp_path):
    import io
    import tarfile
    from cyberrecon_build import normalize_archive
    archives = []
    for index in (1, 2):
        path = tmp_path / f"candidate-{index}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name in ("project/z.txt", "project/a.txt"):
                member = tarfile.TarInfo(name)
                member.mtime = index
                member.uid = index
                member.mode = 0o664
                payload = name.encode()
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        normalize_archive(path, 1700000000)
        archives.append(path)
        with tarfile.open(path) as archive:
            assert archive.getnames() == ["project/a.txt", "project/z.txt"]
            for member in archive:
                assert member.mtime == 1700000000 and member.uid == member.gid == 0 and member.mode == 0o644
                assert archive.extractfile(member).read() == member.name.encode()
    assert archives[0].read_bytes() == archives[1].read_bytes()


def test_sdist_symlink_member_rejected_without_replacing_input(tmp_path):
    import tarfile
    from cyberrecon_build import normalize_archive
    path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("project/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/outside"
        archive.addfile(member)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="Unsafe"):
        normalize_archive(path, 1700000000)
    assert path.read_bytes() == before


@pytest.mark.parametrize("epoch", [-1, 4294967296, True, "invalid"])
def test_sdist_invalid_epoch_rejected(tmp_path, epoch):
    from cyberrecon_build import normalize_archive
    with pytest.raises(ValueError, match="unsigned"):
        normalize_archive(tmp_path / "absent.tar.gz", epoch)


def test_provenance_digest_covers_packaged_documents(tmp_path, monkeypatch):
    prepare = module("prepare_cyberrecon_release")
    for name in ("pyproject.toml", "MANIFEST.in", "cyberrecon_build.py", "LICENSE", "README.md", "USER_MANUAL.md", "CYBERRECON.md"):
        (tmp_path / name).write_text("Controlled source fixture")
    (tmp_path / "docs").mkdir()
    document = tmp_path / "docs/readiness.md"
    document.write_text("First report")
    (tmp_path / "workers").mkdir()
    worker_document = tmp_path / "workers/README.md"
    worker_document.write_text("Worker help")
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setattr(prepare, "ROOT", tmp_path)
    def source_digest():
        prepare.build_manifest(output)
        return json.loads((output / "build-manifest.json").read_text())["source_sha256"]
    first = source_digest()
    document.write_text("Updated report")
    second = source_digest()
    assert first != second
    worker_document.write_text("Updated worker help")
    assert source_digest() != second


@pytest.mark.parametrize("failure", [False, True])
def test_quit_during_diagnostics_drains_signals_before_widget_destruction(tmp_path, failure):
    """Exercise app.quit before either successful or failing diagnostics complete."""
    import os
    import sys
    program = r'''import sys, tempfile, time
from PySide6.QtCore import QTimer, QThreadPool
from PySide6.QtWidgets import QApplication
import cyberrecon.gui as gui
from cyberrecon.storage import Repository
completed = []
def diagnostic(home):
    time.sleep(.3)
    completed.append(True)
    if sys.argv[1] == "True":
        raise ValueError("Controlled diagnostic failure")
    return {}
gui.doctor = diagnostic
app = QApplication([])
with tempfile.TemporaryDirectory() as home:
    QTimer.singleShot(1, app.quit)
    assert gui.launch(Repository(home)) == 0
    assert completed == [True]
    assert QThreadPool.globalInstance().activeThreadCount() == 0
    assert not app.topLevelWidgets()
print("drained diagnostics and deleted widgets")
'''
    result = subprocess.run([sys.executable, "-X", "faulthandler", "-c", program, str(failure)],
                            cwd=ROOT, capture_output=True, text=True, timeout=60,
                            env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 0, result.stderr
    assert "drained diagnostics and deleted widgets" in result.stdout


def test_event_loop_exception_still_drains_diagnostics_and_preserves_error():
    import os
    import sys
    program = r'''import tempfile, time
from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication
import cyberrecon.gui as gui
from cyberrecon.storage import Repository
completed = []
def diagnostic(home):
    time.sleep(.1)
    completed.append(True)
    return {}
def failed_exec(self):
    raise ValueError("Controlled event-loop failure")
gui.doctor = diagnostic
QApplication.exec = failed_exec
app = QApplication([])
with tempfile.TemporaryDirectory() as home:
    try:
        gui.launch(Repository(home))
    except ValueError as exc:
        assert str(exc) == "Controlled event-loop failure"
    else:
        raise AssertionError("Event-loop failure was suppressed")
    assert completed == [True]
    assert QThreadPool.globalInstance().activeThreadCount() == 0
    assert not app.topLevelWidgets()
print("exception preserved; shutdown drained")
'''
    result = subprocess.run([sys.executable, "-X", "faulthandler", "-c", program],
                            cwd=ROOT, capture_output=True, text=True, timeout=60,
                            env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert result.returncode == 0, result.stderr
    assert "exception preserved; shutdown drained" in result.stdout
