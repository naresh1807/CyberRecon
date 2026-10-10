# CyberRecon v0.2.0 production-readiness qualification

Date: 2026-10-10 (Asia/Kolkata). Decision: **NOT APPROVED FOR PRODUCTION RELEASE**. Publication, package uploads, releases and deployment remain disabled. The target has no Git repository; no Git history was created, rewritten or pushed. The original project is read-only and protected by before/after full-file hashes.

## Latest blocker review — 2026-10-10

Decision remains **NOT APPROVED**. No publication, upload, push, production signing, deployment, host package transaction or reboot was performed. The following supersedes the older remaining-blocker statuses below. Commands, exit codes, stdout/stderr and configuration-presence results are retained in `.release-qualification/blocker-review/discovery.json`.

| Ordered blocker/check | Status | Executed evidence and next action |
|---|---|---|
| 1. Disposable Kali lifecycle | BLOCKED | Host identifies as Kali 2026.3, not a disposable guest. virsh, QEMU, VirtualBox, Docker, Podman, nspawn and proot are absent; /dev/kvm, libvirt image directory and disposable marker are absent. No guest OS version exists to report. Provide a snapshotted Kali VM; execute documented default/minimal fresh install, installed non-root CLI/GUI/menu, actual reboot, remove/purge/reinstall and data-policy matrix. |
| 1. Disposable Parrot lifecycle | BLOCKED | No Parrot environment or VM image found in searched project/Downloads locations. No lifecycle transaction executed. Provide a snapshotted Parrot Security VM and record exact OS version plus the same matrix. |
| 2. Genuine previous-version upgrade | BLOCKED | Local search found only CyberRecon 0.2.0-5 plus an unrelated VS Code package. Public GET https://api.github.com/repos/naresh1807/CyberIntel/releases returned HTTP 200 and an empty list (curl exit 0). This does not prove no release exists elsewhere. No standalone repository is configured and no authenticated previous package was located. Development fixtures/edited versions are excluded. Obtain a genuine supported previous artifact, provenance and hashes; test upgrade, configuration/data/dependencies and snapshot rollback/recovery in both guests. |
| 3. Current candidate checksum integrity | PASS | sha256sum -c SHA256SUMS exit 0: all five entries match; read-only validator checks four artifact digests against build-manifest.json. Hashes establish local integrity only. Rebuild and repeat for the final reviewed source. |
| 3. Independently trusted production signatures | BLOCKED | No .asc/.gpg/.pub release key/signature found in the checkout. Existing signing pins a fingerprint/identity but the pin alone is not independent authentication. No production signature verification was executed. Authenticate the public key independently and verify actual release/repository signatures; never supply private keys to this review. |
| 3. Signing dry-run/publication guard | PASS | Actual candidate dry-run exited 0, reports signing NOT RUN, trust BLOCKED, publication/deployment DISABLED; output directory was not created. Regressions ensure dry-run cannot invoke signing subprocesses and real signing cannot bypass gates. Keep dry-run enabled. |
| 4. Release configuration/infrastructure | BLOCKED | Local environment lacks CYBERRECON_MAINTAINER, APT_PUBLIC_URL, GITHUB_SHA, RELEASE_QUALIFIED_COMMIT, RELEASE_QUALIFICATION_JSON, APT_SIGNING_FINGERPRINT, APT_SIGNING_PRIVATE_KEY and APT_SIGNING_PASSPHRASE. Only presence was inspected; no values or private keys were printed/requested. Candidate identity remains developmental. Provision owner-approved protected infrastructure externally, authenticated public identity/trust, repository configuration and reviewed qualification evidence; local absence does not establish remote secret state. |
| 4. Remote protected CI execution | NOT RUN | Existing verification workflow has contents: read, pinned actions, no credentials persistence, no secret references, no upload/publication/deployment steps. Added read-only inventory invocation after artifact generation. No remote repository/protected environment or workflow execution evidence available. Configure a reviewed repository and execute verification; do not enable publication as part of this task. |
| 5. Git provenance/reviewed source commit | BLOCKED | git status, log and tag each exit 128: target is not a repository. Existing manifest source_commit/source_tree_dirty are null. No history, tag, commit or attestation was invented. Restore authentic standalone repository history and independently review an exact clean source commit. |
| 5. Current artifacts versus changed source | BLOCKED | Existing wheel/sdist/Debian/worker bytes were preserved and checksums match their prior manifest. New validator, tests and CI update are not in those previously built archives; no refreshed build/provenance claim is made. Rebuild from the reviewed clean commit with recorded inputs/SOURCE_DATE_EPOCH and compare independent rebuilds; hash records alone are not reproducibility or authenticated provenance. |
| Regression tests after safe changes | PASS | Complete target suite: **300 passed, 0 failed, 3 skipped**; JUnit and log in blocker-review/pytest.xml and pytest.log. Four new security regressions reject tampered artifacts, path escape and symlinks and ensure configuration values remain hidden and fabricated commit claims never establish trust. |
| Original project protection | PASS | Full read-only comparison against the prior baseline: **22,555 files, zero changed**; blocker-review/original-integrity.json. |

Safe additions: `scripts/verify_release_blockers.py` inventories hashes and configuration presence without signing, key import, package operations or publication. It deliberately reports provenance and production trust as BLOCKED even when a manifest claims a commit. Prior Go, source-archive, build, GUI and dependency-audit totals below are retained as previous-run evidence, not claimed as newly executed. Lifecycle procedures remain in [LIFECYCLE_QUALIFICATION.md](LIFECYCLE_QUALIFICATION.md); all unavailable lifecycle entries are BLOCKED, with no fabricated commands or guest results.

## Reproduced evidence (previous verification)

The prior report was treated as a claim. Its baseline was reproduced: **275 passed, 0 failed, 4 skipped**. After safe fixes and new regressions, the standalone target suite is **296 passed, 0 failed, 3 skipped**. The actual extracted source distribution suite is **295 passed, 0 failed, 4 skipped**; its extra skip is the separately compiled optional worker. Three retained historical assertions concern an absent production publishing workflow. Their security requirements are actively checked by new dry-run/gate/verification-workflow regressions; the absent workflow itself is not qualified. No tests were deleted.

Go 1.26.8: **6 tests passed**, race detection passed, `go vet` passed, compilation passed. Deterministic injected DNS tests cover valid scoped resolution, absolute names, three-second deadlines, deduplication and DNS failures. Python integration uses literal fixture IPs, and malformed worker output/missing-worker fallback tests pass. The default Python resolver remains available without Go; only the Go implementation of bounded concurrent A/AAAA resolution is absent in that mode.

Fresh wheel installation: independent Python 3.14.7 environment under `.release-qualification/venv`, not editable and not system-site-enabled. Installed `cyberrecon --version`, `--help`, and `python -I -m cyberrecon --version` passed from outside the checkout. All core modules import without CyberIntel installed or its source path on sys.path. The actual installed GUI passed timed startup/shutdown on Kali X11 (`xcb`), as UID1000. Corrected source GUI qualification additionally passed navigation, icon/rendering, filtering/1000-row cap, scope-error display, cancellation, exports and persistence. These are live-host application checks, not clean system-package/menu or reboot qualification.

The script-owned loopback lab passed verified HTTPS, real unprivileged TCP Nmap inventory, and JSON/CSV/HTML/PDF/graph exports. It contacted no external scan target. Wheel/sdist/worker/Debian candidates build locally. Metadata, SVG asset, console entry point, source/archive isolation and heuristic credential/AST/archive checks pass. Debian staging verifies extraction/overlay/state preservation; it does not install the package on the host.

An online pip-audit of the isolated environment initially reported two duplicate advisory entries for pip 26.1.2 (one issue). Updating only that environment to pip 26.2.1 produced **no known vulnerabilities found**. The custom cyberrecon package is not listed on PyPI and was skipped by the advisory database; its own code is covered by the security regressions and static review. The audit is a point-in-time database result, not a guarantee of absence of vulnerabilities. Initial/final audit JSON and install logs are retained; host Python was untouched.

## Safe fixes

- Complete source distributions now include scripts, tests, worker sources, workflow and manuals; generated environments and inherited evidence are excluded.
- The static release checker works in a source archive without Git. Source digests include tests, worker, workflow, manifest and release tooling inputs.
- Worker result validation rejects malformed object/address/error types and excessive address lists. Go rejects noncanonical internet-wide CIDRs such as `192.0.2.4/0` before work.
- Desktop verification navigates the actual sidebar and advanced dialog, rather than treating every view as a tab; it checks the window's stylesheet.
- Signing defaults to validation-only dry-run. It never imports keys, writes a signature or publishes. Explicit `--sign` requires the existing mandatory production gates before import, and rejects signing temporary directories inside artifact output. Secret-leak/cleanup tests retain their original assertions.
- A read-only CI verification workflow was prepared. It has no secrets, upload, release, push or deployment steps and has not been run remotely.
- A read-only reboot-continuity helper requires a changed kernel boot ID and unchanged installed-version/logical workspace state. It never reboots or changes packages.

## Remaining blockers mapped to evidence

| Requirement | Status | Test or evidence needed |
|---|---|---|
| Standalone runtime/wheel isolation, metadata/assets/CLI | PASS | `scripts/verify_release_inputs.py`, installed-isolation-gui.json, installed-cli.log |
| Complete target tests and scope/TLS/SSRF/export security regressions | PASS | final-pytest.xml/log; 296/0/3; tests/test_standalone.py and existing hardening suites |
| Source distribution development completeness | PASS | isolation-artifacts.json and extracted-sdist tests; 295/0/4 |
| Syntax, static source/artifact checks | PASS | compileall; static-artifacts.json; heuristic limits stated |
| Optional Go race/vet/build, protocol, DNS/error/fallback | PASS | go-test.jsonl (6 tests); tests/test_cyberrecon_go.py and test_release_readiness.py |
| Fresh independent wheel environment and live installed wheel GUI | PASS | installed-isolation-gui.json, wheel-install.log, pip-check.log; xcb UID1000 |
| Live Kali source desktop and owned loopback TLS/Nmap | PASS | desktop/desktop.json, loopback-lab.log; not VM qualification |
| Point-in-time dependency security audit | PASS | dependency-audit-final.json/log; pip26.2.1; no known vulnerabilities |
| Git history/exact reviewed commit provenance | BLOCKED | Target is not a Git checkout. Source/artifact SHA256s are recorded; commit and dirty state remain unknown |
| Kali clean fresh/default/minimal installation | NOT RUN | Disposable Kali desktop VM and real package transaction evidence |
| Parrot clean fresh/default/minimal installation | NOT RUN | Disposable Parrot Security desktop VM and dependency resolution evidence |
| Installed Debian non-root CLI/GUI/menu on both OSes | NOT RUN | Actual installed module/menu paths, CLI output and desktop evidence in each VM |
| Upgrade on both OSes | BLOCKED | Genuine previous supported package/provenance plus VM upgrade and preserved-state checks; edited-version fixtures do not qualify |
| Real reboot and post-reboot use on both OSes | NOT RUN | Changed boot IDs, post-reboot continuity, CLI/GUI/menu reruns |
| Remove/purge/reinstall and data policy on both OSes | NOT RUN | Actual guest transaction logs and DB/report/config preservation checks |
| Trusted production public key and artifact signatures | BLOCKED | Independently authenticated public key matching the configured full fingerprint; actual candidate signatures. None supplied or requested |
| Protected production signing credentials/procedure | BLOCKED | No authorized protected signing environment is configured; no private key is requested, imported or used in this run |
| Production APT trust chain/HTTPS/default-client install | BLOCKED | Genuine signed repository and pinned trusted-key verification; development GPG fixtures are not production trust |
| Public maintainer identity for candidate packaging | BLOCKED | Real release metadata has not been configured; Debian candidate retains an explicit development identity |
| Remote CI execution and reviewed exact-source release gates | NOT RUN | Execution evidence from protected release infrastructure; local workflow checks alone do not qualify this |
| Publication/deployment | DISABLED | Verification-only workflow and default dry-run have no publishing commands |
| Python3.12/3.13 runtime matrix | NOT RUN | Those interpreters are unavailable; only Python3.14.7 is qualified here |

Detailed VM procedure: [LIFECYCLE_QUALIFICATION.md](LIFECYCLE_QUALIFICATION.md). The existing destructive lifecycle runner refuses an unmarked host and was **not run on this host**. No package purge, host installation, reboot, remote workflow, signing or upload was performed.

## Artifact integrity and trust

Candidate SHA256s and provenance are in `dist/SHA256SUMS` and `dist/build-manifest.json`. Verify against the actual files with `sha256sum -c SHA256SUMS`. This is local integrity, not an authenticated distribution channel. Development APT signature/hash-chain/tamper tests use disposable development keys and passed; no production signature or trusted owner public-key verification is claimed. The production fingerprint string in the existing implementation is a configuration pin, not evidence that a trusted public key is present.

Dry-run command: `python scripts/sign_cyberrecon_release.py dist/cyberrecon_0.2.0-5_amd64.deb --dry-run --output .release-qualification/signing-disabled`. Its result explicitly reports signing NOT RUN, production trust BLOCKED, publication DISABLED and deployment DISABLED; the output directory is not created.

Inherited release JSON is preserved under `reference/legacy-monorepo/release-evidence/` and cannot attest to this standalone tree. The current final-production-gate.json records NOT APPROVED and unknown Git provenance. Earlier file versions and candidate artifacts are preserved under `.release-qualification/backup/` and `initial-artifacts/`. Evidence logs, JUnit, installed-environment details and checks are under `.release-qualification/`; the public summary is docs/release-evidence/production-readiness.json.
