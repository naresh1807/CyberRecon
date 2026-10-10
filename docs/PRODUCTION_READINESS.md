# CyberRecon v0.2.0 production-readiness qualification

Date: 2026-10-10 (Asia/Kolkata). Decision: **NOT APPROVED FOR PRODUCTION RELEASE**. Publication, package uploads, releases and deployment remain disabled. At the time of the historical qualification below, the target had no Git repository. The post-push audited baseline is now commit `36b9505665b785d151fb65950bcab84e10b9dd71`; local remediation remains uncommitted. The original project is read-only and protected by before/after full-file hashes.

## Current local remediation — 2026-10-10

Production release remains **NOT APPROVED / BLOCKED**. The post-push read-only audit reproduced 300 Python tests passed, 0 failed, 3 skipped, plus 6 Go tests with race detection and vet passing. These describe the tracked baseline, not a completed Kali/Parrot lifecycle or trusted release. After the scoped local patch, the complete Python suite independently passed again: **300 passed, 0 failed, 3 skipped**, exit 0. `git diff --check`, JSON parsing, historical-snapshot preservation, ignore probes and existing artifact checksums passed. Go was not rerun for this patch because its source is unchanged; the six-test Go result above belongs to the preceding audit. Test output is temporary local evidence, not public attestation.

The baseline now has Git history and was verified against GitHub main during that audit. This resolves absence of a repository, not independent review, reproducibility or artifact-to-commit traceability. Existing artifacts predate these edits and were not rebuilt, replaced or newly qualified. No staging, commit, push, tagging, signing, publication or deployment is part of this patch.

Remaining mandatory blockers: disposable Kali and Parrot fresh-install/menu/reboot/remove/purge/reinstall qualification; a genuine previous-release upgrade; independently trusted production public key and actual signatures; owner-approved protected release infrastructure and identity; and reviewed exact-source artifact provenance. All remain **BLOCKED**; unexecuted scenarios are not passing evidence.

Current machine-readable summary: `release-evidence/production-readiness.json`. The prior summary is preserved unchanged at `release-evidence/history/production-readiness-pre-git-20261010.json`. Sections below retain historical results and commands; their old Git/environment statements describe their execution time, not the present checkout. Local/private evidence paths are not publicly distributed attestations.

## Historical pre-Git blocker review — 2026-10-10

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

## Dashboard resume qualification — 2026-10-10

Production decision: **NOT APPROVED / BLOCKED**. This section records the current uncommitted checkout, superseding earlier local result counts without changing historical evidence. HEAD is `e79cb613a5cd1f79499938e332239a66187c3d95`; dashboard and engine work is not committed or independently reviewed.

The supplied dashboard reference was compared with the actual Kali desktop capture. The navy/blue sidebar, target controls, six cards, overview panels, URL/API views, exports, progress, and responsive layout already existed. This increment makes the full subdomain/IP views use actual DNS mappings with original-record details, and makes cancelled/failed/partial scans actionable even when no warning string was recorded. Missing registrar, location, ASN and technology version remain explicitly unavailable; screenshots are not collected.

Current executed checks: checkout `QT_QPA_PLATFORM=offscreen .release-qualification/venv/bin/python -m pytest -q`: **366 passed, 0 failed, 3 skipped**, exit 0. `go test -race -count=1 -v ./...` and `go vet ./...`: **6 passed**, exit 0. Actual Kali 2026.3 xcb dashboard verification passed all 17 navigation views, narrow layout, owned loopback HTTP/Nmap, filter/details, JSON/HTML/PDF exports, cancellation, and failure display. This is host application functionality, not distribution lifecycle qualification.

`python -m build --no-isolation --outdir .release-qualification/dashboard-resume/packages`, `python -m twine check` and `scripts/check_release_security.py --artifacts` passed (128 source files, 2 verification artifacts). AST parsing and existing `dist/SHA256SUMS` checks passed. Ruff/mypy are unavailable: **NOT RUN**. The security checker is bounded and heuristic, not proof of absence of secrets or vulnerabilities. Evidence is under `.release-qualification/dashboard-resume/`; historical engine evidence remains unchanged.

| Mandatory gate | Status | Evidence and next action |
|---|---|---|
| Full-range and privileged Nmap | BLOCKED | This run used a single owned loopback service. No full-range, privileged UDP/OS/NSE qualification was run. Supply a disposable explicitly authorized target and record real scope/coverage/XML. |
| External providers | BLOCKED | Earlier local doctor evidence records missing/failing optional providers; no external provider qualification was executed in this increment. Configure providers and qualify against authorized domains with recorded errors and limits. |
| Kali and Parrot installation/lifecycle | BLOCKED | Host is Kali 2026.3; no virsh/QEMU/Docker/Podman/VirtualBox command was found. No install, reboot, remove/purge or reinstall transaction was run. Provide disposable distribution guests/snapshots and execute the lifecycle procedure. |
| Previous-version upgrade | BLOCKED | No genuine previous-version package was located in this checkout's shallow artifact search. This does not establish absence elsewhere. Obtain an authenticated previous release and perform upgrade/state/recovery checks in guests. |
| Production APT signing and maintainer identity | BLOCKED | Inventory reports all eight release configuration variables MISSING; no trusted public key or real signature was verified. Configure protected owner-approved infrastructure and independently authenticate the public key; never provide private keys to this audit. |
| Reviewed source provenance/reproducibility | BLOCKED | Existing manifest source_commit is null; runtime changes remain uncommitted. Verification builds demonstrate packaging, not reproducibility or reviewed-source provenance. Review a concrete source commit and independently rebuild/compare artifacts. |
| Protected release workflow | BLOCKED | Only verification-only workflow exists locally. No remote/protected release execution was performed. Configure and qualify owner-approved protected gates without enabling publication in this task. |

Missing configuration names: `CYBERRECON_MAINTAINER`, `APT_PUBLIC_URL`, `GITHUB_SHA`, `RELEASE_QUALIFIED_COMMIT`, `RELEASE_QUALIFICATION_JSON`, `APT_SIGNING_FINGERPRINT`, `APT_SIGNING_PRIVATE_KEY`, `APT_SIGNING_PASSPHRASE`. Presence was checked without printing values. Signing/publication/deployment were not run.

Original-project baseline: **22,555 regular files unchanged**, no added/removed regular files. All **101** protected reference/dist baseline hashes match. No original/reference/release artifact changes, staging, commits, pushes, tags or publication occurred.

Independent archive rerun: extracted verification archive root, `QT_QPA_PLATFORM=offscreen .../venv/bin/python -m pytest -q`, **365 passed, 0 failed, 4 skipped**, exit 0, 42.79 seconds. Final evidence: `.release-qualification/dashboard-resume/archive-final.log`, `.xml`, and `.exit`. Earlier interrupted archive attempts have no final result and are not passing evidence. The extra archive skip is the absent optional Go executable; no test was removed. Verification packages were built before this reporting append and are not reviewed production candidates.
