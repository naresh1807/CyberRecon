# Production qualification continuation — 2026-10-10

Baseline: main `e0fca076044343d442fe694aebaf5f24e88fd3a8`, clean checkout.
Local HEAD, origin/main and live GitHub main were identical before changes.
Remote: `https://github.com/naresh1807/CyberRecon.git`.
Production remains **NOT APPROVED / BLOCKED**.

This report supplements historical records without rewriting them. New evidence:
`.release-qualification/production-gates-e0fca07/`. No commit, push, tag, production
signature, upload, release, Pages deployment or host package lifecycle is authorized.

## Baseline audit

Read the infrastructure/results intelligence reports, release checklist, readiness
and signing reports, APT/lifecycle procedures, package builders, release/signature/input
validators, Nmap/provider code, regression tests and the sole verification workflow.

Independent baseline: **400 passed, 0 failed, 3 skipped**, exit 0, 23.62 seconds
(`baseline.log/xml/exit`). Skips relate to absent production publishing workflows.
Historical tests and package records are not current qualification.

Environment: Kali Rolling 2026.3, kernel 7.1.5+kali-amd64, x86_64, non-root UID 1000,
CPython 3.14.7, Nmap 7.99, Go 1.26.8, PySide6 6.12.0.
Exact dependency inventory and command arguments are in the local JSON evidence.
No virsh, QEMU, VirtualBox, Docker, Podman or /dev/kvm is available.
Disposable user/network namespaces do work; they are sufficient for owned network
testing, not a substitute for Kali/Parrot desktop VM installation and reboot.

## Defects found and local corrections

1. Mandatory signing/publication gate omitted explicit full-range/privileged Nmap,
   external provider, source provenance and reproducibility requirements.
   These are now required individually; FAIL/BLOCKED/NOT RUN/SKIPPED/CANCELLED cannot pass.
   Synthetic complete gate objects in unit tests exercise refusal, not release approval.
2. Provider transport exception messages could include credential-bearing request URLs.
   Shodan/Censys failures now expose only a generic network/TLS diagnostic. No automatic
   retry is introduced: one request maximum. Malformed JSON gets a generic message.
   Arbitrary service objects and echoed credentials are not persisted; timestamps must
   be valid timezone-bearing ISO dates. Contact data and other unrelated fields remain omitted.
3. APT verifier checked exit status and VALIDSIG but did not explicitly reject revoked
   or expired signature/key status markers. Those statuses now fail closed even when a
   mock also presents VALIDSIG. Existing actual development GPG/hash/tamper tests remain.
4. Exact baseline builds were not fully byte-reproducible: wheel, Go worker and Debian
   bytes matched, but the source archive differed. Generated tar timestamps, owner
   metadata and gzip headers were nondeterministic. Content hashes matched.
   A build-only setuptools sdist command now canonicalizes bounded archive metadata
   and gzip when SOURCE_DATE_EPOCH is supplied. Unsafe members/epochs fail closed.
   The build module is included in source archives and source digests, not runtime wheels.
   Verification CI sets the epoch from the commit timestamp; publication remains disabled.
5. GitHub's actual baseline verification run
   [38055086450](https://github.com/naresh1807/CyberRecon/actions/runs/38055086450)
   passed 400 tests, then its startup script printed PASS and exited **139**.
   This is FAIL. The script and GUI launch now drain jobs/callbacks and deferred widget
   deletion before interpreter teardown. A subprocess regression requires actual exit 0.
6. The first network verifier used an unavailable parent /proc namespace link.
   Its output is preserved but not accepted as final isolation proof. The runner now
   captures the parent namespace before unshare, validates distinct namespace IDs,
   and requires a single-UID root mapping. Final evidence must come from this corrected
   verifier. Host privilege, networking, firewall rules and package state are untouched.

## Provider and trust audit

CT uses crt.sh followed by Cert Spotter fallback, public DNS pinning, TLS verification,
one request/second provider reservations, a 60-second collector deadline, at most
20 requests, five pages and bounded response size. Primary CT uses one attempt;
fallback requests allow at most three attempts, with bounded backoff/Retry-After.
Existing tests cover empty/malformed responses, fallback, pagination failures,
duplicates/wildcards, scope, address policy, redirects, rate limits and cancellation.
Subfinder/Assetfinder/Amass remain optional passive subprocess adapters; Amass supports
validated v3 only. Native DNS and optional Go perform resolver observations, not live
third-party account qualification. Shodan/Censys observations remain historical,
unverified current services; no request is sent to the target by their adapters.

SHODAN_API_KEY, CENSYS_PLATFORM_TOKEN and CENSYS_ORGANIZATION_ID are absent.
No explicitly authorized real public provider target was supplied. Live CT/account/tool
provider qualification is BLOCKED; deterministic mocked behavior is separate evidence.
No credentials are requested or printed.

All eight release configuration names are missing:
CYBERRECON_MAINTAINER, APT_PUBLIC_URL, GITHUB_SHA, RELEASE_QUALIFIED_COMMIT,
RELEASE_QUALIFICATION_JSON, APT_SIGNING_FINGERPRINT, APT_SIGNING_PRIVATE_KEY,
APT_SIGNING_PASSPHRASE. Configuration pins in source are not independent trust anchors.
No trusted production public-key artifact or genuine production signature was verified.
Dry-run validates the existing Debian candidate and creates no output; signing is
NOT RUN, trust BLOCKED, publication/deployment DISABLED.

GitHub read-only APIs reported an active verification-only workflow, no environments,
no releases and HTTP 404 for classic main protection. A 404 alone does not establish
which ruleset or permissions apply. Settings were not changed. Remote verification
failure is recorded above; the local repair has not been executed on GitHub.

No Git tags exist. The available standalone Debian inventory contains only v0.2.0-5
candidates; none is a genuine previous supported CyberRecon release. Development
tests that edit Version to 0.2.0-4 are synthetic metadata fixtures and do not qualify
upgrade. An authenticated previous release and disposable guests are still required.

## Current execution and gates

Final command results, exact totals, artifacts and gate statuses are appended after
execution. PASS requires sufficient actual evidence; mocked regressions do not pass
live provider, production trust or distribution lifecycle gates.

### Final observed results

All local commands below completed with exit **0**, except the explicitly identified
baseline comparison/remote qualification failures. A successful dry-run is not signing.
Python commands use `.release-qualification/venv/bin/python`. Output prefix
`Q=.release-qualification/production-gates-e0fca07`, relative to the project root.

| Check | Actual result | Evidence |
|---|---|---|
| Final checkout suite | **458 passed, 0 failed, 0 errors, 3 skipped**, 26.96s | checkout-final.log/xml/exit |
| Final independent source archive | **457 passed, 0 failed, 0 errors, 4 skipped**, 25.34s | archive-final.log/xml/exit; archive-final-command.json |
| Focused first hardening tests | 88 passed, 1 skipped | focused.log/exit |
| Focused shutdown/sdist/gate tests before final provenance regression | 57 passed | focused-final.log/exit |
| Go race tests / vet / build | **6 passed**, race/vet/build exit 0 | go-race.log/exit, go-vet.log/exit, go-build.log/exit |
| Owned DNS/HTTP/Nmap integration | PASS, process-owned listeners only | owned/verification.json; owned-engines.log/exit |
| Owned HTTPS | PASS inside complete suites, ephemeral explicitly trusted fixture certificate | tests/test_infrastructure_intelligence.py; final JUnit |
| Full-range/privileged Nmap lab | PASS, corrected namespace proof and six real checks | nmap-complete/verification.json; nmap-complete.log/exit |
| Live Kali desktop | PASS, xcb, 18 views, narrow layout, exports, cancellation/failure and clean exit | desktop/verification.json; desktop.log/exit |
| Wheel/sdist/worker/Debian double builds | Four payloads byte-equal in both fresh trees | final-reproducibility.json; final-candidate-{1,2} build logs/exit |
| Final metadata / source inputs | PASS, version/entry point/assets, required build module/tests/worker/workflow, no legacy imports or runtime original path | twine-final.log/exit; inputs-final.log/exit |
| Final installed wheel | PASS, isolated target, CLI version/help/module, legacy import guard, 34 runtime/asset files byte-equal, offscreen GUI and clean exit | wheel-install-final.log/exit; wheel-final.log/exit/json; verify_wheel_final.py |
| Current source and candidate security checks | PASS, 137 source files, 4 artifacts; bounded heuristics | security-final.log/exit |
| Git history credential scan | 180 blobs, no heuristic detections; values never printed | history-secret-scan.json |
| Dependency audit | 67 dependencies, **0 known vulnerabilities**, exit 0 | dependency-audit.json/log/exit |
| Local workflow validation | PASS: YAML parsed, 3 actions pinned to full SHAs, contents read, no secrets/publishing commands | workflow-local.json |
| AST / JSON / whitespace / checksums | PASS; 87 Python files parsed; existing and new checksums matched | integrity.json; diff-check.log; checksum logs |
| Signing default/dry-run | PASS for validation-only behavior; no output directory; production signing NOT RUN | dry-run.log; dry-run-final.log/exit |
| Ruff / mypy / actionlint | **NOT RUN**, unavailable | environment.json |
| Patched remote CI execution | **NOT RUN**, patch is local and publication disabled | baseline remote run is FAIL; no workflow triggered |

The three checkout skips cover absent production publishing/signing workflow tests.
The archive has the same skips plus an absent optional Go executable. The source includes
Go build inputs, and checkout cross-language/worker fallback regressions still run.
No tests were removed or weakened.

Dependency auditing is a point-in-time advisory lookup, not a guarantee of security.
The source/history scanners recognize private-key framing and selected token patterns;
unknown credential formats, passwords, encoded secrets and unrelated credentials require
human review. Expired/revoked signature-status regressions are mocked; actual signature,
APT index resolution and tampering tests use disposable development GPG fixtures.
None establishes production key trust.

### Exact command ledger

Shell aliases below expand to the same interpreter/output locations as recorded in the
machine-readable argv ledgers. They are not host installation or publication commands.

```sh
Q=.release-qualification/production-gates-e0fca07
PYTHON="$PWD/.release-qualification/venv/bin/python"

QT_QPA_PLATFORM=offscreen "$PYTHON" -m pytest -q --junitxml="$Q/checkout-final.xml"
"$PYTHON" scripts/verify_cyberrecon_nmap_namespace.py --output "$Q/nmap-complete"
"$PYTHON" scripts/verify_cyberrecon_engines.py --output "$Q/owned"
"$PYTHON" scripts/verify_cyberrecon_dashboard.py --output "$Q/desktop" --desktop
"$PYTHON" -m twine check "$Q/final-candidate-1/packages/cyberrecon-0.2.0-py3-none-any.whl" "$Q/final-candidate-1/packages/cyberrecon-0.2.0.tar.gz"
"$PYTHON" scripts/verify_release_inputs.py --artifacts "$Q/final-candidate-1/packages"
"$PYTHON" scripts/check_release_security.py --artifacts "$Q/final-candidate-1/packages"
"$PYTHON" -m pip_audit --format json --output "$Q/dependency-audit.json"
"$PYTHON" scripts/sign_cyberrecon_release.py "$Q/final-candidate-1/packages/cyberrecon_0.2.0-5_amd64.deb" --dry-run --output "$Q/signing-disabled-final"
"$PYTHON" -m pip install --no-index --no-deps --target "$Q/wheel-site-final" "$Q/final-candidate-1/packages/cyberrecon-0.2.0-py3-none-any.whl"
git diff --check
```

Choose fresh output paths to rerun: evidence-generating verifiers refuse existing
workspaces and must never overwrite these records. Worker commands, from workers/dns:
`go test -race -count=1 -v ./...`, `go vet ./...`, and
`go build -trimpath -buildvcs=false -o ABSOLUTE_Q/cyberrecon-dns .`.
The exact absolute argv, cwd and exit codes are in verification-commands.json.

Archive extraction used tar's data filter. The final pytest ran from
`Q/final-independent-source/cyberrecon-0.2.0`, with PYTHONPATH removed,
QT_QPA_PLATFORM=offscreen and the absolute qualified interpreter/JUnit path.
Exact invocation: archive-final-command.json. Installed-wheel verifier ran from /tmp
with only the installed target on PYTHONPATH; qualified dependencies were reused.
Fresh distro dependency installation is BLOCKED.

Double builds used two fresh git archives of e0fca076 plus explicit patch-file overlays,
fixed SOURCE_DATE_EPOCH from that commit, PYTHONHASHSEED=0, TZ=UTC, LC_ALL=C.UTF-8 and
CGO_ENABLED=0. Commands were `python -m build --no-isolation --outdir ABSOLUTE_PACKAGES`,
`go build -trimpath -buildvcs=false -o ABSOLUTE_PACKAGES/cyberrecon-dns .`, and
`python scripts/build-cyberrecon-deb.py --output ABSOLUTE_PACKAGES --worker ABSOLUTE_PACKAGES/cyberrecon-dns`.
Every exact expansion and hash is in final-reproducibility.json.
New manifests/checksums used prepare_cyberrecon_release.py --build-manifest and --checksums.
Both new directories and the protected existing dist passed `sha256sum -c SHA256SUMS`.

The source digest now also includes the packaged CyberRecon manual, docs and worker
README, in addition to the build-only module. A regression proves document edits change
the digest. Manifests truthfully record the baseline commit and source_tree_dirty=true.
Build-date/dependency manifest metadata are audit records, not byte-reproducible payloads.
The four compared payloads are wheel, sdist, worker and Debian package. Both build trees
used shared qualified tools/dependencies, not independent OS provisioning.
Packages and manifests precede this final report appendix. Their source snapshot/report
hashes remain preserved; final runtime files are byte-equal to the qualified wheel.
Review, commit and rebuild the exact final source before release provenance qualification.

Read-only GitHub commands: gh api repos/naresh1807/CyberRecon, branches/main/protection,
environments, actions/workflows, actions/runs?per_page=5, releases?per_page=100, and
rules/branches/main (each path under repos/naresh1807/CyberRecon).
The active main rules endpoint returned an empty array with exit 0. No required
status checks or protected environments were observed. Classic protection returned
HTTP 404/exit 1. Baseline failed logs were read with
`gh run view 38055086450 --repo naresh1807/CyberRecon --log-failed`, exit 0.
No workflow dispatch or settings write occurred.

### Actual Nmap evidence and limits

The final wrapper created a new user/network namespace, required a distinct captured
parent namespace and a single-UID mapping, then brought up only its loopback.
Namespace root is not host root. The private nft drop rule existed only in that lab
namespace and disappeared when the namespace exited; host firewall state was untouched.

- Full TCP: requested **65535**, explicitly reported **1**, summarized **65534**,
  total **65535**, coverage_verified=true, partial=false. Actual XML is preserved.
  Aggregated closed-port counts do not invent individual absent observations.
- Privileged OS/service: two ports, one open and one closed; coverage verified.
  Nmap emitted competing Linux matches at 92–97 estimates. These are unconfirmed
  fingerprints, not accurate kernel-version assertions; the known lab kernel was 7.1.5.
- Privileged UDP: one process-owned echo port, observed open, coverage verified.
- Filtered TCP: one namespace-local dropped port, observed filtered, coverage verified.
- Cancellation and timeout: actual subprocesses terminated/reaped; diagnostics record
  expected returncode -9. Wrapper exit 0 means those expected failures were handled.
- Unknown, conflicting, malformed and truncated states also have deterministic parser
  regressions; no real unknown port was fabricated to satisfy a test.

Probe caps remained bounded: max parallelism 2, max retries 1, full-range rate cap 1000
only in the private lab, bounded per-stage durations. Default application rate/profile
was not relaxed. No NSE scripts, exploit, brute-force, stealth or evasion behavior was added.

The first verifier run is **FAIL as qualification evidence**, despite exit 0 and passing
scan checks, because its parent namespace identity was empty. It is retained unchanged.
nmap-isolated-final and nmap-complete use corrected proof; only nmap-complete represents
the final six-check verifier including UID mapping, UDP, filtering and timeout.

### Mandatory release-gate matrix

| Mandatory gate | Status | Evidence / next action |
|---|---|---|
| Current local tests, scope/TLS/subprocess/permissions regressions | PASS | Final checkout/archive JUnit and owned HTTPS/network checks; unavailable workflow skips listed separately |
| Full-range Nmap | PASS | Real isolated 65535-port XML with verified coverage |
| Privileged Nmap OS/UDP behavior | PASS | Namespace-root real probes, explicit estimates and limitations; no host elevation |
| External provider live qualification | BLOCKED | Account credentials and an explicitly authorized real public target unavailable; provide owner-configured access/target and collect actual rate/error/privacy evidence |
| Kali installed desktop/lifecycle | BLOCKED | No disposable Kali desktop guest/image/snapshot; live source GUI is separate evidence |
| Parrot installed desktop/lifecycle | BLOCKED | No disposable Parrot Security guest/image/snapshot |
| Genuine previous-version upgrade/recovery | BLOCKED | No authenticated prior supported package in inspected inputs or GitHub releases/tags; obtain real artifact/provenance |
| Production APT trust/signing | BLOCKED | No independently trusted production public key/signatures or configured protected signing procedure |
| Public maintainer/release identity | BLOCKED | CYBERRECON_MAINTAINER and APT_PUBLIC_URL unconfigured; do not invent identity or hosting |
| Source/license, heuristic source/artifact checks | PASS | MIT/package copyright tests; source/archive/static checks; scanner limits stated |
| Reviewed source-to-artifact provenance | BLOCKED | Local patch is uncommitted; manifests intentionally dirty; human review/exact-commit rebuild required |
| Production reproducibility qualification | BLOCKED | Four local payloads match; reviewed exact final source and independently provisioned target build environments still required |
| Protected workflow/publication gates | FAIL | No active main rules or protected environments; baseline remote CI failed 139; owner-approved protection and non-publishing rerun required |
| Production signing / publication / deployment execution | NOT RUN | Explicitly unauthorized; dry-run cannot publish |

Per-distribution lifecycle requirements remain separately blocked:

| Required scenario | Kali | Parrot | Prerequisite/action |
|---|---|---|---|
| Fresh install | BLOCKED | BLOCKED | Disposable guest and exact reviewed candidate |
| Dependencies and integrity | BLOCKED | BLOCKED | Fresh default/minimal package transactions; local extraction/checksums do not substitute |
| Installed GUI/menu | BLOCKED | BLOCKED | Actual installed module/menu path, desktop session, ordinary user |
| Installed scan/export | BLOCKED | BLOCKED | Owned guest listeners and actual installed application |
| Genuine upgrade | BLOCKED | BLOCKED | Authenticated previous supported package |
| Upgrade data/config preservation | BLOCKED | BLOCKED | Real before/after logical state and documented preservation policy |
| Reboot/post-reboot | BLOCKED | BLOCKED | Changed boot ID and rerun installed CLI/GUI/menu |
| Remove/purge semantics | BLOCKED | BLOCKED | Actual guest transactions, package paths absent, user workspace retained |
| Clean reinstall | BLOCKED | BLOCKED | Restored clean snapshot and actual reinstall/launch |
| Missing deps/interrupted install/recovery | BLOCKED | BLOCKED | Snapshot-controlled faults and genuine transaction recovery |

Use the existing LIFECYCLE_QUALIFICATION.md procedure only in real disposable guests.
No host install, purge, reboot or APT source modification occurred. Package removal/purge
policy preserves user-owned configuration, databases, evidence and reports; this policy's
real lifecycle implementation still requires both guests.

### Changed files and next action

Nine existing files changed: .github/workflows/verify.yml, MANIFEST.in, pyproject.toml,
cyberrecon/gui.py, cyberrecon/providers.py, scripts/prepare_cyberrecon_release.py,
scripts/verify_cyberrecon_apt.py, scripts/verify_cyberrecon_startup.py and
scripts/verify_release_inputs.py.
Four files added: cyberrecon_build.py, scripts/verify_cyberrecon_nmap_namespace.py,
tests/test_production_gate_completion.py and this report. All **13** remain local.
No tests deleted; **58** new parametrized/regression test cases added.

Protected comparisons confirmed **22,555 original regular files** and all **101
reference/dist files** unchanged. Historical reports and release-evidence JSON were not
edited. HEAD remains e0fca076, index empty, no GitHub setting/release/publication changes.

Recommended sequence: review this concrete patch; authorize a commit/verification-only
CI rerun separately if desired; obtain disposable Kali/Parrot desktop snapshots and a
genuine prior artifact; configure authorized real provider targets/access; independently
authenticate the public signing key and maintainer identity; have the owner configure
protected checks/environments; qualify the exact reviewed commit and artifacts in those
environments. Private keys stay in owner-managed protected infrastructure and are never
requested by this audit. No mandatory gate may be overridden with fixture results.

Machine-readable local evidence: summary.json, final-reproducibility.json, candidate
build-manifest.json/SHA256SUMS, github-read-only.json, github-branch-rules.json and
integrity.json. These are unsigned audit records, not authenticated release attestations.

**NOT APPROVED — REQUIRED GATES REMAIN**


## Independent shutdown and release-control review — 2026-10-12

This appendix supersedes current-status interpretations of earlier sections; their
2026-10-10 observations remain historical records. HEAD is still
`e0fca076044343d442fe694aebaf5f24e88fd3a8`. All 13 patch files remain uncommitted.
New evidence directory: `.release-qualification/ci-shutdown-review-20261012/`.
Production remains **NOT APPROVED / BLOCKED**.

### Exit 139: observed failure, isolation and limits

Read the actual failed job in run 38055086450. Its Python 3.14.8 Ubuntu runner
passed 400 tests and then printed startup PASS before a native segmentation fault.
Exit 139 is shell encoding of SIGSEGV, not a failed pytest assertion.

Executed the existing verification-only workflow with
`gh workflow run verify.yml --repo naresh1807/CyberRecon --ref main` (exit 0).
Actual new run: [38197452582](https://github.com/naresh1807/CyberRecon/actions/runs/38197452582),
job `verify` / 114643207439, source e0fca076. It again passed **400 tests, 3 skipped**
(24.75s), completed Go race/vet/build and compileall, printed startup PASS, then
segfaulted in `python scripts/verify_cyberrecon_startup.py` with **139**.
The build/check-artifacts step was **SKIPPED**. Dispatch success is not job success.
No source was uploaded or pushed; this run tested committed baseline, not this patch.

Locally extracted `git archive HEAD` into the new evidence directory and ran
`QT_QPA_PLATFORM=offscreen PYTHON -X faulthandler ABSOLUTE_SCRIPT` eight times per
baseline/patched verifier, with core dumps disabled. Local CPython is 3.14.7.
Baseline: **7/8 SIGSEGV (-11 subprocess status), 1/8 exit 0**; patched: **8/8 exit 0**.
`reproduction.json` and individual logs preserve every result, including the success.
Faulthandler reports a native fault with **no Python frame** after startup PASS;
no debugger/native symbols are installed, so an exact Qt/Shiboken native function
or upstream binding defect has not been established.

Ablation in fresh baseline trees: GUI cleanup alone **3/3 SIGSEGV**;
verifier cleanup alone **3/3 exit 0** (`ablation.json`). This isolates the observed
failure to retained Qt widgets/deferred destruction at interpreter teardown; the
first verifier window also needs explicit deletion while QApplication is alive.
Waiting for the thread pool alone did not prevent the baseline crash. Do not
attribute the remote fault solely to an active background worker: the ablation
shows the verifier's explicit widget destruction is necessary to this local repair.
The existing pending-job drain and deferred deletion are retained.

Code review additionally found startup diagnostics omitted from `local_jobs`.
They now participate in closeEvent's ownership/drain handling. Two new subprocess
regressions quit after 1ms while diagnostics sleep 300ms, covering completion and
controlled failure; both require completed jobs, zero active pool threads, no
remaining top-level widgets and actual process exit 0. Against the isolated
committed baseline these tests **both fail** (pytest exit 1; 58 deselected);
against the local patch both pass. No assertions were weakened.

**Local repair supported; remote repair qualification BLOCKED.** There is no way
for GitHub to execute these uncommitted source changes without making them
available remotely. Commit/push remain prohibited. A later explicitly authorized
reviewed-source CI run must exit 0 through all steps before calling this remotely fixed.

### Fresh commands and outcomes

`PYTHON=.release-qualification/venv/bin/python`, project-root cwd unless stated.
These results were executed for this appendix, independently of earlier totals.

| Exact command/check | Exit | Observed result |
|---|---:|---|
| `QT_QPA_PLATFORM=offscreen PYTHON -m pytest -q tests/test_production_gate_completion.py --junitxml=.release-qualification/ci-shutdown-review-20261012/focused.xml` | 0 | **60 passed**, 5.07s |
| `QT_QPA_PLATFORM=offscreen PYTHON -m pytest -q --junitxml=.release-qualification/ci-shutdown-review-20261012/checkout.xml` | 0 | **460 passed, 0 failed, 3 skipped**, 40.07s |
| `QT_QPA_PLATFORM=offscreen PYTHON -m pytest -q .release-qualification/ci-shutdown-review-20261012/tests/test_production_gate_completion.py -k quit_during_diagnostics` | 1, expected | **2 failed, 58 deselected**, baseline negative control |
| `go test -race -count=1 -v ./...` from workers/dns | 0 | **6 passed**, race enabled |
| `go vet ./...` from workers/dns | 0 | No diagnostics |
| `PYTHON scripts/check_release_security.py --artifacts dist` | 0 | 137 source files / 6 existing artifact files; bounded heuristics |
| `sha256sum -c SHA256SUMS` from dist | 0 | All five entries OK |
| `git diff --check` | 0 | No whitespace errors |
| `git diff --cached --name-only` | 0 | Empty index |
| Changed Python AST and release-evidence JSON parsing | 0 | Valid; no historical evidence edited |
| Read-only protected regular-file hash comparisons | 0 | 22,555 original files and 101 reference/dist files unchanged |
| `gh run view 38197452582 --repo naresh1807/CyberRecon --log-failed` | 0 | Retrieval succeeds; workflow itself FAIL/139 |

Exact GitHub read argv/exits are in github-commands.json; local focused/checkout and
baseline regression logs contain their totals. Integrity hashes are in integrity.json.
The earlier independent archive, wheel installation, double builds, dependency audit,
live Kali desktop and isolated Nmap records were **not rerun for this final source**.
They remain prior scoped evidence; current independent archive/packaging/desktop
qualification is NOT RUN. Existing release artifacts were not rebuilt or replaced.
Provider tests in this suite use deterministic mocks; **live providers remain BLOCKED**.
Kali/Parrot lifecycle, prior-version upgrade and production signatures were NOT RUN.
Source/artifact heuristics cannot establish the absence of unknown/encoded credentials.

### Protected workflow audit and required owner configuration

Fresh GitHub APIs returned: active main rules **[]**, classic main protection
**HTTP 404 / gh exit 1**, environments **[]**, sole active workflow **verify.yml**.
Actions are enabled; allowed_actions=all; sha_pinning_required=false.
Default workflow permissions are read and PR-review approval is disabled.
All successful API reads exit 0. This is observed configuration, not inferred protection.
No protected production release workflow currently exists to qualify.

Existing verification safeguards: contents:read, no persisted checkout credentials,
three full-SHA action pins, bounded runner timeout, no signing secrets, no upload,
release/Pages/package publication or deployment step, explicit signing dry-run.
The reproducibility patch only sets SOURCE_DATE_EPOCH; it does not bypass any test.
Required checks are **not enforced** by the observed main settings.

Owner configuration steps (recommendations only; **none performed**):

1. Settings → Rules → Rulesets: create an ACTIVE branch ruleset targeting main.
   Require pull requests and at least one independent approving review; dismiss
   stale approvals, require approval of the latest push and resolved discussions.
   Require status check **verify** from GitHub Actions (the actual job/check name),
   requiring an up-to-date branch. Block force pushes/deletion; avoid administrator
   or actor bypasses that silently remove mandatory release review. Re-read effective
   `rules/branches/main` after configuration and demonstrate a failing check blocks merge.
2. Settings → Environments: create `cyberrecon-production` with independent required
   reviewers, prevent self-review, restrict deployment to protected main and disable
   administrative bypass where supported. Verify settings via API and exercise an
   actual non-publishing approval/rejection job. Mere environment creation is insufficient.
3. Settings → Actions → General: preserve read-only token defaults and disabled PR
   approval; enforce full commit-SHA pinning and restrict allowed actions to reviewed
   dependencies. Keep verification jobs free of signing credentials and write tokens.
4. Before any separately authorized release workflow exists, require its signing job
   to reference the protected environment, run only from an exact reviewed main SHA,
   consume independently reviewed PASS evidence for all **26** required gates, and
   bind immutable artifact digests to that SHA. Unit fixtures/self-asserted JSON are
   not authenticated evidence. Production identity and independent public-key trust
   must be established by the owner. Keep secrets environment-scoped; never place
   private keys in this repository, logs or artifacts.
5. Any future publishing job needs explicit owner authorization, protected approval,
   successful exact-source checks and verified signatures/checksums. Grant write
   permissions only to that separately approved job and only for its intended target;
   no global contents/packages/id-token write permission. Dry-run must have no publishing
   route. Qualify safeguards with negative tests before enabling any publication.

Missing configuration names remain CYBERRECON_MAINTAINER, APT_PUBLIC_URL,
RELEASE_QUALIFIED_COMMIT, RELEASE_QUALIFICATION_JSON, APT_SIGNING_FINGERPRINT,
APT_SIGNING_PRIVATE_KEY and APT_SIGNING_PASSPHRASE in local qualification inputs.
GITHUB_SHA is supplied by Actions, but absent from the local shell; that distinction
does not establish reviewed exact-commit evidence. No private key was requested.

### Review of all 13 current files

| File | Review outcome / current change |
|---|---|
| .github/workflows/verify.yml | Fixed epoch only; read-only non-publishing permissions retained; remote local-patch validation blocked |
| MANIFEST.in | Build-only module included; reference/local qualification/artifact directories pruned |
| cyberrecon/gui.py | Pending-job/deferred deletion retained; diagnostics now tracked; successful/failing early-quit subprocess tests added |
| cyberrecon/providers.py | Generic transport/JSON failures, one-request limit, bounded service/timestamp evidence; live account behavior unqualified |
| pyproject.toml | Build-only sdist hook; runtime dependencies and entry point unchanged |
| scripts/prepare_cyberrecon_release.py | 26 fail-closed gates and expanded packaged-source digest; reviewer trust remains an external prerequisite |
| scripts/verify_cyberrecon_apt.py | Reject expired/revoked/error statuses; new status regressions mocked, production trust not established |
| scripts/verify_cyberrecon_startup.py | Explicit first/CLI widget deletion with QApplication alive; actual parent-process exit regression retained |
| scripts/verify_release_inputs.py | Requires build hook in source archive; no publication action |
| cyberrecon_build.py | Atomic canonicalization preserves payload; rejects unsafe members/epochs; trusted local build utility, not an untrusted archive extraction service |
| scripts/verify_cyberrecon_nmap_namespace.py | Explicit namespace guard before loopback/nft work; owned targets only; prior real lab evidence preserved, not rerun |
| tests/test_production_gate_completion.py | 60 cases including 2 added early-quit cases; baseline negative controls fail; no security assertion weakened |
| docs/PRODUCTION_GATE_COMPLETION.md | This factual appendix preserves earlier results and distinguishes current, historical, mocked, blocked and unavailable checks |

No secret values were reported. The bounded scanner found no prohibited source/artifact
patterns, not proof of no secrets. Qualification scripts must run without Python
optimization: their scan-result assertions are part of verification, not production
release authorization. No unrelated file, reference content, historical evidence or
existing release artifact was changed. Protected comparisons cover regular-file bytes
and membership, not every filesystem metadata attribute.

### Current mandatory gate status

| Gate | Status | Remaining prerequisite |
|---|---|---|
| Current local suite and focused shutdown regressions | PASS | 460/60 tests, actual process exits; remote validation separate |
| Committed-main verification CI | FAIL | Both recorded runs segfault after startup PASS |
| Local repair tested by GitHub | BLOCKED | Reviewed source must become available under later explicit commit/push authorization |
| Branch/environment/release workflow protection | FAIL | Owner configuration and negative approval/check tests above |
| Provider deterministic tests | PASS | Mocked only |
| Live external provider qualification | BLOCKED | Owner-configured accounts and explicitly authorized public scope |
| Real full-range/privileged Nmap | PASS, prior scoped evidence | Prior isolated lab record retained; not rerun in this review |
| Kali and Parrot lifecycle / genuine upgrade | BLOCKED | Disposable desktop guests/snapshots and authenticated prior supported artifact |
| Production APT signing/trust and maintainer identity | BLOCKED | Independent public-key trust, real identity/hosting, approved protected signing procedure |
| Reviewed exact-source provenance / independent reproducibility | BLOCKED | Reviewed commit, exact rebuild and independent provisioned environments |
| Current independent archive/installed packaging/desktop rerun | NOT RUN | Prior results do not qualify this changed source |
| Production signing/publication/deployment | NOT RUN | Explicitly prohibited; no action taken |

Git remains main at e0fca076 with nine modified tracked files and four untracked patch
files; index empty. **NOT APPROVED — REQUIRED GATES REMAIN.**


## Final exception-path and exact local snapshot review — 2026-10-12

New evidence: `.release-qualification/ci-shutdown-final-20261012/` (Q below).
Earlier sections remain unchanged historical observations. This section records the
latest local source; production is **NOT APPROVED / BLOCKED**.

### Smallest additional repair and ownership trace

CLI's no-subcommand path constructs the repository and calls gui.launch. Window
owns its child widgets; diagnostics/scan/local-job signal owners must survive until
queued completion callbacks drain. app.quit can return from the event loop without
closeEvent; closeEvent requests cancellation and defers closing while jobs remain.
launch explicitly closes the window, processes callbacks, waits for the pool, then
posts and flushes widget deletion while QApplication is still alive. This prevents
leaving those windows solely to interpreter teardown in the tested shutdown paths.

The incoming patch only performed that cleanup after a normal app.exec return.
The smallest additional change wraps app.exec in try/finally using the existing
cleanup block; original event-loop exceptions propagate after successful cleanup.
A new subprocess regression injects an event-loop ValueError while diagnostics are
pending and verifies the original exception, finished diagnostics, no active pool
threads, no top-level widgets and real process exit 0. Diagnostics now start after
refresh_projects succeeds, avoiding starting a worker before fallible project setup.
Both existing successful/failing early-quit regressions are preserved exactly.
Only gui.py, its existing new regression file and this report changed in this turn.

The native fault remains **unresolved at the exact Qt/Shiboken function level**.
The prior ablation supports widget lifetime/deferred teardown as a working diagnosis;
it does not prove a particular upstream binding defect or native instruction. The
local repair is verified for recorded cases, not remotely qualified. Bounded shutdown
timeouts still raise failure; no forced success, signal suppression or os._exit is used.

### Fresh local execution

All positive checks below exited 0. The baseline negative control exited 1 as expected.
Exact absolute argv, cwd, per-command exit codes and complete output logs are preserved
in Q/commands.json and Q/<check>.log. PYTHON denotes the qualified local venv interpreter.

| Check / command | Actual result | Evidence |
|---|---|---|
| `QT_QPA_PLATFORM=offscreen PYTHON -m pytest -q tests/test_production_gate_completion.py --junitxml=Q/focused.xml` | **61 passed**, 5.66s, exit 0 | focused.log/xml |
| `QT_QPA_PLATFORM=offscreen PYTHON -m pytest -q --junitxml=Q/checkout.xml` | **461 passed, 0 failed, 3 skipped**, 31.65s, exit 0 | checkout.log/xml |
| Baseline source: `PYTHON -m pytest -q tests/test_production_gate_completion.py -k quit_during_diagnostics` | **2 failed, 59 deselected**, 1.33s, exit **1** | baseline-negative.log; fresh git archive of HEAD |
| Independent new source archive: `PYTHON -m pytest -q --junitxml=Q/archive.xml` | **460 passed, 0 failed, 4 skipped**, 34.87s, exit 0 | archive.log/xml |
| `go test -race -count=1 -v ./...` in workers/dns | **6 passed**, exit 0 | go-race.log |
| `go vet ./...` in workers/dns | No diagnostics, exit 0 | go-vet.log |
| `CGO_ENABLED=0 go build -trimpath -buildvcs=false -o Q/packages/cyberrecon-dns .` | PASS, exit 0 | go-build.log |
| `PYTHON -m build --no-isolation --outdir Q/packages` from Q/source | Wheel and sdist built, exit 0 | build.log |
| `PYTHON scripts/build-cyberrecon-deb.py --output Q/packages --worker Q/packages/cyberrecon-dns` from Q/source | Debian built, exit 0 | deb.log |
| `PYTHON -m twine check Q/packages/cyberrecon-0.2.0-py3-none-any.whl Q/packages/cyberrecon-0.2.0.tar.gz` | Both PASS, exit 0 | twine.log |
| `PYTHON scripts/verify_release_inputs.py --root Q/source --artifacts Q/packages` | 33 runtime sources; metadata/assets/entry point/source inputs PASS; zero legacy imports, exit 0 | inputs.log |
| `PYTHON scripts/check_release_security.py --artifacts Q/packages` from Q/source | 128 archive-source files / four artifacts, exit 0 | security.log; heuristic limits apply |
| `PYTHON scripts/prepare_cyberrecon_release.py --checksums Q/packages` then `sha256sum -c SHA256SUMS` in Q/packages | Four candidate payloads match, both exit 0 | checksums-create.log, checksums.log |
| `sha256sum -c SHA256SUMS` in protected dist | All five existing entries OK, exit 0 | existing-checksums.log |
| `PYTHON -m pip install --no-index --no-deps --target Q/wheel-site Q/packages/cyberrecon-0.2.0-py3-none-any.whl` | Fresh target install, exit 0 | wheel-install.log |
| `QT_QPA_PLATFORM=offscreen PYTHONPATH=Q/wheel-site PYTHON Q/verify_wheel.py` from /tmp | Installed CLI version/help/module, 34 runtime/asset bytes, legacy import guard, offscreen GUI and shutdown PASS; zero critical Qt messages, exit 0 | wheel-gui.log; wheel-final.json |
| `git diff --check` / empty staged-file listing | Exit 0 / no staged files | commands.json and final status |

The three checkout skips concern absent production workflows; archive adds absence of
its optional worker executable. Go source is included and was separately built/tested.
No tests or security assertions were removed or relaxed. Baseline negative-control
failures are genuine test failures against old source, not failures hidden in the
positive total. Provider coverage in these suites uses deterministic mocks and owned
fixtures; no live provider account or external target was qualified.

Fresh build source was git archive HEAD plus explicit overlays of all 13 changed files.
SOURCE_DATE_EPOCH was the baseline commit timestamp; CGO_ENABLED=0 for worker builds.
This single build does **not** establish independent reproducibility or reviewed-commit
provenance. Fresh build/installation outputs exist only under Q, not protected dist.
The archive contained this report before the present appendix; current runtime bytes
match the tested installed wheel, while final documentation requires a reviewed rebuild.
Qualified venv dependencies were reused; fresh OS dependency resolution, xcb installed
menu/desktop lifecycle and independent provisioned builds were NOT RUN.

### Remote qualification: precise blocker and owner action

Read actual run 38197452582 again with
`gh run view 38197452582 --repo naresh1807/CyberRecon --log-failed` (exit 0).
It is still **FAIL**, headSha e0fca076044343d442fe694aebaf5f24e88fd3a8:
400 passed / 3 skipped, startup PASS followed by SIGSEGV and shell exit **139**.
Read its identity/status and remote workflow with GitHub APIs; exact read commands
and exits are in Q/remote-commands.json, outputs in Q/remote-*.log.
No new remote run was dispatched in this continuation because rerunning unchanged
baseline cannot qualify the changed source.

The only remote workflow is verify.yml: it checks out the selected committed ref.
workflow_dispatch has **no inputs**, and there is no existing reviewed mechanism to
receive or validate a local patch/source archive. Reruns use the old source SHA.
Uploading an ad-hoc executable patch or changing the workflow remotely would not
meet the authorized-source requirement and is not performed. No suitable remote
patch transport is available under the current no-commit/no-push/no-settings constraints.
**Remote qualification of the exact patch is BLOCKED.**

Required owner action, not authorization assumed by this report:

1. Independently review the final 13-file diff and recorded tests. Explicitly authorize
   making that exact reviewed source available in the repository, or perform the
   reviewed commit/push themselves. Preserve history and require ordinary protections;
   no force push, release tag, package publication or signing is needed for verification.
2. After an approved source ref exists, execute the existing verification-only workflow
   for that ref (`gh workflow run verify.yml --repo naresh1807/CyberRecon --ref main`
   only if main is the approved ref). Record the actual run ID and full headSha.
3. Verify headSha equals the reviewed source commit, test counts include the 61 current
   focused cases, both early-quit regressions and exception regression execute, startup
   ends with process exit 0, and all downstream build/security/checksum/dry-run steps
   succeed. Preserve logs and bind artifacts to that reviewed source; merely printing
   PASS before teardown is insufficient. Existing CI's dry-run step is validation only.
4. Keep production qualification blocked until separately required protections,
   lifecycle, provider, upgrade, trust, provenance and reproducibility evidence passes.

Read-only current controls still show no active main rules, no environments and only
verification CI. Earlier owner configuration instructions remain recommendations;
no GitHub setting was changed. The protected-workflow qualification gate remains
**BLOCKED** (the observed absence of controls is a failing configuration audit).

### Entire-patch review and current decision

All 13 files were re-inspected. Runtime changes are limited to credential-safe provider
observations and Qt lifecycle handling; packaging adds the build-only canonical sdist
hook and required-source checks. The workflow only adds a reproducible epoch and keeps
read-only, non-publishing permissions. Release requirements remain **26 fail-closed
gates**, including all five added gates; mocked PASS fixtures do not qualify a release.
Signature status checks still reject revoked/expired/error markers. No weakening of
scope, TLS, credential handling, tests, publication protections or artifact pruning
was found in the reviewed diff. Secret scanners are bounded heuristics, not proof that
unknown or encoded secrets are absent. Historical evidence was not rewritten.

| Qualification item | Current status |
|---|---|
| Current local suite, early quit, exception cleanup, archive and packaging checks | **PASS**, scoped local evidence above |
| Committed-main remote CI | **FAIL**, reproduced 139 in recorded remote runs |
| Exact changed source tested remotely | **BLOCKED**, reviewed remote source unavailable under current authorization |
| Live external providers | **BLOCKED**, account configuration and authorized live scope unavailable |
| Kali/Parrot fresh install, reboot, remove/purge/reinstall | **BLOCKED**, disposable suitable guests unavailable |
| Genuine previous-version upgrade | **BLOCKED**, authenticated previous supported artifact unavailable |
| Production signing / trusted maintainer and public key | **BLOCKED**, independently trusted infrastructure/evidence unavailable |
| Reviewed source-to-artifact provenance | **BLOCKED**, changes remain uncommitted and reviewed exact rebuild pending |
| Independent reproducibility | **BLOCKED**, no independent provisioned builds for this final source |
| Protected release workflow | **BLOCKED**, owner configuration and protected workflow qualification absent |
| Production signing, publication, deployment | **NOT RUN**, prohibited |

Final changed-file inventory remains nine modified tracked paths and four untracked
paths, with no staged files. The only additions within this continuation are exception
cleanup, startup ordering, one regression and this evidence appendix. No commit, push,
tag, signing command, publication, deployment or GitHub settings mutation occurred.
Final protected regular-file hash results are recorded in Q/integrity.json; the original
CyberIntel project, reference files, historical evidence and existing artifacts remain
protected. Final status: **NOT APPROVED / BLOCKED**.
