# Engine repair audit — 2026-10-10

Production release remains **NOT APPROVED / BLOCKED**. This audit precedes engine changes. Existing dashboard changes are preserved.

| Component | Observed root cause | Repair / verification |
|---|---|---|
| Nmap | Fixed top-100/light version profile; custom ports capped at 1000; missing successful runstats rejects all partial XML; failed subprocess discards its temporary artifact | Explicit bounded profiles, preserve incomplete evidence, record requested/reported coverage; XML, timeout, privilege, missing-tool fixtures and owned loopback service |
| Subdomains | One selected adapter; CT fallback/pagination exists but provider provenance and independent provider outcomes are not coordinated | Aggregate selected adapters, normalize/deduplicate, retain sources and failures; mocked provider success/failure |
| DNS | First 30 hosts only; NXDOMAIN/NoAnswer silent; no resolution summary or wildcard check | Configurable explicit bounds, every accepted host within those bounds, statuses, TTL/chains and opt-in wildcard/wordlist queries; deterministic resolver fixtures |
| Technologies | Unstructured self-reported banners and five filename patterns; no categories or classification | Independent evidence rules, safe cookie names, version Unknown, frontend/backend categories; negative and positive fixtures |
| Crawl/API | Robots/sitemaps fetched but not parsed; source maps only candidates; JS paths lack methods; API records keyed by URL | Parse bounded public discovery sources, exclude unsafe navigation, retain provenance, per-operation method/auth metadata without sending operations; scope/depth/rate fixtures |
| Orchestration/UI | String progress only, aggregate warnings; URLs/APIs share HTTP view | Persist per-stage outcomes and settings; dedicated views, source/coverage details and existing exports; cancellation/partial/UI regressions |

Planned files: `nmap_scan.py`, `engines.py`, `scanner.py`, `api.py`, `network.py`, `storage.py`, `dashboard.py`, `gui.py`, `cli.py`; new modular discovery/fingerprint/stage helpers, engine regression tests, this report and a verification script. No original project, reference contents, old release evidence or dist artifacts will be changed.

Dependencies observed: Python 3.14.7 and all declared Python packages available; Nmap 7.99 available; Go installed. Subfinder, Assetfinder, gau, waybackurls absent; Amass version probe failed. External providers will be mocked; no internet target scans. No new third-party fingerprint database is copied; project-owned MIT rules are independently updateable. Parrot and disposable distro lifecycle qualification are NOT RUN. Ruff/mypy unavailable.

Verification plan: targeted deterministic regressions, complete existing Python suite, Go test/race/vet, AST/build/package checks in a separate qualification directory, real HTTP/Nmap on a server created and owned by the verification process, GUI offscreen/local launch, original/reference/dist before/after content hashes. Production signing and release gates remain blocked; no commit/push/publication.

Nmap reference: https://nmap.org/book/output-formats-xml-output.html (XML primary and service confidence); https://nmap.org/book/man-performance.html (timeouts may skip hosts); https://nmap.org/book/man-nse.html (default scripts are not all safe; use default-and-safe selection explicitly).

## Executed repair and qualification results

The audit above is the pre-change record. The following results were executed against the repaired local source. **Production remains NOT APPROVED / BLOCKED.** All commands ran in the standalone project unless a different working directory is stated.

| Check / exact command | Observed output | Exit / status |
|---|---|---|
| `QT_QPA_PLATFORM=offscreen .release-qualification/venv/bin/python -m pytest -q --junitxml=.release-qualification/engine-repair/pytest-final-verified.xml` | `362 passed, 3 skipped in 25.05s`; failures/errors 0 | 0 / PASS |
| Same Python `-m pytest -q --junitxml=.../pytest-source-verified.xml`, cwd `.release-qualification/engine-repair/source-verified/cyberrecon-0.2.0` | `361 passed, 4 skipped in 29.82s`; archive runtime import independently checked; failures/errors 0 | 0 / PASS |
| `go test -race -count=1 -v ./...`, cwd `workers/dns` | Six named tests passed; `ok cyberrecon/dns-worker 1.039s` | 0 / PASS |
| `go vet ./...`, cwd `workers/dns` | No diagnostics | 0 / PASS |
| `.release-qualification/venv/bin/python scripts/verify_cyberrecon_engines.py --output .release-qualification/engine-repair/owned-release-final` | PASS: real owned DNS addresses/TTL/CNAME/wildcard/redaction, quick/service HTTP/Nmap XML, routes/API/fingerprints and JSON/HTML/PDF/CSV/graph exports | 0 / PASS |
| `.release-qualification/venv/bin/python scripts/verify_cyberrecon_dashboard.py --desktop --output .release-qualification/engine-repair/desktop-verified` | PASS on Kali 2026.3 X11/xcb; 17 sections, real HTTP/Nmap cards, filters/detail/export, cancellation/failure state, narrow layout; no Qt critical errors | 0 / PASS |
| `.release-qualification/venv/bin/python -m build --no-isolation --outdir .release-qualification/engine-repair/package-verified` | Wheel and sdist successfully built; historical `dist/` untouched | 0 / PASS |
| `.release-qualification/venv/bin/python -m twine check .release-qualification/engine-repair/package-verified/*` | Both packages PASSED | 0 / PASS |
| `.release-qualification/venv/bin/python scripts/check_release_security.py --artifacts .release-qualification/engine-repair/package-verified` | 128 source files and 2 artifacts checked; PASS (bounded credential/AST/archive heuristic, not complete security certification) | 0 / PASS |
| `pip install --no-index --no-deps --target .release-qualification/engine-repair/wheel-verified .../package-verified/cyberrecon-0.2.0-py3-none-any.whl` via qualification Python | Wheel installed; CLI `--version`, `--help`, module `--version` return 0; GUI shows 17 sections from `/tmp`; legacy imports blocked in GUI/import process; all 32 runtime modules and SVG match source | 0 / PASS; existing qualification dependencies reused |
| `git diff --check`; `git diff --cached --name-only` | No whitespace errors; no staged files | 0 / PASS |
| `(cd dist && sha256sum -c SHA256SUMS)` | Manifest, wheel, sdist, worker and Debian package all OK | 0 / PASS |
| Python AST parsing | 32 runtime modules, 19 scripts, 30 test/support files parsed | PASS |
| Original/reference preservation | Original 22,555 regular-file hashes match baseline; current regular-file set identical (0 added/removed/modified). Reference 95 files and dist 6 files match before-task hashes | PASS |

Target skips: three absent production-publishing-workflow checks. Source archive adds the optional built Go-worker integration skip. No security assertion was removed. The existing dashboard test now expects the four additional requested result views and canonical/evidence-backed jQuery records.

### Additional defects found and fixed

* The first independent archive run reported **339 passed, 4 skipped, 21 setup errors**, then exited 139 during Qt teardown. The archive omitted `tests/conftest.py`, including the application-lifetime fixture. `MANIFEST.in` now includes test/support Python files, and `tests/test_source_archive.py` builds a real offline sdist and verifies every shipped test/support module byte-for-byte. Failed archives/logs remain retained; the repaired independent archive run above passes.
* Provider aggregation initially lost the structured tool-missing code; it now preserves the provider error code and independent outcomes.
* OpenAPI surface observations initially interfered with documented-operation selection; these are distinct. Off-scope specification servers never produce invented local operations, and bounded spec coverage is disclosed.
* A wordlist scope helper defect was caught by a pre-request scope regression and fixed.
* The supplied target is prioritized within the host budget. Wildcard-control failures preserve valid web/DNS observations rather than terminating all work.
* Full TCP requires XML coverage/count evidence, not just a successful finish marker. Partial/invalid XML preserves bounded raw evidence and never fabricates missing rows.
* Failed managed report generation preserves database observations and marks the job partial/report stage failed. Live dashboard reports/selectors refer to the actual running job.
* The first integrity probe assumed `shield.svg`; it was corrected to compare the actual asset, `cyberrecon.svg`. The final wheel check validates actual source/asset bytes.
* The first owned DNS fixture used relative RRset names and failed. Absolute `.test.` RRsets corrected the fixture; the failed run is retained and final real DNS verification passes.

### Files changed in this engine task

| Paths | Purpose |
|---|---|
| `cyberrecon/nmap_scan.py`, `cyberrecon/engines.py` | Validated profiles, safe argv/privilege handling, partial XML/raw artifacts, requested/reported port coverage, modular fingerprint adapter |
| `cyberrecon/subdomains.py`, `cyberrecon/dns_inventory.py` | Independent provider aggregation and source provenance, DNS status/TTL/CNAME/PTR, opt-in wordlist/wildcard controls |
| `cyberrecon/fingerprints.py`, `cyberrecon/discovery.py` | Project-owned evidence rules; safe bounded robots/sitemap/JS/JSON/source-map discovery |
| `cyberrecon/api.py`, `cyberrecon/network.py` | Method-aware API declarations/static candidates, scope/coverage/auth metadata, safe fingerprint headers |
| `cyberrecon/scanner.py`, `cyberrecon/stages.py`, `cyberrecon/storage.py` | Incremental bounded coordination, concurrent DNS, live scope checks, persisted independent stage outcomes, report-write failure handling |
| `cyberrecon/cli.py`, `cyberrecon/dashboard.py`, `cyberrecon/gui.py` | Explicit profile/budget controls, dedicated URL/API/frontend/backend/coverage views and live persisted-job rendering |
| `MANIFEST.in`, `tests/test_source_archive.py` | Complete source archive test support and real-archive regression |
| `tests/test_engine_repair.py`, `tests/test_dashboard.py` | Engine/security/coverage/cancellation/export regressions and updated view/fingerprint integration expectations |
| `scripts/verify_cyberrecon_engines.py` | Repeatable real qualification using process-owned listeners only |
| `docs/ENGINE_REPAIR.md`, this file | Root causes, use/profile instructions, exact checks, evidence limitations and next steps |

The previously uncommitted dashboard component, dashboard verifier, dashboard tests, conftest application lifetime and workflow table-filter changes were preserved. Nothing was staged, committed, pushed, tagged, signed, uploaded, deployed or published. Historical readiness JSON/documents were not rewritten. Qualification artifacts are local verification outputs, not new production candidates or reviewed-commit provenance.

### Remaining limitations and release gates

* Real full 65,535-port and privileged OS/UDP/NSE scans: **NOT RUN**; controlled XML/argv/privilege fixtures pass. Only owned single-port quick/service scans were executed.
* External passive provider reliability/credentials/coverage: **NOT RUN** against remote services; deterministic provider/CT pagination fixtures pass. Missing tools are disclosed, not silently replaced with success.
* Complete dynamic browser request collection and screenshots: unsupported. Native rules are a compact project-maintained set, not the Wappalyzer rule database. Private architecture, database internals, exclusive IP ownership and unavailable enrichment stay Unknown.
* Distro fresh install, desktop integration lifecycle, genuine previous-version upgrade/recovery, reboot, remove/purge/reinstall, clean distro dependency resolution, APT delivery and trusted production signatures: **BLOCKED / NOT RUN** on disposable Kali/Parrot systems.
* Independent trusted signing infrastructure, protected release identity/environment/repository gates and reviewed-commit artifact/source reproducibility/provenance: **BLOCKED**. These local dirty-source builds do not resolve them.
* Ruff/mypy: **NOT RUN**, unavailable. Dependency vulnerability audit is not claimed by the heuristic static check.

Next: review the local engine changes; qualify full/privileged profiles and configured providers on expressly authorized disposable labs; expand independently licensed/tested fingerprint rules as needed; complete the separately documented distribution lifecycle, signing and provenance gates before any release approval. See [ENGINE_REPAIR.md](ENGINE_REPAIR.md) for launch/profile commands and honest coverage limits.
