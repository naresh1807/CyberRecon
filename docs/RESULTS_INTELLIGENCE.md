# Results intelligence and accuracy audit — 2026-10-10

Production remains **NOT APPROVED / BLOCKED**. This report concerns local code and controlled fixtures, not production release qualification. Baseline HEAD: `3a87b0277f39703828bb3a32dc2d60dc15a80916`; the working tree was clean before this task. No commits, pushes, tags, release artifacts or historical evidence are changed by this work.

## Audit and prioritized improvements

| Priority | Actual limitation | Implemented behavior / regression |
|---|---|---|
| P1 | Repository save merged attributes last-writer-wins and lost earlier evidence/confidence | Distinct source assertions, confidence, timestamps and historical flags are retained; duplicate assertions coalesce. Evidence lists merge. Unified conflicts are explicitly marked for review. |
| P1 | No shared result contract; exports and details required engine-specific interpretation | `cyberrecon/results.py` projects stable asset IDs, scan-specific result IDs, target/host/IPs/port/protocol, category/title/description, severity/confidence, provenance, timestamps, verification, profile, coverage, limitations and next steps. Missing fields use Unknown. Original observations remain accessible; no schema migration is required. |
| P1 | Observed API GET lacked a methods list and could collide with an unknown-method candidate | Actual observed GET has a method-specific identity; documented POST remains unverified. API claims now attach response hash/source evidence; examples and secret values remain omitted. |
| P1 | Redaction collapsed query-value candidates | Ephemeral keyed IDs preserve distinct candidate variants without storing or sending values. Variants are unverified even if the redacted URL was fetched. Cross-scan variant identity is explicitly INCOMPARABLE, not guessed. |
| P1 | Comparison labelled absent records REMOVED | NOT_OBSERVED includes scan statuses and coverage caution. Optional PERSISTENT records support GUI history; a failed provider is not evidence of removal. |
| P2 | Fingerprint rules took only the first match and overwrote versions | Bounded matches retain all public version indicators. Conflicting versions become Unknown, with evidence and version status. Independent source types raise the descriptive confidence level, never a calibrated probability or product verification. |
| P2 | Nmap native confidence was overwritten by repository confidence | Native service_confidence is preserved separately. XML duplicates coalesce by IP/protocol/port; conflicting assertions remain accessible and make coverage partial. TCP and UDP remain distinct; unobserved ports are never closed by inference. |
| P2 | DNS detail views omitted failure/timestamp evidence | Multi-IP projections attach the actual resolution summary and DNS records. Unresolved, unverified and incomplete are distinct. Sources, lookup times, wildcard controls and record statuses remain available in details. |
| P2 | Finding detail metadata was incomplete | Header-review and JavaScript-pattern findings now provide title, explanation, impact/false-positive context, verification and remediation. They remain review items, not confirmed exploitable vulnerabilities. |
| P2 | Search was per-view; default page rendered up to 1000 rows | All Results supports global search, severity/confidence/source/verification/scan filters and original evidence details. Search serialization is cached and pages render at most 50 rows; overview pages remain 8. |

## Contract and evidence policy

`Repository.snapshot()` adds `results` without replacing the original engine lists. `results.json`, HTML and PDF include the same unified records. JSON, CSV, HTML and PDF retain the original observations as well. Evidence integrity is verified before an explicitly requested managed tool-output preview; previews are limited to 65536 bytes and labelled when truncated. Evidence paths must belong to the selected scan; symlinks, tampered bytes and cross-scan paths are rejected. No evidence file is executed. Existing records that lost earlier evidence before this change cannot have that evidence reconstructed.

Conflicting source assertions are preserved, not assigned arbitrary severity or numeric confidence. The compatibility observation retains the latest attributes; the unified result exposes conflicting fields and each source assertion for review. Source assertions can grow when an engine genuinely reports different attributes; identical assertions do not grow the list.

Hostname/IP joins and shared-IP counts are correlations, not proof of infrastructure ownership, common backend, vulnerabilities or permission to scan another asset. Private architecture, registrar, geolocation, ASN, unsupported versions and missing evidence remain unknown. Scope authorization and DNS pinning are unchanged.

## Existing verified behavior and remaining limitations

Existing bounded XML recovery, explicit Nmap range/profile/coverage metadata, XML preservation, privilege checks and scan-stage errors remain in place. Existing subdomain normalization/provider attribution, A/AAAA/CNAME/MX/NS/TXT/CAA inventory, opt-in wildcard controls and DNS failure handling remain in place. TXT is hashed rather than exported verbatim. Existing public HTML/JS/robots/sitemap/OpenAPI extraction, negative-control content discovery, scope checks, GET-only crawling and cancellation remain in place.

Provider coverage is configured-source-only and never exhaustive. Wildcard controls are heuristic and can be inconclusive for rotating DNS. Fingerprints are a compact project-owned rule set, not complete technology coverage; headers, cookies and assets can be spoofed. Query values are never retained or requested; candidate keyed identities are meaningful only within one scan. The actual redacted URL request does not test the original endpoint behavior with its original values. Browser-executed routes, authenticated APIs and screenshot collection remain unsupported. Full-range/privileged Nmap, external provider production qualification, Kali/Parrot lifecycle/upgrade, trusted production signing, reviewed-source reproducibility and protected release workflow remain blocked.

## Reproduction

Use `.release-qualification/venv/bin/python` and fresh output directories. Evidence for this task is under `.release-qualification/results-intelligence/`. Tests use deterministic mocks or process-owned loopback fixtures; no unauthorized external scans or destructive host transactions are performed. Historical engine/readiness reports are preserved and are not treated as current results.

- `QT_QPA_PLATFORM=offscreen python -m pytest -q`
- `(cd workers/dns && go test -race -count=1 -v ./... && go vet ./...)`
- `python scripts/verify_cyberrecon_dashboard.py --output FRESH --desktop`
- `python scripts/verify_cyberrecon_engines.py --output FRESH`
- `python -m build --no-isolation --outdir FRESH`
- `python -m twine check FRESH/*.whl FRESH/*.tar.gz`
- `python scripts/check_release_security.py --artifacts FRESH`

Final counts, measured performance and protected-file comparisons are appended after execution. Tool absence or interruption is not a pass.

## Shutdown defect found during qualification

The first post-change desktop process printed successful functional checks but exited 139 during interpreter teardown. That run is **FAIL**, irrespective of the JSON status. A fast wheel smoke check also observed an asynchronous diagnostic attempting to emit a signal after its source was deleted. Those outputs are preserved in the local evidence directory. Window closing now requests cancellation and defers destruction while jobs remain active; queued completion callbacks continue to drain. The dashboard verification script explicitly disposes widgets before QApplication teardown. A regression verifies deferred close and successful local-worker signal delivery. Final qualification requires both functional checks and process exit 0.

Final code review also found that a later historical provider assertion could clear a previously observed verification flag, despite keeping CURRENT status. Positive observations within the scan now remain preserved, with the historical assertion retained separately. Optional malformed/null URL, hostname, port and severity fields are projected as Unknown while their original values remain accessible; controlled regressions cover these cases.

All Results searches the selected scan across engine kinds; older scans remain selectable through project history. This is not an unrestricted search across every workspace/project. Query-value variants are intentionally incomparable across scans.

## Final executed results

- Checkout: **384 passed, 0 failed, 0 errors, 3 skipped**, exit 0; `pytest-robust.log/xml/exit`, 22.57 seconds.
- Independent final source archive: **383 passed, 0 failed, 0 errors, 4 skipped**, exit 0; `archive-robust.log/xml/exit`, 23.34 seconds. The extra archive skip is the optional worker executable absent from the source archive; the other skips are unavailable production workflow checks.
- Go: **6 passed**, race, vet and verification-only build passed; `go-test.log`, `go-vet.log`, `go.exit`.
- Final live Kali GUI: **PASS**, xcb, 18 views, real owned loopback HTTP/Nmap, responsive layout, search/details, actual JSON/HTML/PDF exports, cancellation, failure display and clean process exit 0; `desktop-robust/verification.json` and `.exit`. Earlier GUI exit 139 is not counted as passing.
- Final owned engine integration: **PASS**, real process-owned DNS A/AAAA/CNAME/TTL/wildcard, quick/service Nmap, HTTP crawling, API/fingerprint results and exports; `owned-robust/verification.json`, exit 0. This is not full-range or privileged Nmap qualification.
- Final wheel/source builds, twine validation and bounded security checks: **PASS**, exit 0, 131 source files and 2 verification artifacts; `build-robust`, `twine-robust`, `security-robust`. Existing dist is untouched.
- Installed final wheel: **PASS** standalone imports with a legacy-import guard, 34 runtime/asset files byte-equal to the checkout, CLI --version/--help and module --version, offscreen GUI and clean shutdown. Dependencies were reused from the qualified venv; clean Kali/Parrot dependency installation is NOT RUN.
- AST parsing, qualification JSON parsing, existing artifact checksums and git diff --check: **PASS**. Ruff/mypy: **NOT RUN**, unavailable.
- Final benchmark: **5000 controlled URL fixtures**, not scan findings. Normalization 1.730s, table loading 0.656s, filtering 0.009s, 50 rendered rows and 1 match. Peak Python allocation 20,318,876 bytes excludes Qt native allocations and process RSS. No timing threshold is represented as a production capacity guarantee.

The original 22,555-file baseline and all 101 protected reference/dist hashes were compared without modifications. No staging, committing, pushing, signing, tagging or publication occurred. Summary evidence: `.release-qualification/results-intelligence/summary.json`; local evidence is not a public signed attestation. Interrupted suite attempts have no final result and are retained, not called passes.
