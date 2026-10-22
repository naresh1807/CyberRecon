# Reconnaissance engines — local repair and use

Production release remains **NOT APPROVED / BLOCKED**. These changes do not qualify installation, upgrade, reboot, purge, signing or distribution release. The pre-change root-cause audit is [ENGINE_REPAIR_AUDIT.md](ENGINE_REPAIR_AUDIT.md). Current execution evidence is kept separately under `.release-qualification/engine-repair/`; prior readiness reports and release artifacts remain historical.

## Launch and authorization

Use the supported Python >=3.12 virtual environment with the declared dependencies (`pip install -e '.[dev]'` inside that environment), then run `python -m cyberrecon`. Desktop Start Recon runs bounded DNS, HTTP/TLS, technology checks, web discovery and a passive public certificate-transparency (CT) lookup by default. CT results are historical observations, not proof of current DNS. Child names outside Allowed scope are discarded; add wildcard scope only when expressly authorized. Historical URL, lifecycle/NVD, active DNS wordlists and OS/UDP/NSE checks remain explicit opt-ins. CLI CT discovery remains explicit through `--passive`. Scope/settings exposes Nmap profiles, timing, timeouts, probe rate, optional OS/default-and-safe NSE, providers, DNS controls and wordlists. A supplied domain does **not** authorize active port scanning of its resolved addresses. Include exact authorized IPs separately and use an IP target for Nmap. Authority text must refer to ownership or written authorization.

CLI examples below use placeholders: replace `AUTHORIZED_IP`, `AUTHORIZED_DOMAIN`, and `PROJECT_ID` with targets you are expressly authorized to test. Do not execute them against arbitrary targets.

```sh
python -m cyberrecon --doctor --home ./local-workspace
python -m cyberrecon --home ./local-workspace project owned --include AUTHORIZED_IP --authority 'Ownership or written authorization reference'
python -m cyberrecon --home ./local-workspace scan http://AUTHORIZED_IP/ --project PROJECT_ID --ports '' --nmap-profile quick --nmap-unprivileged
python -m cyberrecon --home ./local-workspace scan http://AUTHORIZED_IP/ --project PROJECT_ID --ports 80,443 --nmap-profile service --nmap-unprivileged
python -m cyberrecon --home ./local-workspace scan http://AUTHORIZED_IP/ --project PROJECT_ID --ports '' --nmap-profile full --nmap-timeout 600 --nmap-host-timeout 600 --nmap-rate 100 --nmap-unprivileged
```

Quick selects top-100 TCP unless custom ports are provided; service adds light version detection; full selects TCP 1–65535 and rejects custom port lists and UDP. Custom profiles retain the 1000-port safety bound. Full does not imply completed coverage: timeouts, down hosts, missing/failed output and mismatching XML counts remain partial. XML lists individually reported states and aggregate extraports separately; aggregate counts never fabricate individual rows. All profiles retain bounded parallelism and have no evasion flags. Timing is 0–4, overall/host timeouts 10–600 seconds, explicit maximum probe rate 1–1000. Defaults are intentionally conservative and may be insufficient for full-range coverage.

For already privileged, explicitly authorized use, `--nmap-os` requests OS hints and `--nmap-scripts` requests **default AND safe** NSE. The application never elevates privileges. UDP uses `--udp --ports 53,123` with a quick/service profile and suitable existing privileges; it may be much slower and yield inconclusive states. Do not combine UDP/OS with unprivileged mode. Real full-range/privileged qualification is NOT RUN; argument/XML/privilege behavior is covered by fixtures.

For domain discovery, authorize both the apex and intended wildcard scope:

```sh
python -m cyberrecon --home ./local-workspace project domain-owned --include AUTHORIZED_DOMAIN --include '*.AUTHORIZED_DOMAIN' --authority 'Written domain scope'
python -m cyberrecon --home ./local-workspace scan https://AUTHORIZED_DOMAIN/ --project PROJECT_ID --passive ct,subfinder,assetfinder --crawl --max-hosts 100 --max-pages 100 --max-depth 3 --max-requests 300 --rate 2
python -m cyberrecon --home ./local-workspace scan https://AUTHORIZED_DOMAIN/ --project PROJECT_ID --dns-wordlist ./authorized-labels.txt --check-wildcard
python -m cyberrecon --home ./local-workspace export SCAN_ID ./reports
```

DNS wordlists accept at most 200 single labels; content wordlists (`--wordlist`) accept at most 200 relative paths without traversal/query fuzzing. They are opt-in. Default budgets: 30 hosts (supplied target prioritized), 30 pages/host, depth 2, 100 shared HTTP requests, 2 HTTP requests/second. CLI supports up to 5000 hosts, 500 pages/host, depth 5, 500 shared HTTP requests and 10 HTTP requests/second. Raising limits does not make discovery exhaustive. Names outside scope are never actively processed; omitted hosts remain visible with incomplete coverage warnings.

## Implemented behavior and limits

| Engine | Behavior | Limit |
|---|---|---|
| Nmap | Strict IP argv, quick/service/full profiles, XML states/product/version/confidence, aggregate coverage, raw complete/incomplete XML | Nmap required; 16-MiB output bound; only fully closed hosts can be recovered from truncated XML; raw corrupt bounded output retained without invented findings |
| Subdomains | Aggregate selected CT/Subfinder/Assetfinder/Amass adapters, normalize, deduplicate and preserve provider sources/timestamps; independent failures | CT primary/fallback pagination is provider-dependent; CLI tools and their configured environment credentials are optional; Amass adapter requires verified v3; no global completeness claim |
| DNS | A/AAAA/CNAME/MX/NS/TXT/CAA, multiple IPs, TTL, CNAME chains, PTR for literal IPs, distinct NXDOMAIN/no-answer/timeout/failure, opt-in two-label wildcard controls | Two resolver workers, 3-second query lifetime; DNS retries remain library-controlled; TXT values are hashed/redacted; wildcard comparison is a heuristic and rotating CDN answers may evade it; shared IPs do not establish ownership |
| Fingerprints | Independent project-owned MIT rules for server/runtime/CMS/frontend/library/CSS/build/CDN/auth/API indicators; category, Unknown version, timestamp, rule/hash evidence | Compact native rules, not the Wappalyzer dataset; spoofable indicators stay Likely; Confirmed refers to observed formats or Nmap probes, not private architecture; databases and unobservable backend details stay Unknown |
| Crawl | Links/assets, forms inventoried but never submitted, robots, sitemap indexes, JS routes, linked JSON routes, public source-map metadata, redirects and historical URLs | No browser execution; dynamic routes may be missed; depth/budgets/TLS/scope enforced; logout/state-changing paths and common credential/key filenames are excluded; source contents and secret assignments are not retained |
| APIs | Static fetch/axios routes, observed HTTP API surfaces, public OpenAPI/Swagger method and per-operation auth declarations, GraphQL path indicators | Candidates and declared methods do not establish reachability/auth correctness; methods other than discovery GET/HEAD/OPTIONS are never sent; no account enumeration or authorization bypass; specification paths capped at 500 with warnings |
| Orchestration | Unique jobs, incremental SQLite observations, persisted stage status/settings, real progress, live dashboard updates, independent failures, cancellation, managed JSON and user-requested CSV/HTML/PDF/graph exports | Stage completion means selected bounded work completed; reports stage refers to managed JSON, not automatic PDF generation; skipped and partial stages remain visible; report-write failure leaves partial status and preserves DB observations |
| Dashboard | 17 sections including dedicated URLs, APIs, frontend/backend and coverage; six actual-count cards, filters/sort/pagination/details and original export evidence | Geolocation/registrar/private database details remain uncollected; browser-request collection and screenshots are unsupported |
| Go | Existing optional validated A/AAAA worker; errors/missing worker do not erase Python results | Supplemental maximum 30 hosts; Python inventories the selected DNS hosts independently; no Go worker bundled into Python wheel |

Required Python packages remain those in `pyproject.toml`. No extra runtime dependency was introduced. Nmap 7.99 and Python 3.14.7 were available locally on Kali 2026.3. Subfinder, Assetfinder, gau and waybackurls were absent; Amass's version probe failed. Provider behavior was mocked, not externally qualified. Parrot and disposable distro lifecycle environments remain unavailable. Ruff/mypy are not installed; AST/security checks are narrower substitutes, not lint/type-check certification.

## Repeatable verification

```sh
QT_QPA_PLATFORM=offscreen .release-qualification/venv/bin/python -m pytest -q
(cd workers/dns && go test -race -count=1 -v ./... && go vet ./...)
.release-qualification/venv/bin/python scripts/verify_cyberrecon_engines.py --output .release-qualification/new-owned-engine-run
.release-qualification/venv/bin/python scripts/verify_cyberrecon_dashboard.py --desktop --output .release-qualification/new-owned-desktop-run
.release-qualification/venv/bin/python scripts/check_release_security.py
 git diff --check
```

Both verification scripts create their own loopback listeners and fresh workspaces; Nmap targets only the owned HTTP port. DNS uses reserved `.test` names and an owned UDP listener. Engine verification performs real DNS, HTTP, quick/service Nmap and exports; the unrelated system PTR lookup is mocked. Desktop verification performs real HTTP/Nmap, navigation, size/filter/detail/export/cancellation checks; its unrelated PTR is also mocked. Neither script performs system package lifecycle operations or release qualification. Use a fresh output path to preserve prior evidence.

Current verification totals, commands, exit codes, protected-content comparisons, wheel checks and any remaining failures are recorded in `ENGINE_REPAIR_AUDIT.md` after execution. Historical failed fixture runs are retained alongside successful corrected runs. No artifacts are uploaded and no commits/tags/releases are created.
