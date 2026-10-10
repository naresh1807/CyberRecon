# CyberRecon user manual

Install and launch using README.md. The console entry point is `cyberrecon`; the module entry point is `python -m cyberrecon`. The GUI opens when no subcommand is supplied.

## Authorized projects

Create a project with a descriptive name, explicit `--include` rules and a nonempty `--authority` reference. Repeat `--include` or `--exclude` for multiple rules. Rules accept domains, wildcard subdomains, individual IPs and bounded CIDRs. Exclusions win. Internet-wide inclusion is rejected. A wildcard excludes the apex for active requests; passive CT lookup can query the apex to discover authorized descendants.

The default workspace is `~/.local/share/cyberrecon` (or the configured home); pass `--home` before the subcommand to select another directory. Keep sensitive evidence in a private workspace on encrypted storage. Use `projects`, `scans PROJECT_ID` and `compare BEFORE_SCAN_ID AFTER_SCAN_ID` to inspect stored work. Use `scope-import PROJECT_ID scope.json` to replace scope from JSON include/exclude arrays.

## Scanning

`scan TARGET --project PROJECT_ID` collects bounded observations. Targets accept validated domains, IPs or HTTP(S) URLs without credentials. Use `--passive ct` for public certificate observations; optional subfinder, assetfinder and verified Amass v3 adapters need installed tools. `--history gau` or `waybackurls` imports scoped historical URLs. Third-party providers receive the queried target; CT records do not prove a live host.

HTTP scans enforce exclusions on resolved IPs and each redirect. Private targets require explicit IP scope as well as hostname scope. Use `--ca-bundle lab-ca.pem` for an owned lab with a private CA; this adds trust rather than disabling certificate checks. `--crawl` and `--wordlist` enable bounded scope-controlled requests. Wordlists accept at most 200 relative paths and the scanner's page budget still applies.

`--ports 22,80,443` enables Nmap against explicit IP targets only. Empty port text selects the top 100 TCP ports. Ranges and hostnames are not accepted as Nmap targets. Up to 16 same-family IPs and 1000 selected ports are allowed. `--udp` needs appropriate existing privileges; the app does not elevate itself. Keep scans within your authorization.

Optional `--lifecycle`, `--cve` and `host-intel` requests disclose limited product/CPE or authorized public-IP information to the selected providers. Review the command help and project scope first. Imported external observations use `import-engine ENGINE FILE --project PROJECT_ID --target TARGET`; imports do not authorize new active requests.

## GUI

Launch `cyberrecon --home /path/to/workspace`, select or create an authorized project, enter a target, and use the scan controls. Review scope, errors, evidence and Doctor alongside findings. Missing tools, partial scans and cancellation are preserved as such. Offscreen startup verification exercises window creation and event-loop shutdown without initiating scans; it does not replace display-platform validation.

## Exports and recovery

`export SCAN_ID DIRECTORY` writes reports and graph artifacts with atomic output handling and export validation. CSV formula-leading values and HTML content are escaped; cookie values are omitted from header findings. A failed export preserves existing output.

After stopping any scan processes, use `recover PROJECT_ID` to mark unfinished scans interrupted. Do not use recovery while another process is still scanning. Findings, banners, versions and configuration headers are observations requiring contextual review, not a security certification.

See README.md for dependencies, installation and supported limitations, and docs/DEVELOPMENT.md for deterministic tests.
