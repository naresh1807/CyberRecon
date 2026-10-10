# CyberRecon 0.2.0

CyberRecon is an independent desktop and CLI workspace for authorized, bounded reconnaissance. It stores scoped projects, observations, evidence, comparisons and reports locally. It does not require another project checkout or package.

## Installation

Python 3.12 or newer is required. From this directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/cyberrecon --version
.venv/bin/cyberrecon --help
```

For development, install `.[dev]` instead. Use virtual environments; do not install into OS-managed Python. Required Python libraries are PySide6-Essentials (QtCore/QtGui/QtWidgets), httpx, dnspython, defusedxml, networkx, numpy, plotly and reportlab. Linux GUI startup also needs the platform's Qt/display libraries. Nmap and passive CLI engines are optional system tools, checked by Doctor. The Go DNS worker is optional; see workers/README.md.

## CLI and GUI

```sh
cyberrecon --doctor
cyberrecon --home /path/to/private/workspace project "Owned lab" --include 127.0.0.1 --authority "Owned local lab"
cyberrecon --home /path/to/private/workspace projects
cyberrecon --home /path/to/private/workspace
```

Launching without a subcommand opens the GUI. `python -m cyberrecon` is equivalent. Project creation returns an identifier; use that identifier with subsequent commands. For an explicitly authorized local service:

```sh
cyberrecon --home /path/to/private/workspace scan http://127.0.0.1:8080/ --project PROJECT_ID
cyberrecon --home /path/to/private/workspace scans PROJECT_ID
cyberrecon --home /path/to/private/workspace export SCAN_ID /path/to/reports
```

Use `cyberrecon scan --help` for options and USER_MANUAL.md for details. Only assess systems you own or have explicit permission to assess. Record the authority and precise scope before requests. Domain authorization does not implicitly authorize Nmap against resolved IPs. Explicitly include lab IPs for private destinations.

## Functionality and limits

Supported features include CT discovery with provider fallback, bounded DNS/HTTP observations, header configuration review, optional TCP/UDP Nmap inventory, scoped external engine imports, limited crawling/content checks, technology candidates, optional host intelligence, report exports and offline relationship graphs. Missing engines appear in Doctor; unavailable or incomplete observations remain visible. CT observations can be stale; wildcard certificates do not establish concrete hosts. Headers and version/CVE candidates require human validation and are not proof of exploitation or safety.

No stealth, evasion, destructive scanning, phone-owner/location lookup, Wi-Fi discovery or CDR/PCAP forensics is provided. TLS verification remains enabled, including with an explicit additional lab CA bundle. Metadata collection allows public HTTPS/443 only, pins validated DNS addresses, rejects cross-host redirects, limits requests to 20 and collection time to 60 seconds, and bounds each response to 8 MiB. Cert Spotter pagination stops at five pages. Active HTTP scanning uses project scope, IP exclusions and separate explicit private-IP authorization.

## Development and validation

```sh
.venv/bin/python -m pytest
.venv/bin/python -m compileall -q cyberrecon scripts tests
.venv/bin/python -m build
QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/verify_cyberrecon_startup.py
```

Tests use mocks and local fixtures. No external active scan is needed. Debian/release tests require the relevant platform tools and skip when unavailable. See docs/DEVELOPMENT.md for packaging and the archived-test rationale. Standalone validation does not qualify signed APT publication or every Kali/Parrot installation lifecycle.


Release status: production publication is **BLOCKED** until the mandatory checks in [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) and [docs/LIFECYCLE_QUALIFICATION.md](docs/LIFECYCLE_QUALIFICATION.md) have passing evidence. The checked-in CI workflow verifies locally built artifacts only. Signing validation defaults to dry-run and cannot publish or deploy.
