# Standalone development

Package version and CLI version are 0.2.0. Python >=3.12 follows the existing supported baseline. Setuptools discovers only cyberrecon packages and includes assets/*.svg. The wheel contains no legacy desktop package. Build with `python -m build`, inspect wheel metadata/assets and run `python -m twine check dist/*`. Test a wheel in a fresh virtual environment from outside the checkout, then run installed `cyberrecon --version` and `--help`.

Core modules use local models, validation errors and atomic output helpers. domains.py owns FQDN normalization; connectors.py implements only public CT metadata; nmap_scan.py owns bounded argv validation and entity-safe XML parsing; web_assessment.py contains offline header findings. engines.py executes fixed argument lists with shell=False; scanner.py and scope.py enforce authorization and scope. HTTP transports may be injected for deterministic tests. No original checkout belongs on sys.path or PYTHONPATH.

The complete suite is under tests/. Historical copied tests and unrelated scripts are retained verbatim as .py.txt under reference/legacy-monorepo/ with an explicit rationale. They test absent legacy desktop/session/vault/forensic interfaces, rather than CyberRecon. Relevant extraction security tests were ported to tests/test_standalone.py; existing CyberRecon security, GUI, release and workflow coverage remains active.

Build optional Debian payloads with scripts/build-cyberrecon-deb.py; these include only the standalone package and declare the XML parser dependency. Signing and APT publication require separate release credentials and platform qualification. Historical release evidence is retained for provenance, not current qualification.

Run `python -m pytest`, compileall, `python -m build`, and the offscreen startup verifier. Go tests may skip without the Go toolchain; platform tests may skip without Debian utilities. Never run external active scans as packaging validation.

Three historical production workflow assertions skip explicitly because the standalone target has no .github/workflows/release-apt.yml. Signing-key validation, cleanup and failure-path script regressions remain active. No publishing pipeline is claimed or installed by this conversion.

Source archive build manifests report a deterministic source digest and unknown Git commit/dirty state. Production gates still require reviewed exact-commit qualification; archive provenance does not bypass them.


Final-readiness verification is documented in docs/PRODUCTION_READINESS.md and docs/LIFECYCLE_QUALIFICATION.md. The new verification-only CI workflow uses read-only repository permissions and has no secrets, artifact upload or publication steps. Remote workflow execution was not verified by the local audit. Signing defaults to candidate validation (`--dry-run`); `--sign` separately requires every existing production gate and protected credentials. Dry-run results explicitly mark signing NOT RUN and production trust BLOCKED.

The development extra declares cryptography for the temporary loopback TLS certificate fixture; it is not a runtime dependency. MANIFEST.in includes tests, scripts, workers and documentation so the standalone sdist is a complete development source tree. Generated environments, historical snapshots and inherited release evidence are excluded from the distribution.

release/constraints-python314.txt and release/tools.txt record the actual audited/tested qualification environment versions. They are platform-specific evidence, not a universal Python/distribution support claim.

The audited baseline is now in Git at `36b9505`. Existing candidate artifacts predate current remediation; a Git commit alone does not qualify provenance or production release. Historical evidence is labeled separately in docs/release-evidence/history/.
