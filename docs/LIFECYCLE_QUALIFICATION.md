# Kali and Parrot lifecycle qualification

Current status: **BLOCKED** for both clean-distribution lifecycle matrices. The live Kali desktop/loopback checks are separate evidence. No suitable disposable VM/snapshot, real previous-release Debian artifact or clean Parrot desktop is available here. Never infer this qualification from mocked tests, archive extraction, a container, or changed package metadata.

Run the following independently in fresh Kali Security amd64 and Parrot Security amd64 desktop VMs. Record ISO/source, `/etc/os-release`, kernel, Python, VM snapshot identifier, date, real non-root test account and boot ID. Keep an untouched snapshot for rollback. Copy reviewed source scripts, the actual previous supported package, current candidate, SHA256SUMS and the trusted public key into each guest. Never use the development signing key as production trust. Do not create the disposable marker on the development host.

## Inputs and trust

Verify `sha256sum -c SHA256SUMS` against delivered artifacts. Independently authenticate the full production fingerprint using the release owner's established trusted channel. Run `verify_cyberrecon_apt.py REPOSITORY --keyring TRUSTED_PUBLIC_KEY --fingerprint FULL_FINGERPRINT --production` before production APT use. A key delivered only alongside a repository is not an independent trust anchor. Until that public key and genuine signatures exist, record signing/production APT as BLOCKED. Do not request or copy private keys into a guest.

The previous package must be a real supported release with verified provenance. A fixture whose Version field was edited does not qualify upgrade behavior. Record both input hashes and `dpkg-deb -f` metadata. Use fresh directories and preserve all stdout/stderr and failure evidence.

## Automated package lifecycle, only in the disposable guest

An operator must first verify the guest/snapshot and create `/run/cyberrecon-disposable-root` containing exactly `RELEASE_TEST_ONLY` inside that guest. The marker alone is not proof that a host is disposable. Do not run these commands on the host.

```sh
sudo python3 scripts/qualify_cyberrecon_release.py PREVIOUS.deb CURRENT.deb --output /tmp/qualification-default
```

Restore the clean VM snapshot and repeat with `--no-install-recommends --output /tmp/qualification-minimal`. The script records package metadata/hashes, actual previous install, dependency repair, current upgrade, CLI/help/Doctor, package-owned files, workspace permissions, offscreen GUI startup, script-owned loopback TLS/Nmap/reports, actual removal, reinstallation, actual purge, fresh current installation and final purge. It checks logical SQLite state, schema, reports and a user-data marker throughout. Failures remain failures; save partial JSON/logs. It does not qualify a real desktop/menu, non-root application use or reboot.

## Desktop, non-root use and reboot

Restore/reinstall the reviewed current package in the guest using its normal dependency resolver. Log in as the ordinary test user; run `/usr/bin/cyberrecon --version`, `--help`, `--doctor`, and start the installed GUI from the desktop menu. Inspect icon, launch target and rendering. Save application-only screenshots and journal/session errors. Run `desktop-file-validate /usr/share/applications/cyberrecon.desktop`. Confirm the loaded module is `/usr/share/cyberrecon/cyberrecon`, rather than a checkout. The source-only desktop verifier does not satisfy installed-menu integration.

Create a project, synthetic observations and JSON/CSV/HTML/PDF/graph reports using the installed app in the ordinary user's private workspace. With the disposable marker present, capture:

```sh
python3 scripts/verify_cyberrecon_post_reboot.py before --distro kali --home /path/to/test-user-workspace --evidence /path/to/reboot-before.json
```

Use `parrot` in the Parrot guest. Save evidence outside `/run` and `/tmp` so it survives reboot. The VM operator now performs a real reboot using the VM's normal controls. Recreate the transient marker only after confirming the same disposable guest. Run the matching `after` command and redirect its JSON to a new evidence file. The helper requires a changed kernel boot ID, identical installed package version and identical logical DB/report state. Re-run non-root CLI/Doctor, the installed GUI and menu launch after reboot. The helper never calls reboot, apt, dpkg installation, removal or purge.

## Required evidence matrix, per distribution

| Requirement | Verifiable evidence | Current status |
|---|---|---|
| Fresh install, default and minimal dependencies | Actual apt/dpkg logs, version, dependency Doctor | BLOCKED |
| Installed non-root CLI/GUI | Executable/module paths, CLI output, real desktop screenshot | BLOCKED |
| Desktop/menu integration | desktop-file-validate and actual menu launch | BLOCKED |
| Real previous-version upgrade | Genuine input provenance, versions, preserved logical state | BLOCKED |
| Reboot/post-reboot | Changed boot ID, continuity JSON, CLI/GUI/menu rerun | BLOCKED |
| Remove and purge | Actual transaction logs and absent package-owned paths | BLOCKED |
| Reinstall | Fresh transaction and non-root launch with preserved workspace | BLOCKED |
| Configuration/user data | Before/after fingerprints and documented policy | BLOCKED |
| Clean dependency resolution | Fresh snapshot plus default/minimal runs | BLOCKED |
| Checksums/integrity/production trust | SHA256SUMS, package checks, pinned-key signature chain | Production trust BLOCKED |

Policy: package removal and purge remove package-owned application/menu/icon files, and preserve user-owned workspaces, DBs, evidence, reports and configuration. Data deletion is an independent explicit operator action; qualification never deletes a real user's workspace. Successful source or wheel checks do not qualify system-package uninstall behavior.

Do not mark mandatory gates PASS until both distributions have complete evidence for the exact reviewed release source and artifacts. Production publication is disabled in this project; the verification-only CI workflow cannot upload, sign or deploy releases.
