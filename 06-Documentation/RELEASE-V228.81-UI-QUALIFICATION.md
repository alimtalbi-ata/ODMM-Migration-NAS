# ODMM V228.81 — Windows UI qualification and limitations

Author: Abdelhalim Talbi

## Qualified on GitHub Actions
Commit: 8b673531d0a4c917aa92274db13464b492e77b1a
Windows run: https://github.com/alimtalbi-ata/ODMM-Migration-NAS/actions/runs/39261841798
Linux crash tests: https://github.com/alimtalbi-ata/ODMM-Migration-NAS/actions/runs/39261841794
Source ZIP: https://github.com/alimtalbi-ata/ODMM-Migration-NAS/actions/runs/39261841693

The Windows workflow compiles a portable executable and an installer, runs
headless UI contract tests, initializes the bundled Tcl/Tk runtime, launches
the GUI, tests standalone execution outside the source checkout, tests
silent installation and uninstallation, and verifies SHA-256 manifest entries.

## Human interaction

- F5 and Ctrl+R: refresh registry; Ctrl+F: focus search; Escape: reset both
  search and status filter; Ctrl+Tab: change tab.
- Live server data and synthetic demonstration data are labeled differently.
- Network errors preserve previous rows and show that they may be stale.
- No operation in Compact may trigger migration, ACL writes, deletion, cutover
  or auto-recovery. Export is a local summary operation.

## Explicit non-qualifications

No production NAS ACL preservation, end-to-end NFS/SMB migration, Windows 10/11
hardware fleet compatibility, or cross-vendor cutover is established by this CI.
No screenshots are claimed in this document; screenshots must come from actual
captured application runs and be accompanied by provenance.

## Next release V228.82

- Native audit verification CLI with structured exit codes and tamper tests.
- Stronger concurrent refresh stress tests and fault injection.
- Distinguish stale/error/demo in a dedicated UI status banner.
- Signed release evidence is planned, not currently provided.
