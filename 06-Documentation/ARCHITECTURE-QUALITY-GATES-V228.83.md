# ODMM V228.83 — Architecture quality gates and forward delivery plan
Author: Abdelhalim Talbi

## Architectural decision: safety before features
The product has TWO independent execution planes:
1. Windows Compact: **read-only** registry supervision, filtering, reporting and diagnostics.
2. Native POSIX prototype: migration planner and crash-consistent SQLite registry, with
   explicitly gated filesystem effects and manual reconciliation.

A green Windows EXE build does **not** qualify NFS/SMB migration, ACL/ADS/xattr fidelity,
NAS appliance support or production cutover. Never advertise it as such.

## Risk register / evidence matrix
| Priority | Risk | Current control | Next qualification |
|---|---|---|---|
| P0 | Lost latest refresh | Bounded queue coalescing, stale generation gate | producer/consumer race stress and timeout watchdog |
| P0 | Misleading demo data | Explicit live/demo/stale labels | screenshot and accessibility audit on real Windows |
| P0 | Interrupted native publish | durable SQLite intent, fsync, manual reconciliation | process kill after publish and on-disk reconciliation |
| P0 | Unauthorized destructive action | Compact read-only, DELETE_REVIEW never executes | formal negative authorization tests |
| P0 | Audit forgery | canonical SHA-256 self-integrity, strict JSON parser | detached signature with independently managed key |
| P1 | ACL/identity corruption | fail-closed prototype, no production claim | NFSv3/v4 + SMB NTFS/SID/UID/GID matrix with real targets |
| P1 | Binary supply chain | Git SHA, ZIP per-file SHA-256 manifest | signed artifacts, SBOM, dependency pinning |
| P1 | Cross-vendor correctness | planning only | NetApp/FlashBlade/PowerScale bidirectional fixtures |
| P2 | UX complexity | 3 supervision tabs, keyboard shortcuts | task-based workflow and guided connection wizard |

## Release train
- V228.83: strict JSON audit verification; Linux and Windows adversarial tests; architectural quality gate document.
- V228.84: native kill-after-publish fault injection, crash evidence and operator recovery playbook.
- V228.85: independent signed provenance, deterministic manifests, SBOM and third-party dependencies.
- V228.86: UI error/status state machine, timeouts, keyboard navigation, genuine Windows screenshots.
- V228.87: cross-vendor compatibility catalog and vendor API simulator tests, without claiming appliance qualification.
- V228.88: ACL/identity canonical contract and bidirectional effective-access verification harness.
- V228.89: production-readiness gap review, load tests, operator approval, rollback and staged cutover governance.

## Release definition of done
- Source and binary artifacts refer to **exact same Git SHA**.
- Unit, fault injection, negative-security and install/uninstall tests all pass.
- Document every test as executed or simulated; never fabricate screenshots.
- State unsupported platforms/protocols clearly; keep destructive operations fail-closed.
- Provide cumulative ZIP and actual downloadable EXE after GitHub Actions success.
- Preserve existing main history; prefer PR branches for larger architectural refactors.

## Executable verification example
`python 09-Tools/VERIFY-RECOVERY-AUDIT.py recovery-audit.json`
Exit 0: self-consistent *unsigned* evidence; exit 2: invalid/unreadable.
An attacker able to edit both payload and digest can still forge an unsigned audit.
