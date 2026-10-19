# ODMM V228.79 — Quality consolidation and roadmap

Author: Abdelhalim Talbi

## Verified scope versus product claims

Windows Compact 7.9.31 is a **read-only** job/report supervisor. It does not perform
file copies, ACL translation, NFS/SMB cutover, or NAS remediation. The POSIX
migration engine is a separate prototype and is not production NAS-qualified.

## Source and component review

- Active Windows entry point: `02-Sources/odmm_windows_compact_v22811.py`.
  Earlier versioned GUI files are retained as historical references, **not**
  multiple competing application entry points. Avoid removing them until
  dependency reachability and import contracts are verified.
- GUI separation: Tk view -> pure view model -> read-only refresh worker ->
  registry client and validation. Do not expose mutation actions in Compact.
- SQLite recovery: claims remain durable across process death; explicit operator
  confirmation required for reset; audit SHA-256 detects report edits but does
  not authenticate an author or verify NAS file contents.
- V228.79: removed duplicate Escape key binding. Escape now clears **both**
  search text and status filter when the jobs tab is active. Static regression
  test asserts a single binding and both reset operations.
- Windows qualification must run native Windows GUI, bundled Tcl/Tk,
  standalone portable, installer/uninstaller, SHA256 delivery manifest checks.
  GitHub Actions success is evidence of CI runner behavior, not every Windows PC.

## Operational usability and human interaction

1. Connection is explicitly read-only; token remains memory-only and masked.
2. Network refresh happens off the Tk thread; old data remains on errors.
3. Synthetic demo data must always be labeled **fictional**.
4. Filtering, selection, pagination, error messages and report export remain
   independently testable. Never label generated mockups as real screenshots.
5. Recovery decisions must display evidence and safe next steps, never
   silently reset or resume interrupted migrations.

## Risks requiring follow-up

- The bounded refresh result queue may drop the newest completion when older
  workers saturate it. Introduce generation-aware coalescing and stress tests.
- The UI still uses a single Tk module with many closures; extract presenter
  state and keyboard contracts incrementally with behavioral tests.
- Audit hash is not a signature. Add signed manifests, independent verifier,
  and reproducible verification instructions.
- Native POSIX copy recovery still needs process-kill tests at publication and
  durable intent boundaries. Add Linux CI coverage.
- NAS vendor ACL fidelity and effective-access validation are **not qualified**.

## Planned versions

| Version | Priority | Acceptance criteria |
| --- | --- | --- |
| V228.80 | Refresh reliability | Latest request result never lost under bounded queue saturation; stress tests on Windows |
| V228.81 | GUI ergonomics | Clear connection/error/demo modes, keyboard accessibility, stable detail selection |
| V228.82 | Auditable recovery | Standalone signed evidence format, verify/export CLI, negative tamper tests |
| V228.83 | Crash consistency | Kill-after-publish recovery tests, explicit reconciliation, orphan cleanup |
| V228.84 | NAS qualification framework | NetApp/FlashBlade/PowerScale matrix, ACL and effective-access evidence; no unsupported production claims |

## Release evidence

GitHub Actions is the authoritative build and qualification log for each commit.
The ZIP contains the actual sources and Windows artifacts only when native
Windows packaging, install/uninstall tests and manifest verification succeed.
